//go:build windows
// +build windows

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
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

const (
	defaultAPIURL = "https://your-default-api-url.com/upload"
	defaultAPIKey = "your-default-api-key"
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
	Source     string `json:"source"` // The name of the JSONL file this record is associated with
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
	// Custom usage message
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Winlist - Windows File Listing Tool\n\n")
		fmt.Fprintf(os.Stderr, "This tool scans the C:\\ drive, collects file information, and uploads it to a specified API.\n\n")
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  1. Use default API URL and key:\n")
		fmt.Fprintf(os.Stderr, "     %s\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  2. Specify custom API URL and key:\n")
		fmt.Fprintf(os.Stderr, "     %s -api https://your-api-url.com/upload -key your-api-key\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  3. Specify custom API URL, use default key:\n")
		fmt.Fprintf(os.Stderr, "     %s -api https://your-api-url.com/upload\n", os.Args[0])
	}

	// Parse command-line flags
	apiURL := flag.String("api", defaultAPIURL, "API URL for uploading data")
	apiKey := flag.String("key", defaultAPIKey, "API key for authentication")
	help := flag.Bool("help", false, "Show help message")
	flag.Parse()

	// If -help flag is provided, print usage and exit
	if *help {
		flag.Usage()
		os.Exit(0)
	}

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

	// Process results from file scanning and write to JSONL file
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

	err = addFileToZip(zipWriter, logFileName)
	if err != nil {
		log.Fatal("Could not add log file to zip:", err)
	}

	err = addFileToZip(zipWriter, jsonlFileName)
	if err != nil {
		log.Fatal("Could not add jsonl file to zip:", err)
	}

	// Close the zip writer and file
	err = zipWriter.Close()
	if err != nil {
		log.Fatal("Could not close zip writer:", err)
	}
	err = zipFile.Close()
	if err != nil {
		log.Fatal("Could not close zip file:", err)
	}

	// Close the log file and jsonl file
	logFile.Close()
	jsonlFile.Close()

	// Upload JSONL file to API
	err = uploadToAPI(jsonlFileName, logger, *apiURL, *apiKey)
	if err != nil {
		logger.Printf("[%s] [ERROR] Failed to upload JSONL file to API: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	} else {
		// Wait before deleting local files to ensure upload completion and API processing
		logger.Printf("[%s] [INFO] Waiting 5 seconds before deleting local files to ensure upload completion...\n", time.Now().UTC().Format(time.RFC3339))
		time.Sleep(5 * time.Second)

		// Delete local files after successful upload
		filesToDelete := []string{zipFileName, jsonlFileName, logFileName}
		for _, file := range filesToDelete {
			if err := os.Remove(file); err != nil {
				logger.Printf("[%s] [ERROR] Failed to delete %s: %v\n", time.Now().UTC().Format(time.RFC3339), file, err)
				// If deletion fails, try again after a short delay
				time.Sleep(1 * time.Second)
				if err := os.Remove(file); err != nil {
					logger.Printf("[%s] [ERROR] Failed to delete %s after retry: %v\n", time.Now().UTC().Format(time.RFC3339), file, err)
				} else {
					logger.Printf("[%s] [INFO] %s deleted successfully after retry\n", time.Now().UTC().Format(time.RFC3339), file)
				}
			} else {
				logger.Printf("[%s] [INFO] %s deleted successfully\n", time.Now().UTC().Format(time.RFC3339), file)
			}
		}
		logger.Printf("[%s] [INFO] Local file deletion process completed\n", time.Now().UTC().Format(time.RFC3339))
	}

	// Self-delete after completing main operations
	if err := selfDelete(); err != nil {
		logger.Printf("[%s] [ERROR] Failed to initiate self-deletion: %v\n", time.Now().UTC().Format(time.RFC3339), err)
	}
}

func uploadToAPI(jsonlFile string, logger *log.Logger, apiURL, apiKey string) error {
	// Open the JSONL file
	file, err := os.Open(jsonlFile)
	if err != nil {
		return fmt.Errorf("error opening jsonl file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	buffer := make([]byte, 0, 1024*1024) // 1MB buffer
	scanner.Buffer(buffer, 5*1024*1024)  // Allow up to 5MB per line

	var batch []string
	batchSize := 0
	maxBatchSize := 4 * 1024 * 1024 // 4MB max batch size

	for scanner.Scan() {
		line := scanner.Text()
		lineSize := len(line)

		if batchSize+lineSize > maxBatchSize {
			// Upload current batch
			err = uploadBatch(apiURL, apiKey, batch)
			if err != nil {
				return fmt.Errorf("error uploading batch: %v", err)
			}
			logger.Printf("[%s] [INFO] Batch uploaded successfully\n", time.Now().UTC().Format(time.RFC3339))

			// Reset batch
			batch = []string{}
			batchSize = 0
		}

		batch = append(batch, line)
		batchSize += lineSize
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading jsonl file: %v", err)
	}

	// Upload final batch if not empty
	if len(batch) > 0 {
		err = uploadBatch(apiURL, apiKey, batch)
		if err != nil {
			return fmt.Errorf("error uploading final batch: %v", err)
		}
		logger.Printf("[%s] [INFO] Final batch uploaded successfully\n", time.Now().UTC().Format(time.RFC3339))
	}

	logger.Printf("[%s] [INFO] JSONL file successfully uploaded to API\n", time.Now().UTC().Format(time.RFC3339))
	return nil
}

func uploadBatch(apiURL, apiKey string, batch []string) error {
	// Prepare the JSON payload
	payload := struct {
		Events []json.RawMessage `json:"events"`
	}{
		Events: make([]json.RawMessage, len(batch)),
	}

	for i, line := range batch {
		payload.Events[i] = json.RawMessage(line)
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("error marshalling JSON payload: %v", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API request failed with status code: %d, body: %s", resp.StatusCode, string(body))
	}

	return nil
}

// selfDelete initiates the deletion of the executable after a delay
// This ensures the program can finish its operations before removing itself
func selfDelete() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("could not get executable path: %v", err)
	}

	cmd := exec.Command("cmd", "/C", "ping 127.0.0.1 -n 2 > nul && del /F /Q "+exe)
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
	return cmd.Start()
}
