# winlist

# Overview

Winlist.exe is a Windows utility designed to create a detailed inventory of files on a system. It recursively scans the C: drive, collecting metadata about each file, and outputs this information in a structured JSONL format. The tool is particularly useful for system administrators, forensic analysts, and IT professionals who need to quickly gather and analyze file system information.

# Features

- Recursive file system scanning starting from C:\
- Parallel processing for improved performance
- Detailed file metadata collection including:
  - File name
  - File size
  - File type (extension)
  - Full file path
  - SHA256 hash
  - Creation, modification, and last access timestamps
- Output in JSONL (JSON Lines) format for easy parsing and analysis
- Comprehensive logging of the scan process
- Automatic compression of output files into a ZIP archive
- Self-deletion capability after completion for minimal footprint

# Usage

To use winlist.exe, simply run it from a command prompt or by double-clicking the executable: .\winlist.exe

No command-line arguments are required.

# Output

Winlist.exe generates the following files:

1. `<hostname>.jsonl`: Contains the file inventory in JSONL format.
2. `<hostname>.log`: A detailed log of the scan process.
3. `<hostname>_<timestamp>.zip`: A ZIP archive containing both the JSONL and log files.

Where `<hostname>` is the name of the computer and `<timestamp>` is the start time of the scan.

# Performance

The tool utilizes parallel processing to maximize efficiency on multi-core systems. The number of worker goroutines is automatically set to match the number of CPU cores available.

# Security Note

Winlist.exe includes a self-deletion feature that attempts to remove the executable after completion. This is designed to minimize the tool's footprint on the scanned system. However, be aware that this means the executable will try to delete itself after each run.

# Limitations

- Currently only scans the C: drive
- Requires administrative privileges to access all files
- May take considerable time on systems with many files
- Large output files may be generated for systems with many files

# Troubleshooting

If you encounter any issues:

1. Check the log file for detailed error messages
2. Ensure you have sufficient permissions to access all directories
3. Verify that you have enough disk space for the output files

# Legal and Ethical Use

This tool should only be used on systems you own or have explicit permission to scan. Unauthorized use may violate local, state, or federal laws.

# Development

Winlist.exe is written in Go. To modify or compile from source:

1. Ensure you have Go installed (version 1.16 or later recommended)
2. Clone the repository or download the source code
3. Make your modifications
4. Build using: `go build -o winlist.exe`
