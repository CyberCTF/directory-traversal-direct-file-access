# Direct File Access - Direct File Access Vulnerability

A file administration portal with a direct file access vulnerability. The application allows direct access to sensitive system files.

## Objective
Access sensitive system files directly without bypassing protection.

## Vulnerability
The application allows direct access to the `/etc/passwd` file without proper permission verification.

## Solution
Use the direct path `/etc/passwd` to access the system file content.

## Quick Start

```bash
docker pull cyberctf/direct-file-access:latest
docker run -p 3206:5000 cyberctf/direct-file-access:latest
```

The application will be accessible at http://localhost:3206

## Flag
The flag is located in the content of the `/etc/passwd` file. Find it!

## Issue Reporting

If you encounter any issues with this laboratory, please open an issue on the GitHub repository.

*This is a deliberately vulnerable laboratory designed for educational purposes only.*
