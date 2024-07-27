# Registry Monitor

## Overview
Registry Monitor is a Python script designed to monitor changes in specific Windows registry keys. It logs these changes to a timestamped log file for auditing and debugging purposes.

## Features
- Monitors a predefined list of registry paths for changes.
- Logs changes with timestamps to a log file.
- Ensures the script runs with administrative privileges.
- Clean exit with proper handling of resources.

## Requirements
- Python 3.x
- `pywin32` library

## Installation
1. **Clone the Repository:**
    ```sh
    git clone https://github.com/yourusername/RegistryMonitor.git
    cd RegistryMonitor
    ```

2. **Install Dependencies:**
    ```sh
    pip install pywin32
    ```

## Usage
1. **Run the Script:**
    ```sh
    python src/main.py
    ```

2. **Monitor Changes:**
    - The script will automatically log changes detected in the specified registry keys.
    - Logs are saved in the `logs` directory with a timestamped filename.

## Registry Paths Monitored
The script monitors the following registry paths:
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Windows` (AppInit_DLLs)
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
- `HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Uninstall`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders`
- `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders`
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WinDefend` (Start)
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisSvc` (Start)
- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\WdNisDrv` (Start)

you can simply add your own registry paths if desired.