import os
import sys
import ctypes

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    # Re-run the program with admin rights
    print("Attempting to restart with administrative privileges...")
    if sys.platform == "win32":
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit(0)


import winreg
import win32event
import win32api
import win32con
import threading
import time
from datetime import datetime

# Manually defining the REG_NOTIFY_CHANGE_LAST_SET if not present in win32con
REG_NOTIFY_CHANGE_LAST_SET = getattr(win32con, 'REG_NOTIFY_CHANGE_LAST_SET', 0x00000004)

# Registry paths to monitor
REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", ""),  # Autostart programs
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", ""),  # One-time autostart programs
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies", ""),  # General policies
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", ""),  # System-specific policies
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),  # DLL injection points
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ""),  # Login settings
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", ""),  # Debugger settings
    (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services", ""),  # Services and drivers
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", ""),  # Folder options like hidden files
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", ""),  # Installed programs
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", ""),  # User-specific paths
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", ""),  # Global user paths
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),  # Microsoft Defender Antivirus Service
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisSvc", "Start"),  # Microsoft Defender Antivirus Network Inspection Service
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisDrv", "Start"),  # Windows Defender Antivirus Network Inspection System Driver
]

# Log file to record messages
LOG_FILE = "log.txt"

def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def monitor_registry_key(hive, path, value_name):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
        event = win32event.CreateEvent(None, 0, 0, None)
        while True:
            result = win32api.RegNotifyChangeKeyValue(key, True, REG_NOTIFY_CHANGE_LAST_SET, event, True)
            if result != 0:  # Check if there's an actual error
                error_code = win32api.GetLastError()
                if error_code != 0:
                    error_message = win32api.FormatMessage(error_code).strip()
                    log_message(f"Error setting up change notification on {path}: {error_code} - {error_message}")
                    break
            else:  # Properly wait for an event when there's no error
                if win32event.WaitForSingleObject(event, win32event.INFINITE) == win32con.WAIT_OBJECT_0:
                    log_message(f"Change detected in {path} for value '{value_name}'")
    except Exception as e:
        log_message(f"Exception monitoring {path}: {str(e)}")
    finally:
        winreg.CloseKey(key)

def main():
    """ Main function to start threads monitoring registry keys """
    log_message("Registry monitoring started by user.")
    threads = []
    for hive, path, value_name in REGISTRY_PATHS:
        t = threading.Thread(target=monitor_registry_key, args=(hive, path, value_name))
        t.daemon = True
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log_message("Registry monitoring stopped by user.")

if __name__ == "__main__":
    main()
