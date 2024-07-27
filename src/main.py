import winreg
import win32event
import win32api
import win32con
import threading
import time
from datetime import datetime

REG_NOTIFY_CHANGE_LAST_SET = getattr(win32con, 'REG_NOTIFY_CHANGE_LAST_SET', 0x00000004)

REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", ""),  # Autostart programs
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", ""),  # One-time autostart programs
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies", ""),  # General policies
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", ""),  # System-specific policies
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),  # DLL injection points
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ""),  # Login settings
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", ""),  # Debugger settings
    (winreg.HKEY_LOCAL_MACHINE, r"System\CurrentControlSet\Services", ""),  # Services and drivers
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", "Hidden"),  # Folder options like hidden files
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", ""),  # Installed programs
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", ""),  # User-specific paths
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", ""),  # Global user paths
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),  # Microsoft Defender Antivirus Service
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisSvc", "Start"),  # Microsoft Defender Antivirus Network Inspection Service
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisDrv", "Start"),  # Windows Defender Antivirus Network Inspection System Driver
]

LOG_FILE = "log.txt"

def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {message}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def monitor_registry_key(hive, path, value_name):
    key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
    event = win32event.CreateEvent(None, 0, 0, None)
    try:
        while True:
            win32api.RegNotifyChangeKeyValue(key, True, REG_NOTIFY_CHANGE_LAST_SET, event, True)
            log_message(f"Change detected in {path} for value '{value_name}'")
            time.sleep(1)  # Adding a 1-second delay to prevent rapid logging
    except Exception as e:
        log_message(f"Error monitoring {path}: {str(e)}")
    finally:
        winreg.CloseKey(key)

def main():
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
        exit(0)

if __name__ == "__main__":
    main()
