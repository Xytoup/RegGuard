import os
import winreg
import win32event
import win32api
import win32con
import threading
import time
from datetime import datetime
import ctypes
import sys

# Check for admin rights
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    print("Attempting to restart with administrative privileges...")
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

# Constants for registry change notification
REG_NOTIFY_CHANGE_LAST_SET = getattr(win32con, 'REG_NOTIFY_CHANGE_LAST_SET', 0x00000004)

# Extensive list of registry paths for monitoring
REGISTRY_PATHS = [
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Policies\System", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", ""),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", ""),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall", ""),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", ""),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", ""),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WinDefend", "Start"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisSvc", "Start"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\WdNisDrv", "Start")
]
log_directory = "../logs"
if not os.path.exists(log_directory):
    os.makedirs(log_directory)
log_filename = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
LOG_FILE = os.path.join(log_directory, log_filename)

def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {message}"
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")
    print(log_entry)

def monitor_registry_key(hive, path, value_name, stop_event):
    try:
        key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        event = win32event.CreateEvent(None, 0, 0, None)
        while not stop_event.is_set():
            win32api.RegNotifyChangeKeyValue(key, True, REG_NOTIFY_CHANGE_LAST_SET, event, True)
            result = win32event.WaitForSingleObject(event, 1000)  # Timeout after 1000 ms
            if result == win32con.WAIT_OBJECT_0:
                try:
                    value, _ = winreg.QueryValueEx(key, value_name) if value_name else ("N/A", None)
                except FileNotFoundError:
                    value = "Not found"
                log_message(f"Change detected in {path} for value '{value_name}': {value}")
            if stop_event.is_set():  # Check if the stop event has been triggered
                break
    except Exception as e:
        log_message(f"Exception monitoring {path}: {str(e)}")
    finally:
        winreg.CloseKey(key)

def main():
    stop_event = threading.Event()
    threads = []
    log_message("Monitoring started")

    # Start all monitoring threads
    for hive, path, value_name in REGISTRY_PATHS:
        t = threading.Thread(target=monitor_registry_key, args=(hive, path, value_name, stop_event))
        t.daemon = True
        t.start()
        threads.append(t)

    # Wait for user interruption to stop the monitoring
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        for t in threads:
            t.join()
        log_message("Monitoring stopped by user")

if __name__ == "__main__":
    main()
