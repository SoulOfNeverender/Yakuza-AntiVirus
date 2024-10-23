import sys
import os
import hashlib
import shutil
import psutil
import queue
import threading
import time
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, 
                             QVBoxLayout, QGridLayout, QLabel, QFileDialog, 
                             QWidget, QTextEdit, QProgressBar)
from PyQt5.QtGui import QPalette, QColor, QFont, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Dummy virus signature database (hashes of known malicious files)
VIRUS_SIGNATURES = {
    "eicar.txt": "44d88612fea8a8f36de82e1278abb02f",  # Example hash
}

# Junk file extensions and directories
JUNK_FILE_EXTENSIONS = [".tmp", ".log", ".bak", ".old", ".cache", ".chk", ".~", ".swp"]
COMMON_JUNK_DIRECTORIES = [
    "/tmp",
    os.path.expanduser("~/.cache"),
    os.path.expanduser("~/AppData/Local/Temp"),
    os.path.expanduser("~/Library/Caches"),
    os.path.expanduser("~/Downloads"),
]

MONITORED_DIRECTORIES = [
    os.path.expanduser("~/"),
    "/tmp",
    os.path.expanduser("~/Downloads"),
]

class FileMonitorHandler(FileSystemEventHandler):
    """Handles real-time file system events with optimized scanning"""
    def __init__(self, antivirus):
        self.antivirus = antivirus
        self.file_queue = queue.Queue()

    def on_created(self, event):
        """Handle file creation events and add them to the queue for scanning"""
        if not event.is_directory:
            self.file_queue.put(event.src_path)
            self.antivirus.log_message(f"File created: {event.src_path}")

    def on_modified(self, event):
        """Handle file modification events and add them to the queue for scanning"""
        if not event.is_directory:
            self.file_queue.put(event.src_path)
            self.antivirus.log_message(f"File modified: {event.src_path}")


class FileScannerThread(QThread):
    """Background thread for file scanning to avoid blocking the UI"""
    log_signal = pyqtSignal(str)

    def __init__(self, file_queue):
        super().__init__()
        self.file_queue = file_queue
        self.running = True

    def run(self):
        while self.running:
            try:
                file_path = self.file_queue.get(timeout=1)  # Wait for file from queue
                if file_path:
                    self.scan_file(file_path)
            except queue.Empty:
                continue

    def stop(self):
        """Stop the scanning thread"""
        self.running = False

    def scan_file(self, file_path):
        """Scan the given file for virus signatures"""
        self.log_signal.emit(f"🔥 Scanning {file_path}...")

        # Check if the file exists before proceeding
        if not os.path.exists(file_path):
            self.log_signal.emit(f"❌ File not found: {file_path}")
            return

        file_hash = self.calculate_md5(file_path)

        if file_hash in VIRUS_SIGNATURES.values():
            self.log_signal.emit(f"⚠️ Virus found in {file_path}! 💀")
        else:
            self.log_signal.emit(f"✔️ {file_path} is clean.")

    def calculate_md5(self, file_path):
        """Calculate the MD5 hash of the file"""
        hash_md5 = hashlib.md5()

        # Retry mechanism: Handle cases where the file is temporarily inaccessible
        retries = 3
        while retries > 0:
            try:
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                return hash_md5.hexdigest()
            except FileNotFoundError:
                self.log_signal.emit(f"❌ File not found during hash calculation: {file_path}")
                return None
            except PermissionError:
                # If the file is locked, retry a few times before giving up
                retries -= 1
                time.sleep(0.5)  # Wait briefly before retrying
                continue
            except Exception as e:
                self.log_signal.emit(f"Error reading file {file_path}: {e}")
                return None
        return None


class DeepScannerThread(QThread):
    """Background thread for deep scanning of all files on the user's PC"""
    log_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.running = True

    def run(self):
        """Scan all files and directories starting from the user's home directory"""
        home_directory = os.path.expanduser("~")
        self.scan_directory(home_directory)

    def stop(self):
        """Stop the deep scanning thread"""
        self.running = False

    def scan_directory(self, directory):
        """Recursively scan the given directory for virus signatures"""
        for root, dirs, files in os.walk(directory):
            for file in files:
                if not self.running:
                    break  # Stop scanning if not running
                file_path = os.path.join(root, file)
                self.scan_file(file_path)

    def scan_file(self, file_path):
        """Scan the given file for virus signatures"""
        self.log_signal.emit(f"🔥 Scanning {file_path}...")

        # Check if the file exists before proceeding
        if not os.path.exists(file_path):
            self.log_signal.emit(f"❌ File not found: {file_path}")
            return

        file_hash = self.calculate_md5(file_path)

        if file_hash in VIRUS_SIGNATURES.values():
            self.log_signal.emit(f"⚠️ Virus found in {file_path}! 💀")
        else:
            self.log_signal.emit(f"✔️ {file_path} is clean.")

    def calculate_md5(self, file_path):
        """Calculate the MD5 hash of the file"""
        hash_md5 = hashlib.md5()

        retries = 3  # Retry mechanism for locked/inaccessible files
        while retries > 0:
            try:
                with open(file_path, "rb") as f:
                    for chunk in iter(lambda: f.read(4096), b""):
                        hash_md5.update(chunk)
                return hash_md5.hexdigest()
            except FileNotFoundError:
                self.log_signal.emit(f"❌ File not found during hash calculation: {file_path}")
                return None
            except PermissionError:
                retries -= 1
                time.sleep(0.5)
                continue
            except Exception as e:
                self.log_signal.emit(f"Error reading file {file_path}: {e}")
                return None
        return None


class AntivirusApp(QMainWindow):
    """Main Antivirus Window with Yakuza:0 Anime Theme"""
    def __init__(self):
        super().__init__()

        # Set up UI elements
        self.setWindowTitle("Yakuza Antivirus 🐉🔥")
        self.setGeometry(200, 200, 800, 600)
        self.set_yakuza_theme()

        layout = QGridLayout()

        # Scan File button
        self.scan_button = QPushButton(QIcon('icons/scan_yakuza.png'), "🔍 Scan File")
        self.scan_button.setToolTip("Select and scan a file for viruses (like a dragon's eye)")
        self.scan_button.clicked.connect(self.scan_file_dialog)
        self.scan_button.setStyleSheet("background-color: #9B111E; color: white; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.scan_button, 0, 0)

        # Deep Scan button
        self.deep_scan_button = QPushButton(QIcon('icons/deep_scan_yakuza.png'), "🐉 Deep Scan All Files")
        self.deep_scan_button.setToolTip("Perform a deep scan, Kiryu-style")
        self.deep_scan_button.clicked.connect(self.start_deep_scan)
        self.deep_scan_button.setStyleSheet("background-color: #292b2c; color: #F4F4F4; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.deep_scan_button, 0, 1)

        # Real-time monitoring buttons
        self.monitor_button = QPushButton(QIcon('icons/monitor_yakuza.png'), "🔴 Start Real-Time Monitoring")
        self.monitor_button.setToolTip("Monitor critical directories like a Yakuza boss")
        self.monitor_button.clicked.connect(self.start_monitoring)
        self.monitor_button.setStyleSheet("background-color: #FFD700; color: black; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.monitor_button, 1, 0)

        self.stop_monitor_button = QPushButton(QIcon('icons/stop_monitor_yakuza.png'), "❌ Stop Real-Time Monitoring")
        self.stop_monitor_button.setToolTip("End the monitoring, Majima-style")
        self.stop_monitor_button.clicked.connect(self.stop_monitoring)
        self.stop_monitor_button.setStyleSheet("background-color: #DC3545; color: white; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.stop_monitor_button, 1, 1)

        # RAM Booster button
        self.ram_boost_button = QPushButton(QIcon('icons/boost_ram_yakuza.png'), "⚡ Boost RAM")
        self.ram_boost_button.setToolTip("Clear up memory like a swift Yakuza move")
        self.ram_boost_button.clicked.connect(self.boost_ram)
        self.ram_boost_button.setStyleSheet("background-color: #28a745; color: white; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.ram_boost_button, 2, 0)

        # Junk File Cleaner button
        self.clean_junk_button = QPushButton(QIcon('icons/clean_junk_yakuza.png'), "🗑️ Clean Junk Files")
        self.clean_junk_button.setToolTip("Eliminate unwanted junk like an old Yakuza foe")
        self.clean_junk_button.clicked.connect(self.clean_junk_files)
        self.clean_junk_button.setStyleSheet("background-color: #007bff; color: white; font-size: 16px; padding: 10px; font-family: Impact;")
        layout.addWidget(self.clean_junk_button, 2, 1)

        # Log area
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area, 3, 0, 1, 2)

        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar, 4, 0, 1, 2)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Setup for monitoring
        self.observer = None
        self.file_queue = queue.Queue()
        self.file_scanner_thread = FileScannerThread(self.file_queue)
        self.file_scanner_thread.log_signal.connect(self.log_message)
        self.file_scanner_thread.start()

    def set_yakuza_theme(self):
        """Set Yakuza-themed color palette"""
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(10, 10, 10))  # Dark theme
        palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        palette.setColor(QPalette.Button, QColor(100, 100, 100))
        palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        self.setPalette(palette)
        self.setFont(QFont("Comic Sans MS", 10))

    def log_message(self, message):
        """Log messages to the UI log area"""
        self.log_area.append(message)

    def scan_file_dialog(self):
        """Open a file dialog to select a file for scanning"""
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Select a file to scan", "", "All Files (*);;Text Files (*.txt);;Executable Files (*.exe)", options=options)
        if file_name:
            self.file_queue.put(file_name)
            self.log_message(f"📂 Selected file: {file_name}")

    def start_deep_scan(self):
        """Start deep scanning of all files"""
        self.log_message("🚀 Starting deep scan...")
        self.deep_scan_thread = DeepScannerThread()
        self.deep_scan_thread.log_signal.connect(self.log_message)
        self.deep_scan_thread.start()

    def start_monitoring(self):
        """Start real-time file monitoring"""
        if self.observer:
            return  # Monitoring is already active

        self.observer = Observer()
        handler = FileMonitorHandler(self)
        for directory in MONITORED_DIRECTORIES:
            if os.path.exists(directory):
                self.observer.schedule(handler, directory, recursive=True)
        self.observer.start()
        self.log_message("🔍 Real-time monitoring started.")

    def stop_monitoring(self):
        """Stop real-time file monitoring"""
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
            self.log_message("❌ Real-time monitoring stopped.")

    def boost_ram(self):
        """Clear RAM by freeing memory from inactive processes"""
        self.log_message("⚡ Boosting RAM...")
        for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                if proc.info['memory_info'].rss > 100 * 1024 * 1024:  # If using more than 100 MB
                    self.log_message(f"🔧 Freeing memory from process: {proc.info['name']} (PID: {proc.info['pid']})")
                    proc.terminate()  # Terminate the process to free memory
                    proc.wait()  # Wait for the process to be terminated
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        self.log_message("🚀 RAM boosting complete!")

    def clean_junk_files(self):
        """Clean junk files from specified directories"""
        self.log_message("🗑️ Cleaning junk files...")
        for directory in COMMON_JUNK_DIRECTORIES:
            if os.path.exists(directory):
                for root, _, files in os.walk(directory):
                    for file in files:
                        if any(file.endswith(ext) for ext in JUNK_FILE_EXTENSIONS):
                            try:
                                os.remove(os.path.join(root, file))
                                self.log_message(f"🗑️ Deleted junk file: {file}")
                            except Exception as e:
                                self.log_message(f"Error deleting file {file}: {e}")
        self.log_message("🗑️ Junk file cleaning complete!")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = AntivirusApp()
    window.show()
    sys.exit(app.exec_())