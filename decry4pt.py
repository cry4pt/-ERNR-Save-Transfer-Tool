import os, sys, struct, hashlib, json, glob, shutil, winreg, qdarktheme
from datetime import datetime
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PySide6.QtWidgets import (QApplication, QMainWindow, QPushButton, QFileDialog, 
                               QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, 
                               QMessageBox, QWidget, QProgressBar, QFrame,
                               QSpacerItem, QSizePolicy, QGraphicsDropShadowEffect)
from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtGui import QFont, QColor

# Constants
DS2_KEY = b'\x18\xF6\x32\x66\x05\xBD\x17\x8A\x55\x24\x52\x3A\xC0\xA0\xC6\x09'
DEBUG_MODE = True
IV_SIZE = 0x10
PADDING_SIZE = 0xC
START_OF_CHECKSUM_DATA = 4
END_OF_CHECKSUM_DATA = PADDING_SIZE + 16

# Global variables
original_sl2_path = None
bnd4_entries = []

def debug(msg: str = '') -> None:
    if DEBUG_MODE:
        print(msg)

class BND4Entry:
    def __init__(self, raw_data: bytes, index: int, output_folder: str, size: int, offset: int, name_offset: int, footer_length: int, data_offset: int):
        self.index = index
        self.size = size
        self.data_offset = data_offset
        self.footer_length = footer_length
        self._raw_data = raw_data
        self._encrypted_data = raw_data[offset:offset + size]
        self._decrypted_slot_path = output_folder
        self._name = f"USERDATA_{index:02d}"
        self._clean_data = b''
        self._iv = self._encrypted_data[:IV_SIZE]
        self._encrypted_payload = self._encrypted_data[IV_SIZE:]
        self.decrypted = False
    
    def decrypt(self) -> None:
        try:
            decryptor = Cipher(algorithms.AES(DS2_KEY), modes.CBC(self._iv)).decryptor()
            decrypted_raw = decryptor.update(self._encrypted_payload) + decryptor.finalize()
            self._clean_data = decrypted_raw 
            debug(f"Entry {self.index}: Decrypted {len(decrypted_raw)} bytes")
            if self._decrypted_slot_path:
                os.makedirs(self._decrypted_slot_path, exist_ok=True)
                output_path = os.path.join(self._decrypted_slot_path, self._name)
                with open(output_path, 'wb') as f:
                    f.write(self._clean_data)
            self.decrypted = True
        except Exception as e:
            debug(f"Error decrypting entry {self.index}: {str(e)}")
            raise
    
    def patch_checksum(self):
        checksum = self.calculate_checksum()
        checksum_end = len(self._clean_data) - END_OF_CHECKSUM_DATA
        self._clean_data = (
            self._clean_data[:checksum_end] +
            checksum +
            self._clean_data[checksum_end + 16:]
        )
    
    def calculate_checksum(self) -> bytes:
        checksum_end = len(self._clean_data) - END_OF_CHECKSUM_DATA
        data_for_hash = self._clean_data[START_OF_CHECKSUM_DATA:checksum_end]
        return hashlib.md5(data_for_hash).digest()
    
    def encrypt_sl2_data(self) -> bytes:
        encryptor = Cipher(algorithms.AES(DS2_KEY), modes.CBC(self._iv)).encryptor()
        encrypted_payload = encryptor.update(self._clean_data) + encryptor.finalize()
        return self._iv + encrypted_payload

def decrypt_ds2_sl2(input_file: str) -> Optional[str]:
    global original_sl2_path, bnd4_entries
    original_sl2_path = input_file
    bnd4_entries = []
    
    try:
        with open(input_file, 'rb') as f:
            raw = f.read()
    except Exception as e:
        debug(f"ERROR: Could not read input file: {e}")
        return None
    
    debug(f"Read {len(raw)} bytes from {input_file}.")
    if raw[0:4] != b'BND4':
        debug("ERROR: 'BND4' header not found! This doesn't appear to be a valid SL2 file.")
        return None
    else:
        debug("Found BND4 header.")

    num_bnd4_entries = struct.unpack("<i", raw[12:16])[0]
    debug(f"Number of BND4 entries: {num_bnd4_entries}")

    unicode_flag = (raw[48] == 1)
    debug(f"Unicode flag: {unicode_flag}")
    debug("")

    BND4_HEADER_LEN = 64
    BND4_ENTRY_HEADER_LEN = 32

    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_folder = os.path.join(script_dir, "decrypted_output")
    
    for i in range(num_bnd4_entries):
        pos = BND4_HEADER_LEN + (BND4_ENTRY_HEADER_LEN * i)
        if pos + BND4_ENTRY_HEADER_LEN > len(raw):
            debug(f"Warning: File too small to read entry #{i} header")
            break
        entry_header = raw[pos:pos + BND4_ENTRY_HEADER_LEN]
        if entry_header[0:8] != b'\x40\x00\x00\x00\xff\xff\xff\xff':
            debug(f"Warning: Entry header #{i} does not match expected magic value - skipping")
            continue
        entry_size = struct.unpack("<i", entry_header[8:12])[0]
        entry_data_offset = struct.unpack("<i", entry_header[16:20])[0]
        entry_name_offset = struct.unpack("<i", entry_header[20:24])[0]
        entry_footer_length = struct.unpack("<i", entry_header[24:28])[0]
        if entry_size <= 0 or entry_size > 1000000000:
            debug(f"Warning: Entry #{i} has invalid size: {entry_size} - skipping")
            continue
        if entry_data_offset <= 0 or entry_data_offset + entry_size > len(raw):
            debug(f"Warning: Entry #{i} has invalid data offset: {entry_data_offset} - skipping")
            continue
        if entry_name_offset <= 0 or entry_name_offset >= len(raw):
            debug(f"Warning: Entry #{i} has invalid name offset: {entry_name_offset} - skipping")
            continue
        debug(f"Processing Entry #{i} (Size: {entry_size}, Offset: {entry_data_offset})")
        try:
            entry = BND4Entry(
                raw_data=raw, 
                index=i, 
                output_folder=output_folder, 
                size=entry_size, 
                offset=entry_data_offset,
                name_offset=entry_name_offset, 
                footer_length=entry_footer_length, 
                data_offset=entry_data_offset  
            )
            entry.decrypt()
            bnd4_entries.append(entry)
        except Exception as e:
            debug(f"Error processing entry #{i}: {str(e)}")
            continue
    
    debug(f"\nDONE! Successfully decrypted {len(bnd4_entries)} of {num_bnd4_entries} entries.")
    save_index_mapping(bnd4_entries, output_folder)
    return output_folder

def save_index_mapping(entries, output_path):
    mapping = {entry.index: f"USERDATA_{entry.index:02d}" for entry in entries if entry.decrypted}
    mapping_file = os.path.join(output_path, "index_mapping.json")
    with open(mapping_file, 'w') as f:
        json.dump(mapping, f)
    debug(f"Saved index mapping to {mapping_file}")

def encrypt_modified_files(output_sl2_file: str):
    global original_sl2_path, bnd4_entries
    with open(original_sl2_path, 'rb') as f:
        original_data = f.read()
    debug(f"Original file size: {len(original_data)} bytes")
    new_data = bytearray(original_data)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_folder = os.path.join(script_dir, "decrypted_output")
    for entry in bnd4_entries:
        filename = f"USERDATA_{entry.index:02d}"
        file_path = os.path.join(output_folder, filename)
        if not os.path.exists(file_path):
            continue
        debug(f"\nProcessing {filename}:")
        with open(file_path, 'rb') as f:
            modified_data = f.read()
        debug(f"  Modified data size: {len(modified_data)} bytes")
        entry._clean_data = bytearray(modified_data)
        entry.patch_checksum()
        debug(f"  New checksum calculated and patched")
        encrypted_entry_data = entry.encrypt_sl2_data()
        debug(f"  Encrypted data size: {len(encrypted_entry_data)} bytes")
        if len(encrypted_entry_data) != entry.size:
            debug(f"  WARNING: Size mismatch! Expected {entry.size}, got {len(encrypted_entry_data)}")
            continue
        data_start = entry.data_offset
        new_data[data_start:data_start + len(encrypted_entry_data)] = encrypted_entry_data
        debug(f"  ✓ Successfully processed {filename}")
    with open(output_sl2_file, 'wb') as f:
        f.write(new_data)
    debug(f"\n=== Final Result ===")
    debug(f"Original size: {len(original_data)} bytes")
    debug(f"New size: {len(new_data)} bytes")
    debug(f"Saved to: {output_sl2_file}")
    if len(new_data) == len(original_data):
        debug("✓ Perfect size match!")
    else:
        debug("⚠ Size difference detected")

class ProcessThread(QThread):
    progress_updated = Signal(int)
    status_updated = Signal(str)
    finished_with_result = Signal(bool, str)
    
    def __init__(self, input_file, steam_id, output_file):
        super().__init__()
        self.input_file = input_file
        self.steam_id = steam_id
        self.output_file = output_file
    
    def run(self):
        try:
            self.status_updated.emit("Decrypting save file...")
            self.progress_updated.emit(20)
            
            folder_path = decrypt_ds2_sl2(self.input_file)
            if not folder_path:
                self.finished_with_result.emit(False, "Failed to decrypt the SL2 file")
                return
            
            self.progress_updated.emit(40)
            self.status_updated.emit("Processing Steam ID...")
            
            user_data_10_path = os.path.join(folder_path, 'USERDATA_10')
            if not os.path.isfile(user_data_10_path):
                self.finished_with_result.emit(False, f"USERDATA_10 not found in {folder_path}")
                return
            
            with open(user_data_10_path, 'rb') as f:
                f.seek(0x8)
                old_steam_id = f.read(8)
            
            self.progress_updated.emit(60)
            
            steam_id_hex = format(int(self.steam_id), 'x').zfill(16)
            new_steam_id_bytes = bytes.fromhex(steam_id_hex)[::-1]
            
            userdata_files = sorted(glob.glob(os.path.join(folder_path, "USERDATA*")))
            files_modified = 0
            
            self.status_updated.emit("Updating save files...")
            
            for file_path in userdata_files:
                with open(file_path, 'rb') as f:
                    data = f.read()
                if old_steam_id in data:
                    new_data = data.replace(old_steam_id, new_steam_id_bytes)
                    with open(file_path, 'wb') as f:
                        f.write(new_data)
                    files_modified += 1
            
            self.progress_updated.emit(80)
            self.status_updated.emit("Encrypting and saving...")
            
            encrypt_modified_files(self.output_file)
            
            self.progress_updated.emit(100)
            self.status_updated.emit("Complete!")
            
            self.finished_with_result.emit(True, f"Successfully processed {files_modified} files and saved to {self.output_file}")
            
        except Exception as e:
            self.finished_with_result.emit(False, str(e))

class ModernButton(QPushButton):
    def __init__(self, text, primary=False):
        super().__init__(text)
        self.primary = primary
        self.setup_style()
        self.setup_effects()
    
    def setup_style(self):
        if self.primary:
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #4CAF50, stop:1 #45a049);
                    color: white;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 8px;
                    font-size: 14px;
                    font-weight: bold;
                    min-height: 20px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #5CBF60, stop:1 #4CAF50);
                    transform: translateY(-1px);
                }
                QPushButton:pressed {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #45a049, stop:1 #3d8b40);
                }
                QPushButton:disabled {
                    background: #cccccc;
                    color: #666666;
                }
            """)
        else:
            self.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #f8f9fa, stop:1 #e9ecef);
                    color: #495057;
                    border: 2px solid #dee2e6;
                    padding: 10px 20px;
                    border-radius: 8px;
                    font-size: 13px;
                    min-height: 16px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #ffffff, stop:1 #f8f9fa);
                    border-color: #adb5bd;
                }
                QPushButton:pressed {
                    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                        stop:0 #e9ecef, stop:1 #dee2e6);
                }
            """)
    
    def setup_effects(self):
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(10)
        shadow.setColor(QColor(0, 0, 0, 60))
        shadow.setOffset(0, 2)
        self.setGraphicsEffect(shadow)

class ModernLineEdit(QLineEdit):
    def __init__(self, placeholder=""):
        super().__init__()
        self.setPlaceholderText(placeholder)
        self.setup_style()
    
    def setup_style(self):
        self.setStyleSheet("""
            QLineEdit {
                border: 2px solid #e9ecef;
                border-radius: 8px;
                padding: 12px 16px;
                font-size: 14px;
                color: #495057;
            }
            QLineEdit:focus {
                border-color: #4CAF50;
            }
            QLineEdit:hover {
                border-color: #adb5bd;
            }
        """)

class ModernProgressBar(QProgressBar):
    def __init__(self):
        super().__init__()
        self.setup_style()
    
    def setup_style(self):
        self.setStyleSheet("""
            QProgressBar {
                border: none;
                border-radius: 8px;
                background-color: #e9ecef;
                text-align: center;
                font-weight: bold;
                color: #495057;
                height: 20px;
            }
            QProgressBar::chunk {
                border-radius: 8px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #4CAF50, stop:1 #81C784);
            }
        """)

class SteamIDDialog(QDialog):
    def __init__(self, parent=None, initial_steam_id=None):
        super().__init__(parent)
        self.setWindowTitle("Steam ID Required")
        self.setFixedSize(480, 280)
        self.setModal(True)
        self.setup_ui()
        self.setup_style()
        if initial_steam_id:
            self.steam_id_entry.setText(initial_steam_id)
            self.validate_steam_id()
    
    def setup_ui(self):
        layout = QVBoxLayout()
        layout.setSpacing(20)
        layout.setContentsMargins(30, 30, 30, 30)
        
        title = QLabel("Enter Your Steam ID")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                font-size: 22px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 10px;
            }
        """)
        layout.addWidget(title)
        
        desc = QLabel("Please enter your 17-digit Steam ID to transfer the save file:")
        desc.setAlignment(Qt.AlignCenter)
        desc.setWordWrap(True)
        desc.setStyleSheet("""
            QLabel {
                font-size: 13px;
                color: #6c757d;
                margin-bottom: 20px;
            }
        """)
        layout.addWidget(desc)
        
        self.steam_id_entry = ModernLineEdit("Enter your 17-digit Steam ID")
        self.steam_id_entry.setMaxLength(17)
        layout.addWidget(self.steam_id_entry)
        
        self.validation_label = QLabel("")
        self.validation_label.setAlignment(Qt.AlignCenter)
        self.validation_label.setStyleSheet("color: #dc3545; font-size: 12px;")
        layout.addWidget(self.validation_label)
        
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        cancel_btn = ModernButton("Cancel")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        self.submit_button = ModernButton("Continue", primary=True)
        self.submit_button.clicked.connect(self.validate_and_accept)
        button_layout.addWidget(self.submit_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        self.steam_id_entry.textChanged.connect(self.validate_steam_id)
        self.steam_id_entry.setFocus()
    
    def setup_style(self):
        pass  # Removed light background stylesheet
    
    def validate_steam_id(self):
        text = self.steam_id_entry.text()
        if not text:
            self.validation_label.setText("")
            self.submit_button.setEnabled(True)
        elif len(text) != 17:
            self.validation_label.setText("Steam ID must be exactly 17 digits")
            self.submit_button.setEnabled(False)
        elif not text.isdigit():
            self.validation_label.setText("Steam ID must contain only numbers")
            self.submit_button.setEnabled(False)
        else:
            self.validation_label.setText("✓ Valid Steam ID")
            self.validation_label.setStyleSheet("color: #28a745; font-size: 12px;")
            self.submit_button.setEnabled(True)
    
    def validate_and_accept(self):
        steam_id = self.steam_id_entry.text()
        if len(steam_id) == 17 and steam_id.isdigit():
            self.accept()
        else:
            self.validation_label.setText("Please enter a valid 17-digit Steam ID")
            self.validation_label.setStyleSheet("color: #dc3545; font-size: 12px;")
    
    def get_steam_id(self):
        return self.steam_id_entry.text()

class SaveTransferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Elden Ring: Nightreign Save Transfer Tool")
        self.setFixedSize(600, 500)
        self.backup_folder = None
        self.setup_ui()
        self.setup_style()
        self.center_window()
    
    def get_current_steam_id(self):
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam\ActiveProcess")
            active_user, _ = winreg.QueryValueEx(registry_key, "ActiveUser")
            winreg.CloseKey(registry_key)
            
            if active_user and active_user != 0:
                steam_id_64 = active_user + 76561197960265728
                return str(steam_id_64)
        except (FileNotFoundError, OSError, WindowsError):
            debug("Could not retrieve Steam ID from registry")
        
        try:
            steam_path = self.get_steam_path()
            if steam_path:
                loginusers_path = os.path.join(steam_path, "config", "loginusers.vdf")
                if os.path.exists(loginusers_path):
                    with open(loginusers_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        import re
                        steam_ids = re.findall(r'"(7656[0-9]{13})"', content)
                        if steam_ids:
                            return steam_ids[0]
        except Exception as e:
            debug(f"Could not read loginusers.vdf: {e}")
        
        return None
    
    def get_steam_path(self):
        try:
            registry_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Valve\Steam")
            steam_path, _ = winreg.QueryValueEx(registry_key, "SteamPath")
            winreg.CloseKey(registry_key)
            return steam_path
        except (FileNotFoundError, OSError, WindowsError):
            return None
    
    def setup_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        main_layout = QVBoxLayout()
        main_layout.setSpacing(25)
        main_layout.setContentsMargins(40, 40, 40, 40)
        
        header_layout = QVBoxLayout()
        header_layout.setSpacing(10)
        
        title = QLabel("Elden Ring: Nightreign")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                font-size: 28px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 5px;
            }
        """)
        header_layout.addWidget(title)
        
        subtitle = QLabel("Save Transfer Tool")
        subtitle.setAlignment(Qt.AlignCenter)
        subtitle.setStyleSheet("""
            QLabel {
                font-size: 16px;
                color: #7f8c8d;
                margin-bottom: 20px;
            }
        """)
        header_layout.addWidget(subtitle)
        
        main_layout.addLayout(header_layout)
        
        info_frame = QFrame()
        info_frame.setStyleSheet("""
            QFrame {
                border: 1px solid #cccccc;
                border-radius: 12px;
                padding: 20px;
            }
        """)
        
        info_layout = QVBoxLayout()
        info_text = QLabel("This tool allows you to transfer save files between Steam accounts by updating the Steam ID embedded in the save data.")
        info_text.setWordWrap(True)
        info_text.setStyleSheet("""
            QLabel {
                font-size: 13px;
                color: #495057;
                line-height: 1.4;
            }
        """)
        info_layout.addWidget(info_text)
        info_frame.setLayout(info_layout)
        
        main_layout.addWidget(info_frame)
        
        self.progress_widget = QWidget()
        progress_layout = QVBoxLayout()
        
        self.status_label = QLabel("Ready to process...")
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #495057;
                margin-bottom: 10px;
            }
        """)
        progress_layout.addWidget(self.status_label)
        
        self.progress_bar = ModernProgressBar()
        progress_layout.addWidget(self.progress_bar)
        
        self.progress_widget.setLayout(progress_layout)
        self.progress_widget.hide()
        main_layout.addWidget(self.progress_widget)
        
        main_layout.addItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))
        
        self.select_button = ModernButton("Select Save File to Transfer", primary=True)
        self.select_button.setMinimumHeight(50)
        self.select_button.clicked.connect(self.start_process)
        main_layout.addWidget(self.select_button)
        
        footer = QLabel("Select your SL2 save file to begin the transfer process")
        footer.setAlignment(Qt.AlignCenter)
        footer.setStyleSheet("""
            QLabel {
                font-size: 12px;
                color: #6c757d;
                margin-top: 10px;
            }
        """)
        main_layout.addWidget(footer)
        
        central_widget.setLayout(main_layout)
    
    def setup_style(self):
        pass  # Removed light background stylesheet
    
    def center_window(self):
        screen = QApplication.primaryScreen().geometry()
        window = self.geometry()
        x = (screen.width() - window.width()) // 2
        y = (screen.height() - window.height()) // 2
        self.move(x, y)
    
    def get_input_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Save File to Transfer",
            "",
            "SL2 Files (*.sl2);;All Files (*.*)"
        )
        return file_path if file_path else None
    
    def start_process(self):
        input_file = self.get_input_file()
        if not input_file:
            return
        
        steam_id = self.get_current_steam_id()
        
        dialog = SteamIDDialog(self, initial_steam_id=steam_id)
        if dialog.exec() != QDialog.Accepted:
            return
        
        steam_id = dialog.get_steam_id()
        
        app_data_path = os.path.join(os.environ['APPDATA'], 'Nightreign')
        save_dir = os.path.join(app_data_path, steam_id)
        
        if os.path.exists(save_dir):
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.backup_folder = os.path.join(app_data_path, f"backup_{timestamp}")
            os.makedirs(self.backup_folder, exist_ok=True)
            
            for file_name in ['NR0000.sl2', 'NR0000.sl2.bak', 'steam_autocloud.vdf']:
                src_file = os.path.join(save_dir, file_name)
                if os.path.exists(src_file):
                    shutil.copy(src_file, self.backup_folder)
                    debug(f"Copied {file_name} to {self.backup_folder}")
                else:
                    debug(f"Warning: {file_name} not found in {save_dir}")
        else:
            debug(f"Save directory {save_dir} does not exist. No backup needed.")
            self.backup_folder = None
        
        os.makedirs(save_dir, exist_ok=True)
        
        output_file = os.path.join(save_dir, 'NR0000.sl2')
        
        self.progress_widget.show()
        self.select_button.setEnabled(False)
        self.select_button.setText("Processing...")
        
        self.process_thread = ProcessThread(input_file, steam_id, output_file)
        self.process_thread.progress_updated.connect(self.progress_bar.setValue)
        self.process_thread.status_updated.connect(self.status_label.setText)
        self.process_thread.finished_with_result.connect(self.process_finished)
        self.process_thread.start()
    
    def process_finished(self, success, message):
        self.progress_widget.hide()
        self.select_button.setEnabled(True)
        self.select_button.setText("Select Save File to Transfer")
        
        if success:
            if self.backup_folder:
                message += f"\nBackup created in {self.backup_folder}"
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Transfer Complete")
            msg_box.setText("Save file transfer completed successfully!")
            msg_box.setDetailedText(message)
            msg_box.setIcon(QMessageBox.Information)
            # Removed custom stylesheet to use theme styling
            msg_box.exec()
        else:
            msg_box = QMessageBox(self)
            msg_box.setWindowTitle("Transfer Failed")
            msg_box.setText("An error occurred during the transfer process.")
            msg_box.setDetailedText(message)
            msg_box.setIcon(QMessageBox.Critical)
            # Removed custom stylesheet to use theme styling
            msg_box.exec()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    qdarktheme.setup_theme("light")  # Apply dark theme
    app.setStyle('Fusion')  # Optional, as qdarktheme sets it
    
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    window = SaveTransferWindow()
    window.show()
    
    sys.exit(app.exec())
