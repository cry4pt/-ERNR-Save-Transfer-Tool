# Elden Ring: Nightreign Save Transfer Tool

![image](https://github.com/user-attachments/assets/3190aaaf-d8fb-442a-9e46-b534cbfd47d6)

A modern GUI application for transferring save files between Steam accounts for Elden Ring: Nightreign. This tool decrypts, modifies, and re-encrypts save files to change the embedded Steam ID, allowing you to move your progress between different Steam accounts.

## Features

- **User-Friendly GUI**: Modern, dark-themed interface built with PySide6
- **Automatic Steam ID Detection**: Attempts to detect your current Steam ID from the Windows registry
- **Save File Encryption/Decryption**: Handles BND4-format encrypted save files
- **Automatic Backups**: Creates timestamped backups of existing save files
- **Progress Tracking**: Real-time progress updates during processing
- **Checksum Validation**: Automatically recalculates and patches checksums after modifications

## Requirements

### System Requirements
- Windows (required for Steam registry access)
- Python 3.7+

### Dependencies
```
PySide6
cryptography
qdarktheme
```

## Installation

1. Clone this repository:
```bash
git clone https://github.com/cry4pt/Save-Transfer-Tool.git
cd Save-Transfer-Tool
```

2. Install required dependencies:
```bash
pip install PySide6 cryptography qdarktheme
```

3. Run the application:
```bash
python decry4pt.py
```

## Usage

1. **Launch the Application**: Run the Python script to open the GUI
2. **Select Save File**: Click "Select Save File to Transfer" and choose your `.sl2` save file
3. **Enter Steam ID**: The tool will attempt to detect your Steam ID automatically, or you can enter it manually (17-digit Steam ID required)
4. **Wait for Processing**: The tool will:
   - Decrypt the save file
   - Update all Steam ID references
   - Recalculate checksums
   - Re-encrypt the save file
   - Save to the appropriate Steam directory
5. **Complete**: Your save file will be transferred and ready to use with the target Steam account

## File Structure

The tool processes save files in the following locations:
- **Source**: Any `.sl2` file you select
- **Destination**: `%APPDATA%/Nightreign/{SteamID}/NR0000.sl2`
- **Backups**: `%APPDATA%/Nightreign/backup_{timestamp}/`

## Technical Details

### Save File Format
- Uses BND4 container format
- AES-CBC encryption with a fixed key
- Contains multiple USERDATA entries
- Steam ID is embedded in USERDATA_10 at offset 0x8

### Security Note
The encryption key used by the game is hardcoded in this tool. This is necessary for decrypting and re-encrypting save files but means the key is visible in the source code.

## Troubleshooting

### Common Issues

**"BND4 header not found"**
- Ensure you're selecting a valid `.sl2` save file
- The file may be corrupted or not a valid Elden Ring: Nightreign save

**"Could not retrieve Steam ID from registry"**
- Make sure Steam is running
- Try entering your Steam ID manually
- Ensure you're running on Windows

**"Size mismatch" warnings**
- This usually indicates the save file structure has changed
- The tool may need updates for newer game versions

### Getting Your Steam ID

If automatic detection fails, you can find your Steam ID by:
1. Opening Steam
2. Going to your profile
3. Looking at the URL: `steamcommunity.com/profiles/[YOUR_STEAM_ID]`
4. The 17-digit number is your Steam ID

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test thoroughly
5. Commit your changes (`git commit -m 'Add some amazing feature'`)
6. Push to the branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Disclaimer

This tool is for educational and personal use only. Use at your own risk. Always backup your save files before using this tool. The developers are not responsible for any data loss or corruption that may occur.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with PySide6 for the modern GUI framework
- Uses the `cryptography` library for AES encryption/decryption
- Dark theme provided by `qdarktheme`

## Version History

- **v1.0.0**: Initial release with basic save transfer functionality
- Modern GUI with progress tracking
- Automatic Steam ID detection
- Backup system for existing saves

---

**Note**: This tool is not affiliated with FromSoftware or Bandai Namco Entertainment. Elden Ring: Nightreign is a trademark of their respective owners.
