# 🔐 Secure Encryption Tool

A professional-grade file and folder encryption tool with both GUI and command-line interfaces, featuring password-based encryption with strong cryptographic security.

## ✨ Features

- **🖥️ Modern GUI Interface** - User-friendly tabbed interface with progress tracking
- **⌨️ Command Line Support** - Full CLI functionality for automation
- **📁 File Encryption** - Secure individual file encryption/decryption
- **📂 Folder Encryption** - Batch encryption of entire directories
- **💬 Message Encryption** - Encrypt/decrypt text messages
- **🔒 Password Protection** - Per-file password protection with PBKDF2 key derivation
- **🧂 Salt-based Security** - Each password-protected file gets unique salt
- **🔄 Progress Tracking** - Real-time operation progress and logging
- **🏠 Windows Integration** - Pinnable to Start Menu and taskbar

## 🛡️ Security Features

- **AES-128 Encryption** via Fernet (cryptographically secure)
- **PBKDF2 Key Derivation** with 100,000 iterations
- **Unique Salt Generation** for each password-protected file
- **Secure Password Input** with hidden typing and confirmation
- **Key Management** with automatic generation and backup

## 📋 Requirements

- **Python 3.7+**
- **cryptography** library
- **tkinter** (usually included with Python)
- **Windows OS** (for Start Menu integration)

## 🚀 Quick Start

### Installation

1. **Clone or download** this repository
2. **Install dependencies**:
   ```bash
   pip install cryptography
   ```
3. **Run the tool**:
   ```bash
   python secure_encryption.py
   ```

### First Launch

1. Choose **GUI** or **Command Line** interface
2. The tool will automatically generate an encryption key on first run
3. Start encrypting files, folders, or messages!

## 🖥️ GUI Interface

Launch the graphical interface:

```bash
python secure_encryption.py --gui
```

### Interface Tabs

- **📁 Files** - Encrypt/decrypt individual files
- **📂 Folders** - Batch encrypt/decrypt entire directories  
- **💬 Messages** - Encrypt/decrypt text messages
- **⚙️ Settings** - Key management and protected files viewer

### Key Features

- **File Browser Integration** - Easy file/folder selection
- **Progress Indicators** - Real-time progress bars and status updates
- **Operation Logs** - Detailed logging of all operations
- **Password Dialogs** - Secure password input with confirmation
- **Auto-suggestions** - Intelligent output file naming

## ⌨️ Command Line Interface

Launch the command-line interface:

```bash
python secure_encryption.py
```

### Available Operations

1. **Generate Key** - Create new encryption key
2. **Encrypt Message** - Encrypt text messages
3. **Decrypt Message** - Decrypt text messages
4. **Encrypt File** - Basic file encryption
5. **Decrypt File** - File decryption
6. **Encrypt File (Password)** - Password-protected file encryption
7. **View Protected Files** - List all password-protected files
8. **Exit** - Quit the application

## 🔒 Security Model

### File Encryption Without Password
- Uses main encryption key (`secret.key`)
- Standard AES-128 encryption via Fernet
- Suitable for personal file protection

### File Encryption With Password
- Uses **password-derived key** (not main key)
- PBKDF2 with SHA-256, 100,000 iterations
- Unique salt per file stored in `file_salts.json`
- **True password security** - files cannot be decrypted without correct password

### Key Files
- `secret.key` - Main encryption key (auto-generated)
- `file_salts.json` - Salt storage for password-protected files

## 📁 Project Structure

```
encryption-and-decryption/
├── secure_encryption.py          # Main application
├── Secure_Encryption_Tool.bat    # Windows launcher
├── secret.key                    # Encryption key (auto-generated)
├── file_salts.json               # Password salt storage
├── README.md                     # This documentation
├── LICENSE                       # License file
├── docs/
│   └── INSTALL.md                # Installation guide
└── .git/                         # Git repository data
```

## 🏠 Windows Integration

### Create Desktop & Start Menu Shortcuts

Run the installation script:

```powershell
# Run as Administrator or with execution policy bypass
powershell -ExecutionPolicy Bypass -Command "& '.\install_shortcuts_simple.ps1'"
```

### Pin to Start Menu

1. Press **Windows Key**
2. Type `"Secure Encryption"`  
3. Right-click **"Secure Encryption Tool"**
4. Select **"Pin to Start"**

## 🔧 Usage Examples

### Encrypt a file with password protection:
```bash
python secure_encryption.py
# Choose option 6, then follow prompts
```

### Batch encrypt a folder:
1. Launch GUI: `python secure_encryption.py --gui`
2. Go to **Folders** tab
3. Select input/output folders
4. Check "Use password protection" if desired
5. Click "Encrypt Folder"

### Decrypt password-protected files:
- GUI will automatically detect password protection and prompt
- Command line will prompt for passwords when needed

## ⚠️ Important Security Notes

- **Backup your `secret.key`** - Without it, non-password files cannot be decrypted
- **Remember your passwords** - Password-protected files cannot be recovered without the correct password
- **Keep `file_salts.json`** - Required for password-protected file decryption
- **Strong passwords recommended** - Use complex passwords for maximum security

## 🐛 Troubleshooting

### Common Issues

**"Key file not found"**
- Run the program once to auto-generate `secret.key`

**"GUI won't launch"**
- Ensure tkinter is installed: `python -m tkinter`

**"Password dialog errors"**
- Updated GUI handles this automatically with proper thread management

**"Can't decrypt password-protected file"**
- Ensure you have both the correct password AND `file_salts.json`

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the terms specified in the LICENSE file.

## 🔄 Version History

- **v2.0** - Added comprehensive GUI, improved security model, Windows integration
- **v1.0** - Basic command-line encryption tool

---

**🔐 Built with security and usability in mind. Protect your data with confidence!**