# 🚀 Installation Guide

Complete installation instructions for the Secure Encryption Tool.

## 📋 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10/11 (primary), Linux, macOS
- **Python**: 3.7 or higher
- **RAM**: 512 MB
- **Disk Space**: 50 MB for installation + space for encrypted files

### Recommended Requirements
- **Python**: 3.9+
- **RAM**: 1 GB or more
- **Disk Space**: 1 GB or more free space

## 🔧 Installation Methods

### Method 1: Git Clone (Recommended)

```bash
# Clone the repository
git clone https://github.com/YourUsername/encryption-and-decryption.git

# Navigate to directory
cd encryption-and-decryption

# Install dependencies
pip install cryptography

# Run the application
python secure_encryption.py
```

### Method 2: Download ZIP

1. Download the ZIP file from GitHub
2. Extract to your desired location
3. Open command prompt/terminal in the extracted folder
4. Install dependencies: `pip install cryptography`
5. Run: `python secure_encryption.py`

### Method 3: Standalone Executable (Future)

*Coming soon: Pre-built executable for Windows*

## 🐍 Python Setup

### Install Python (if not already installed)

1. **Download Python** from [python.org](https://python.org)
2. **Check "Add Python to PATH"** during installation
3. **Verify installation**:
   ```bash
   python --version
   pip --version
   ```

### Install Dependencies

```bash
# Required: Cryptography library
pip install cryptography

# Optional: Upgrade pip first
pip install --upgrade pip
```

### Verify tkinter (GUI support)

```bash
# Test if tkinter is available
python -c "import tkinter; print('GUI support available')"
```

## 🪟 Windows Integration Setup

### Automatic Setup (Recommended)

1. **Navigate to the project folder**
2. **Run the installer**:
   ```powershell
   powershell -ExecutionPolicy Bypass -File install_shortcuts_simple.ps1
   ```

This creates:
- Desktop shortcut
- Start Menu entry
- Ready for pinning to Start Menu

### Manual Setup

1. **Create batch file** (`launch.bat`):
   ```batch
   @echo off
   cd /d "C:\path\to\encryption-and-decryption"
   python secure_encryption.py --gui
   pause
   ```

2. **Create shortcuts**:
   - Right-click batch file → Send to → Desktop
   - Copy shortcut to: `%APPDATA%\Microsoft\Windows\Start Menu\Programs`

## 🐧 Linux Installation

### Ubuntu/Debian

```bash
# Install Python and pip
sudo apt update
sudo apt install python3 python3-pip python3-tk

# Clone and install
git clone https://github.com/YourUsername/encryption-and-decryption.git
cd encryption-and-decryption
pip3 install cryptography

# Run
python3 secure_encryption.py
```

### Create Desktop Entry

```bash
# Create desktop file
cat > ~/.local/share/applications/secure-encryption.desktop << EOF
[Desktop Entry]
Name=Secure Encryption Tool
Comment=File and folder encryption with GUI
Exec=/usr/bin/python3 /path/to/secure_encryption.py --gui
Icon=/path/to/icon.png
Terminal=false
Type=Application
Categories=Utility;Security;
EOF
```

## 🍎 macOS Installation

```bash
# Install Python via Homebrew (recommended)
brew install python-tk

# Or install via official Python installer from python.org

# Clone and install
git clone https://github.com/YourUsername/encryption-and-decryption.git
cd encryption-and-decryption
pip3 install cryptography

# Run
python3 secure_encryption.py
```

## ✅ Verify Installation

### Test Basic Functionality

```bash
# Test imports
python -c "from cryptography.fernet import Fernet; print('Cryptography OK')"
python -c "import tkinter; print('GUI support OK')"

# Test application
python secure_encryption.py --version  # If version command exists
```

### Test GUI Launch

```bash
python secure_encryption.py --gui
```

Should open the graphical interface without errors.

### Test CLI Launch

```bash
python secure_encryption.py
```

Should show the menu interface.

## 🔧 Troubleshooting

### Common Installation Issues

#### "cryptography installation failed"
```bash
# On Windows:
pip install --upgrade pip setuptools wheel
pip install cryptography

# On Linux:
sudo apt install build-essential libffi-dev python3-dev
pip3 install cryptography

# On macOS:
xcode-select --install
pip3 install cryptography
```

#### "No module named tkinter"
```bash
# Linux:
sudo apt install python3-tk

# macOS:
brew install python-tk

# Windows:
# Reinstall Python with "tcl/tk and IDLE" checked
```

#### "Permission denied" errors
```bash
# Linux/macOS:
chmod +x secure_encryption.py

# Windows:
# Run command prompt as Administrator
```

#### "Python not found"
- Ensure Python is added to system PATH
- Use `python3` instead of `python` on Linux/macOS
- Reinstall Python with "Add to PATH" option

### Performance Issues

#### Slow startup
- Check antivirus software (may scan Python files)
- Use SSD storage for better performance
- Close unnecessary programs

#### GUI freezing
- Updated version includes proper threading
- Ensure sufficient RAM available
- Try command-line interface as alternative

## 🔄 Updates and Maintenance

### Keeping Up to Date

```bash
# Git method:
cd encryption-and-decryption
git pull origin main

# Manual method:
# Download new version and replace files
# Keep your secret.key and file_salts.json files
```

### Backup Important Files

Before updating, backup:
- `secret.key` - Your main encryption key
- `file_salts.json` - Password salt database
- Any encrypted files you need

### Clean Installation

```bash
# Remove old version (keep data files)
cp secret.key secret.key.backup
cp file_salts.json file_salts.json.backup

# Delete old files, install new version
# Restore backed up files

cp secret.key.backup secret.key
cp file_salts.json.backup file_salts.json
```

## 🏢 Enterprise/Multi-User Setup

### Shared Network Installation

1. Install on network drive
2. Each user gets their own `secret.key`
3. Consider centralized key management
4. Set appropriate file permissions

### Automated Deployment

```powershell
# Example PowerShell deployment script
$InstallPath = "C:\Program Files\SecureEncryption"
New-Item -ItemType Directory -Path $InstallPath
Copy-Item -Recurse ".\*" -Destination $InstallPath
# Set up shortcuts for all users
```

## 📞 Support

### Getting Help

1. **Check documentation** - README.md and this file
2. **Common issues** - See troubleshooting section
3. **GitHub Issues** - Report bugs or feature requests
4. **Community** - Check existing discussions

### Reporting Issues

When reporting problems, include:
- Operating system and version
- Python version
- Error messages (full text)
- Steps to reproduce
- Screenshots if relevant

---

**🎯 Ready to install? Follow the method that best suits your setup!**