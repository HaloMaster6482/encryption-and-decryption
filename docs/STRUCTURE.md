# 📁 Project Structure

This document describes the organization of files in the Secure Encryption Tool project.

## 📂 Directory Structure

```
encryption-and-decryption/
├── 🐍 secure_encryption.py          # Main application (GUI + CLI)
├── 🚀 Secure_Encryption_Tool.bat    # Windows launcher script
├── 🔑 secret.key                    # Main encryption key (auto-generated)
├── 🧂 file_salts.json               # Salt storage for password protection
├── 📖 README.md                     # Main documentation
├── ⚖️ LICENSE                       # Project license
├── 📁 docs/                         # Documentation directory
│   └── 🚀 INSTALL.md                # Installation guide
└── 📦 .git/                         # Git repository data
```

## 📝 File Descriptions

### Core Application Files

| File | Purpose | Required | Description |
|------|---------|----------|-------------|
| `secure_encryption.py` | Main app | ✅ Yes | Complete encryption tool with GUI and CLI |
| `Secure_Encryption_Tool.bat` | Launcher | 📌 Windows | Batch script for easy Windows launching |
| `secret.key` | Encryption key | ✅ Yes | Auto-generated Fernet key for non-password encryption |
| `file_salts.json` | Password data | 🔒 Security | Salt storage for password-protected files |

### Documentation Files

| File | Purpose | Required | Description |
|------|---------|----------|-------------|
| `README.md` | Main docs | 📖 Recommended | Complete feature overview and usage guide |
| `docs/INSTALL.md` | Setup guide | 🚀 Helpful | Detailed installation instructions |
| `LICENSE` | Legal | ⚖️ Standard | Project license information |

### Repository Files

| File | Purpose | Required | Description |
|------|---------|----------|-------------|
| `.git/` | Version control | 📦 Git | Git repository metadata and history |

## 🔄 File Lifecycle

### First Run
1. `secure_encryption.py` launches
2. `secret.key` is auto-generated if missing
3. User can start encrypting files immediately

### During Use
- `file_salts.json` is created when first password-protected file is encrypted
- Encrypted files (`.enc`) are created in user-specified locations
- Operation logs appear in GUI

### Backup Priority
1. **Critical**: `secret.key` (without this, non-password files cannot be decrypted)
2. **Important**: `file_salts.json` (needed for password-protected files)
3. **Useful**: `secure_encryption.py` (can be re-downloaded)
4. **Optional**: Documentation and scripts (can be re-downloaded)

## 🚫 Files NOT Included

The following files are intentionally excluded to keep the project clean:

- ❌ Test files and folders (`test_*`)
- ❌ Setup scripts (`create_shortcut.ps1`, `install_shortcuts.ps1`)
- ❌ Legacy files (`file_passwords.json`)
- ❌ Python cache (`__pycache__/`, `*.pyc`)
- ❌ IDE files (`.vscode/`, `.idea/`)
- ❌ OS files (`.DS_Store`, `Thumbs.db`)

## 🔧 Development Files

If contributing to development, you might see additional files:
- `requirements.txt` - Python dependencies
- `setup.py` - Installation script
- `tests/` - Test suite
- `examples/` - Usage examples

## 📏 Project Size

- **Total size**: ~50-100 KB (excluding encrypted files)
- **Core app**: ~30 KB (`secure_encryption.py`)
- **Documentation**: ~20 KB (README + INSTALL)
- **Other files**: <10 KB

## 🔒 Security Considerations

### File Permissions
- `secret.key` - Should be readable only by owner (600 on Unix)
- `file_salts.json` - Should be readable only by owner (600 on Unix)
- `secure_encryption.py` - Standard executable permissions (755 on Unix)

### Sensitive Files
- **Never commit** `secret.key` or `file_salts.json` to public repositories
- **Always backup** key files before major changes
- **Use `.gitignore`** to prevent accidental commits of sensitive data

---

**🎯 This structure provides a clean, professional, and secure encryption tool!**