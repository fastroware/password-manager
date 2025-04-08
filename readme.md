# Password Manager

<!-- ![Status](https://img.shields.io/badge/status-stable-green) -->
<!-- ![Version](https://img.shields.io/badge/version-1.0.0-blue) -->
<!-- ![License](https://img.shields.io/badge/license-MIT-yellow) -->
![Build Status](https://github.com/fastroware/password-manager/actions/workflows/build-release.yml/badge.svg)
![Latest Version](https://img.shields.io/github/v/tag/fastroware/password-manager?label=version)
![License](https://img.shields.io/github/license/fastroware/password-manager)
![Downloads](https://img.shields.io/github/downloads/fastroware/password-manager/total)

## ⚠️ DISCLAIMER

**IMPORTANT: USE AT YOUR OWN RISK**

The developers of this Password Manager DO NOT take any responsibility for data breaches, data loss, or any security issues that may arise from using this application. While we've implemented several security measures, no password manager can guarantee 100% security.

Security ultimately depends on:
- Your system's security
- How you handle your master password
- Potential software vulnerabilities

By using this Password Manager, you acknowledge these risks and accept full responsibility for your data security.

---

## 📋 About

An offline and secure password manager built with Python that helps you organize and protect your credentials. This application runs completely offline on your local machine, ensuring your sensitive data never leaves your computer.

### Key Features

- **Secure Encryption**: All data is encrypted using AES-128 (Fernet implementation)
- **Folder Organization**: Organize passwords into custom categories
- **Multi-language Support**: Currently supports English and Indonesian
- **User-friendly Interface**: Modern and intuitive GUI
- **Password Generator**: Create strong passwords with a single click
- **Local Storage**: All data is stored locally on your machine
- **Password Strength Indicator**: Visual feedback about password strength
- **Search Function**: Quickly find passwords across all folders

## 🔧 Installation

### Clone the Repository

```bash
git clone https://github.com/fastroware/password-manager.git
cd password-manager
```

### Install Dependencies

Use the included requirements file:

```bash
pip install -r requirements.txt
```

Or install dependencies manually:

```bash
pip install tkinter pillow cryptography
```

## 🚀 Usage

### Starting the Application

```bash
python password_manager.py
```

### First-time Setup

1. The application will create the necessary folders (`data` and `lang`) on first run
2. Create an account using the registration form
3. Log in with your newly created credentials

### Adding Passwords

1. Create a folder for organization (e.g., "Social Media", "Banking")
2. Navigate into a folder and click "Add Password"
3. Fill in the details and save

### Managing Passwords

- **View**: Click "Show" to see full password details
- **Edit**: Update existing password entries
- **Delete**: Remove passwords or folders no longer needed
- **Copy**: Quickly copy passwords to clipboard

### Security Features

- **Auto-logout**: For added security, the application doesn't keep you logged in after closing
- **Password Masking**: Passwords are hidden by default with a toggle to view
- **Encrypted Storage**: All password data is encrypted with your master key

## 🔒 Security Architecture

- **Master Password**: Never stored in plain text, only a cryptographic hash is saved
- **PBKDF2**: Password-based key derivation with 100,000 iterations for master password
- **AES-128 Encryption**: Industry-standard encryption algorithm for all sensitive data
- **Salted Hashes**: Unique salt for each user to prevent rainbow table attacks
- **Local Storage Only**: No internet connectivity, reducing attack vectors

## 🌍 Language Support

This application supports multiple languages. Currently available languages:

- English (en)
- Indonesian (id)

Switch languages using the language selector at the bottom of the application.

### Adding New Languages

To add a new language:
1. Create a new file in the `lang` folder named `lang-XX.json` (where XX is the language code)
2. Copy the structure from an existing language file and translate the values
3. The new language will automatically appear in the language selector

## 🤔 Why Use This Password Manager?

- **Offline Security**: Your data never leaves your computer
- **No Subscription Fees**: Completely free and open-source
- **No Account Required**: No email or cloud account needed
- **Transparency**: You can review the code to verify security measures
- **Customizable**: As an open-source project, you can modify it to suit your needs
- **No Tracking**: We don't collect any data about you or your usage

## 🔍 Technical Details

This application uses:
- Python 3.11+
- Tkinter for the GUI
- Cryptography library for secure encryption
- JSON for data structure

## ⚙️ System Requirements

- Python 3.11 or higher
- Operating System: Windows, macOS, or Linux
- Minimal disk space required (< 10MB excluding your password data)

## 🐛 Known Issues

- The UI may vary slightly between different operating systems
- On some systems, the initial window size might need adjustment

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

As this is an open-source project maintained by volunteers, support is provided on a best-effort basis. Please open an issue on GitHub if you encounter problems.

---

*Remember: The strongest security measure is your own vigilance. Choose a strong master password, keep your computer secure, and never share your credentials.*