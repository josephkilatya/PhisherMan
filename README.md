# README.md

```markdown
# PhisherMan: Phishing Email Analysis Tool

A comprehensive desktop application for analyzing and investigating phishing emails with advanced security features and detailed email forensics.

## Overview

PhisherMan is a powerful Python-based application that provides security analysts with tools to examine suspicious emails, extract metadata, analyze attachments, and perform threat intelligence lookups.

## Features

### 📧 Email Analysis
- **Header Analysis**: Extract and display complete email headers
- **URL Extraction**: Identify and analyze URLs with protocol and port information
- **Attachment Analysis**: File type identification and hash calculation (MD5, SHA1, SHA256)
- **HTML Rendering**: View email content as rendered HTML
- **Raw Email View**: Access complete raw email content

### 🔍 Threat Intelligence
- **VirusTotal Integration**: Domain reputation checking
- **WHOIS Data**: Domain registration information
- **Security Scanning**: Multiple antivirus engine results

### 🎨 User Interface
- Modern ttkbootstrap-themed GUI
- Tabbed interface for organized data presentation
- Right-click copy functionality for easy data extraction
- Responsive layout with scrollable sections

## Project Structure

```
PhisherMan/
├── main.py                 # Main application entry point
├── login.py               # Authentication forms and validation
├── display_module/
│   └── __init__.py        # Main email analysis GUI (provided above)
├── attachments/           # Extracted email attachments storage
└── README.md             # Project documentation
```

## Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Step 1: Install Dependencies
```bash
pip install ttkbootstrap tkinterhtml requests python-magic beautifulsoup4 pygments email
```

### Step 2: System Dependencies
**For Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libmagic1
```

**For macOS:**
```bash
brew install libmagic
```

**For Windows:**
- Download and install [python-magic-bin](https://pypi.org/project/python-magic-bin/)

### Step 3: Run the Application
```bash
python main.py
```

## Usage

### 1. Authentication
- Launch the application
- No authentication required

### 2. Email Analysis
1. **Open Email File**: Use File → Open to select an .eml file
2. **Navigate Tabs**:
   - **Headers**: View complete email metadata
   - **URLs**: Extract and analyze embedded URLs
   - **Rendered HTML**: See how the email appears to recipients
   - **VirusTotal Results**: Domain reputation analysis
   - **Attached Files**: File information and hashes
   - **Raw Email**: Complete email source
   - **WHOIS Data**: Domain registration information
   - **Raw HTML**: Formatted HTML source code

### 3. Data Extraction
- Right-click on any table row to copy data
- Export findings for further analysis
- Generate security reports

## Modules Overview

### Email Processing Module (`display_module/__init__.py`)
- **EmailProcessor**: Parses .eml files and extracts metadata
- **VirusTotalScanner**: Performs domain reputation checks
- **FileProcessor**: Analyzes email attachments
- **GUI**: Main interface with tabbed analysis panels

## API Configuration

### VirusTotal Integration
The application uses VirusTotal API for domain reputation checks. To use this feature:

1. Get a free API key from [VirusTotal](https://www.virustotal.com/)
2. Replace the API key in `VirusTotalScanner` class:
```python
api_key = "your_virustotal_api_key_here"
```

## Supported File Formats

- **Email Files**: .eml format
- **Attachments**: All file types (automatically extracted and analyzed)


## Troubleshooting

### Common Issues

1. **Module Import Errors**:
   ```bash
   pip install --upgrade ttkbootstrap tkinterhtml
   ```

2. **File Type Detection Issues**:
   - Ensure `python-magic` dependencies are installed
   - Verify file permissions for attachment extraction

3. **VirusTotal API Errors**:
   - Check internet connection
   - Verify API key validity
   - Monitor API rate limits

## Development

### Adding New Analysis Features
1. Extend the `EmailProcessor` class for new parsing capabilities
2. Add new tabs to the `GUI` class for additional analysis views
3. Integrate with additional threat intelligence APIs

### Customizing the Interface
- Modify ttkbootstrap themes in the `GUI` class
- Add new menu items in the menu bar configuration
- Extend treeview columns for additional data points

## Legal and Ethical Use

⚠️ **Important**: This tool is intended for:
- Security research and education
- Incident response and forensics
- Legitimate email analysis
- Authorized penetration testing

**Do not use for:**
- Unauthorized access to systems
- Harassment or spamming
- Illegal surveillance activities

## Credits

**Developer**: Joseph Kilatya  
**Version**: 1.00  
**Copyright**: © 2024 josephkilatya

## License

This software is provided 'as-is', without any expressed or implied warranty. In no event will the author be held liable for any damages arising from the use of this software.

## Support

For issues and feature requests, please ensure:
1. You're using the latest version
2. All dependencies are properly installed
3. You've reviewed the troubleshooting section

---

**Disclaimer**: This tool is for educational and legitimate security analysis purposes only. Always ensure you have proper authorization before analyzing emails.
```

## Key Improvements in the README:

1. **Complete Project Overview**: Now covers email analysis components
2. **Detailed Installation Instructions**: Includes system-specific dependencies
3. **Comprehensive Usage Guide**: Step-by-step instructions for all features
4. **API Configuration**: Instructions for setting up VirusTotal integration
5. **Troubleshooting Section**: Common issues and solutions
6. **Security Considerations**: Clear guidelines for ethical use
7. **Module Documentation**: Explains each component's purpose
8. **Legal Compliance**: Important disclaimers and usage guidelines

The README now provides a complete guide for users to install, configure, and use your PhisherMan application effectively.
