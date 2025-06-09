# IP Address Lookup Tool 🌐

A comprehensive Python tool for retrieving detailed IP address information using the IPInfo API.

## Features ✨

- 🔍 **Interactive Mode**: User-friendly terminal interface
- 📋 **Command Line Mode**: Single command IP lookups  
- 🌍 **IPv4 & IPv6 Support**: Works with both IP versions
- 🔄 **Retry Logic**: Automatic retry with exponential backoff
- 🔐 **Authentication Support**: Use API tokens for unlimited requests
- 📊 **Multiple IP Lookup**: Process multiple IPs at once
- 🛡️ **Privacy Detection**: Identifies VPNs, proxies, Tor, etc.
- 📄 **Flexible Output**: Formatted display or raw JSON
- ⚡ **Error Handling**: Comprehensive error management

## Quick Start 🚀

### Option 1: Automatic Setup (Recommended)

**Windows:**
```cmd
setup_windows.bat
```

**macOS/Linux:**
```bash
chmod +x setup_unix.sh
./setup_unix.sh
```

### Option 2: Manual Setup

1. **Create virtual environment:**
   ```bash
   python -m venv ip-tool-env

   # Activate it:
   # Windows: ip-tool-env\Scripts\activate
   # macOS/Linux: source ip-tool-env/bin/activate
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the tool:**
   ```bash
   python ip_lookup_enhanced.py
   ```

## Usage Examples 💡

### Interactive Mode
```bash
python ip_lookup_enhanced.py
```

### Single IP Lookup
```bash
python ip_lookup_enhanced.py 8.8.8.8
```

### JSON Output
```bash
python ip_lookup_enhanced.py --json 8.8.8.8
```

### With Authentication Token
```bash
python ip_lookup_enhanced.py --token YOUR_TOKEN 8.8.8.8
```

### Multiple IPs (Interactive Mode)
Enter IPs separated by commas or spaces:
```
Enter IP address: 8.8.8.8, 1.1.1.1, 208.67.222.222
```

## API Information 📡

This tool uses the [IPInfo API](https://ipinfo.io):

- **Free Tier**: 1000 requests/day (shared by IP address)
- **Authenticated Free**: Unlimited requests with free account
- **Sign up**: [ipinfo.io/signup](https://ipinfo.io/signup)

### Getting an API Token (Optional but Recommended)

1. Visit [ipinfo.io/signup](https://ipinfo.io/signup)
2. Create a free account
3. Copy your access token
4. Use with `--token` flag or set `IPINFO_TOKEN` environment variable

## Sample Output 📄

```
============================================================
               🌐 IP ADDRESS INFORMATION
============================================================

📍 IP Address:      8.8.8.8
🏠 Hostname:        dns.google
🌍 Country:         US (United States)
🗺️  Region:          California
🏙️  City:            Mountain View
📮 Postal Code:     94035
📍 Latitude:        37.3860
📍 Longitude:       -122.0838
🏢 Organization:    AS15169 Google LLC
🕐 Timezone:        America/Los_Angeles
============================================================
```

## Configuration ⚙️

### Environment Variables
Copy `.env.template` to `.env` and customize:
```bash
IPINFO_TOKEN=your_token_here
API_TIMEOUT=10
MAX_RETRIES=3
```

### Config File
Modify `config.json` for default settings:
```json
{
    "api": {
        "timeout": 10,
        "max_retries": 3
    },
    "output": {
        "show_emojis": true,
        "show_privacy_info": true
    }
}
```

## Testing 🧪

Run the test script to verify functionality:
```bash
python test_ip_lookup.py
```

## Troubleshooting 🔧

### Common Issues:

1. **"Module not found"**: Ensure virtual environment is activated
2. **"Connection error"**: Check internet connection and firewall
3. **"Rate limit exceeded"**: Consider using an API token
4. **"Invalid IP format"**: Verify IP address syntax

### Debug Mode:
Add print statements or use VS Code debugger (F5) for detailed troubleshooting.

## Project Structure 📁

```
ip-lookup-tool/
├── ip_lookup_enhanced.py      # Main application
├── requirements.txt           # Python dependencies  
├── config.json               # Configuration template
├── .env.template             # Environment variables template
├── test_ip_lookup.py         # Test script
├── setup_windows.bat         # Windows setup script
├── setup_unix.sh             # Unix/Linux/macOS setup script
└── README.md                 # This file
```

## Contributing 🤝

Feel free to fork, modify, and improve this tool! Some ideas for enhancements:

- GUI interface using tkinter or PyQt
- Database storage for lookup history
- Export functionality (CSV, Excel)
- Bulk IP processing from files
- Geolocation mapping integration
- Performance monitoring

## License 📝

This project is open source. Use it freely for personal and commercial projects.

## Support 💬

For issues with the tool, check the troubleshooting section or create an issue.
For IPInfo API questions, visit [ipinfo.io/support](https://ipinfo.io/support).

---

**Happy IP hunting! 🕵️‍♂️**
