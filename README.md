# IPProxyChecker

# IP Checker

A web application for checking and analyzing IP addresses using the IPQualityScore service. The application allows verification of IP addresses for proxies, VPNs, TOR, and other security characteristics.

## Features

- Individual IP address verification
- Multiple IP address verification (up to 20 simultaneously)
- Text file upload for IP addresses
- Filter results by multiple criteria:
  - Proxy/VPN
  - VPN
  - TOR
  - Bot Status
  - Fraud Score
  - Recent Abuse
  - Crawler
- Export results to CSV format
- Intuitive and easy-to-use interface
- Quick data reset
- Results persistence until manual reset or page reload

## Requirements

- Python 3.x
- Flask
- pandas
- requests
- python-dotenv

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd ip-checker
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create a `.env` file and add your API key:
```
API_KEY=your_api_key_here
```

## Usage

1. Start the application:
```bash
python app.py
```

2. Open your browser and navigate to `http://localhost:5050`

3. You can check IP addresses in the following ways:
   - Enter a single IP address in the dedicated field
   - Enter multiple IP addresses separated by commas (max 20)
   - Upload a .txt file with IP addresses (one per line)

4. Use filters to refine results:
   - Check desired criteria
   - Adjust values as needed
   - Results update automatically

5. To export results:
   - Apply desired filters
   - Click the "Download CSV" button
   - File will download automatically

6. To reset data:
   - Click the "Reset Data" button
   - All results will be cleared

## Project Structure

```
ip-checker/
├── app.py                 # Main Flask application
├── ip_checker.py         # IP checking class
├── requirements.txt      # Project dependencies
├── static/
│   ├── css/
│   │   └── style.css    # CSS styling
│   └── js/
│       └── main.js      # JavaScript logic
└── templates/
    └── index.html       # Main template
```

## API and Rate Limiting

The service uses the IPQualityScore API which has the following limits:
- Free checks: 5,000/month
- Rate limit: 2 requests/second

## Security Features

- IP address input validation
- Limit of 20 IPs for multiple verification
- Data sanitization before display
- XSS injection protection
- Secure file handling for uploads

## Data Persistence

- Results are stored in memory until:
  - Manual reset via the "Reset Data" button
  - Application restart
  - Browser page reload
- Filtered results can be downloaded at any time
- All data is temporary and not stored in any database

## Error Handling

- Invalid IP address format detection
- Maximum IP limit enforcement
- API error handling and user feedback
- File upload validation
- Empty result set handling

## Contributing

If you'd like to contribute to the project:
1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the [MIT License](LICENSE).

## Acknowledgments

- [IPQualityScore](https://www.ipqualityscore.com/) for providing the IP verification service
- Flask community for the excellent web framework
- Pandas team for the data handling capabilities
