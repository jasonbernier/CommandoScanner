# CommandoScanner

## Description
CommandoScanner is a powerful Python-based tool designed for security professionals and ethical hackers to identify and exploit command injection vulnerabilities in web applications. It supports a wide range of functionalities, including dynamic payload generation, GET and POST request handling, custom header support, interactive shell access for confirmed vulnerabilities, and more.

## Key Features
- **Dynamic Payload Generation**: Utilizes both predefined and dynamically generated payloads to test for command injection vulnerabilities.
- **Support for GET and POST Requests**: Allows users to specify the request method suitable for the target application's API.
- **Custom Headers and Authentication**: Facilitates testing of authenticated endpoints by adding custom request headers.
- **Interactive Shell**: Engages an interactive shell for real-time exploitation upon detecting a vulnerable endpoint.
- **Proxy Support**: Routes traffic through a specified proxy server, aiding in anonymity and evasion.
- **User-Agent Randomization**: Avoids detection by randomizing the user-agent string in each request.

## Usage
CommandoScanner is a command-line tool that accepts various arguments to customize the testing process:

```bash
python commandoscanner.py --url TARGET_URL --param PARAMETER [--method {GET,POST}] [--proxy PROXY] [--headers HEADERS]
```

- `--url`: The target URL to test.
- `--param`: The parameter suspected of being vulnerable to command injection.
- `--method`: Optional. Specify 'GET' or 'POST' for the request method. Defaults to 'GET'.
- `--proxy`: Optional. Set a proxy server (e.g., 'http://127.0.0.1:8080').
- `--headers`: Optional. Add custom headers in JSON format (e.g., '{"Authorization": "Bearer XYZ"}').

### Example Commands
Testing with a GET request and custom headers:
```bash
python commandoscanner.py --url "http://example.com/vuln-page" --param "cmd" --method GET --headers '{"Cookie": "session=abcd123"}'
```

Testing with a POST request through a proxy:
```bash
python commandoscanner.py --url "http://example.com/login" --param "username" --method POST --proxy "http://127.0.0.1:8080"
```

## Installation
Ensure you have Python 3 and pip installed on your system. Install the required dependencies by running:
```bash
pip install -r requirements.txt
```

## Disclaimer
CommandoScanner is intended for legal security auditing and educational purposes only. It is the end user's responsibility to comply with all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

