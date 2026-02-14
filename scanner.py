import requests
import sys
import json

# ANSI color codes for pretty terminal output
class Colors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'

def analyze_headers(url):
    print(f"{Colors.HEADER}--- Starting Security Scan for: {url} ---{Colors.ENDC}")
    
    report = {
        "target": url,
        "vulnerabilities": [],
        "score": 100
    }

    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        
        # 1. Check for HSTS
        if 'Strict-Transport-Security' not in headers:
            print(f"{Colors.FAIL}[X] Missing HSTS Header{Colors.ENDC}")
            report["vulnerabilities"].append("Missing Strict-Transport-Security")
            report["score"] -= 20
        else:
            print(f"{Colors.OKGREEN}[✓] HSTS Header found{Colors.ENDC}")

        # 2. Check for X-Content-Type-Options
        if 'X-Content-Type-Options' not in headers:
            print(f"{Colors.FAIL}[X] Missing X-Content-Type-Options{Colors.ENDC}")
            report["vulnerabilities"].append("Missing X-Content-Type-Options")
            report["score"] -= 20
        else:
            print(f"{Colors.OKGREEN}[✓] X-Content-Type-Options found{Colors.ENDC}")

        # 3. Check for X-Frame-Options
        if 'X-Frame-Options' not in headers:
            print(f"{Colors.FAIL}[X] Missing X-Frame-Options{Colors.ENDC}")
            report["vulnerabilities"].append("Missing X-Frame-Options")
            report["score"] -= 20
        else:
             print(f"{Colors.OKGREEN}[✓] X-Frame-Options found{Colors.ENDC}")

        # 4. Check for CSP
        if 'Content-Security-Policy' not in headers:
            print(f"{Colors.WARNING}[!] Missing Content-Security-Policy (Critical){Colors.ENDC}")
            report["vulnerabilities"].append("Missing Content-Security-Policy")
            report["score"] -= 30
        else:
            print(f"{Colors.OKGREEN}[✓] CSP found{Colors.ENDC}")

        # Final Report
        print(f"\n{Colors.HEADER}--- Scan Complete ---{Colors.ENDC}")
        print(f"Final Security Score: {report['score']}/100")
        
        # Fail the pipeline if score is too low
        if report["score"] < 80:
            sys.exit(1)
        else:
            sys.exit(0)

    except requests.exceptions.RequestException as e:
        print(f"{Colors.FAIL}Error connecting to target: {e}{Colors.ENDC}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <url>")
        sys.exit(1)
    
    target_url = sys.argv[1]
    analyze_headers(target_url)