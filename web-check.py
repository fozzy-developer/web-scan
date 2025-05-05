#!/usr/bin/env python3

import requests
import sys
import argparse
import re

class bcolors:
    OK = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    RESET = '\033[0m'
    INFO = '\033[94m'

parser = argparse.ArgumentParser(description="Search URLs and domains via Wayback Machine")
parser.add_argument("-k", "--keyword", help="search for a specific extension or keyword (e.g., js, xml, json, pdf, admin, login)", type=str)
parser.add_argument("-l", "--limit", help="limit number of links to retrieve", type=str)
args = parser.parse_args()

def clean_domain(input_url):
    """Cleans the input domain or URL, returning only the domain name."""
    cleaned = re.sub(r'^(https?://)?(www\.)?', '', input_url, flags=re.IGNORECASE)
    cleaned = re.sub(r'[:/].*$', '', cleaned)
    return cleaned.strip()

def is_valid_domain(domain):
    """Checks if the string is a valid domain."""
    if len(domain) < 3 or ' ' in domain:
        return False
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9\-]*(?:\.[a-zA-Z0-9][a-zA-Z0-9\-]*)*\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def get_file_type(url):
    """Determines the file type from the URL and returns a label."""
    if re.search(r'\.js(?:\?|$)', url, re.IGNORECASE):
        return '[Site Script]'
    if re.search(r'\.css(?:\?|$)', url, re.IGNORECASE):
        return '[Site Styles]'
    return ''

def match_domains(urls):
    """Extracts unique domains from the list of URLs."""
    regex = r"^(?:https?:\/\/)?(?:[^@\/\n]+@)?(?:www\.)?([^:\/\n]+)/?"
    matches = re.finditer(regex, urls, re.MULTILINE)
    domain_list = [match.group(1) for match in matches]
    
    unique_domains = sorted(set(domain_list))
    if unique_domains:
        print(bcolors.INFO + "\n[*] Domains found:" + bcolors.RESET)
        for domain in unique_domains:
            print(f"  - {domain}")
    else:
        print(bcolors.WARNING + "[!] No domains found." + bcolors.RESET)
    return unique_domains

def fetch_urls(domain):
    """Sends a request to the Wayback Machine and returns the list of URLs."""
    url = f"https://web.archive.org/cdx/search?matchType=domain&collapse=urlkey&output=text&fl=original&url={domain}/"
    
    if args.keyword:
        url += f"&filter=urlkey:.*{args.keyword}"
    if args.limit:
        try:
            limit = int(args.limit)
            if limit <= 0:
                raise ValueError
            url += f"&limit={limit}"
        except ValueError:
            print(bcolors.FAIL + "[!] Error: Invalid limit value. Must be a positive integer." + bcolors.RESET)
            sys.exit(1)

    print(bcolors.INFO + f"[*] Processing request for {domain}... This may take a few seconds." + bcolors.RESET)
    try:
        rq = requests.get(url, timeout=15)
        rq.raise_for_status()
        return rq.text.strip()
    except requests.Timeout:
        print(bcolors.FAIL + "[!] Error: Request timed out. Please try again later." + bcolors.RESET)
        return None
    except requests.ConnectionError:
        print(bcolors.FAIL + "[!] Error: Failed to connect to the server. Check your internet connection." + bcolors.RESET)
        return None
    except requests.HTTPError as e:
        status_code = e.response.status_code
        if status_code == 429:
            print(bcolors.FAIL + "[!] Error: Too many requests. Please wait and try again." + bcolors.RESET)
        else:
            print(bcolors.FAIL + f"[!] HTTP Error: {status_code} - {e}" + bcolors.RESET)
        return None
    except requests.RequestException as e:
        print(bcolors.FAIL + f"[!] Error during request: {e}" + bcolors.RESET)
        return None

def print_urls(urls_text):
    """Prints URLs, grouping by type (JS, CSS, other)."""
    if not urls_text:
        print(bcolors.WARNING + "[!] No URLs found for this domain." + bcolors.RESET)
        return

    js_urls = []
    css_urls = []
    other_urls = []

    for url in urls_text.splitlines():
        file_type = get_file_type(url)
        if '[Site Script]' in file_type:
            js_urls.append((url, file_type))
        elif '[Site Styles]' in file_type:
            css_urls.append((url, file_type))
        else:
            other_urls.append((url, file_type))

    print(bcolors.OK + "\n[+] Found URLs:" + bcolors.RESET)
    
    if js_urls:
        print(bcolors.OK + "JavaScript Files:" + bcolors.RESET)
        for url, file_type in js_urls:
            print(f"  - {url} {bcolors.INFO}{file_type}{bcolors.RESET}")
    
    if css_urls:
        print(bcolors.OK + "\nCSS Files:" + bcolors.RESET)
        for url, file_type in css_urls:
            print(f"  - {url} {bcolors.INFO}{file_type}{bcolors.RESET}")
    
    if other_urls:
        print(bcolors.OK + "\nOther URLs:" + bcolors.RESET)
        for url, file_type in other_urls:
            print(f"  - {url}")

def main():
    while True:
        input_url = input(bcolors.INFO + "[*] Enter domain or URL (e.g., https://example.com, http://example.com, example.com): " + bcolors.RESET).strip()
        
        if not input_url:
            print(bcolors.FAIL + "[!] Error: No input provided. Please try again." + bcolors.RESET)
            continue

        domain = clean_domain(input_url)
        if not is_valid_domain(domain):
            print(bcolors.FAIL + "[!] Error: Invalid domain or URL. Please try again." + bcolors.RESET)
            continue

        urls_text = fetch_urls(domain)
        if urls_text is not None:
            print_urls(urls_text)
            match_domains(urls_text)
        break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(bcolors.FAIL + "\n[!] Script canceled by user." + bcolors.RESET)
        sys.exit(0)
    except Exception as e:
        print(bcolors.FAIL + f"[!] An unexpected error occurred: {e}" + bcolors.RESET)
        sys.exit(1)
