#!/usr/bin/env python3
import requests
import re
import argparse
import warnings
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3
warnings.simplefilter('ignore', InsecureRequestWarning)

# Define ANSI escape sequences for colors
RED = "\033[31m"  # Red for vulnerable
GREEN = "\033[32m"  # Green for safe
NC = "\033[0m"  # No Color

# Fetch security.txt or /.well-known/security.txt and save found links
def fetch_security_txt(url, output_file):
    # Ensure URL has a trailing slash
    if not url.endswith('/'):
        url += '/'

    security_urls = [url + "security.txt", url + ".well-known/security.txt"]
    
    found_links = []

    for sec_url in security_urls:
        try:
            response = requests.get(sec_url, timeout=10, verify=False)  # Ignore SSL warnings
            if response.status_code == 200:
                print(f"[+] {sec_url} found.")
                found_links.append(sec_url)  # Save found link
                return response.text, found_links
            else:
                print(f"[-] {sec_url} not found (Status: {response.status_code}).")
        except requests.exceptions.RequestException as e:
            print(f"Error fetching {sec_url}: {e}")
    
    return None, found_links

# Command-line interface
def main():
    parser = argparse.ArgumentParser(description='Security.txt Checker Tool')
    parser.add_argument('-f', '--file', type=str, help='File containing list of domains (e.g., domain.txt)')
    parser.add_argument('url', type=str, nargs='?', help='Target website URL (e.g., https://example.com)')
    
    args = parser.parse_args()

    # To store found links
    all_found_links = []

    # If a file is specified, read domains from the file
    if args.file:
        try:
            with open(args.file, 'r') as f:
                domains = f.read().splitlines()
                for domain in domains:
                    # Check and add http:// or https:// if needed
                    if not domain.startswith(('http://', 'https://')):
                        domain = 'http://' + domain  # Or use 'https://'
                    print(f"Checking {domain}...")
                    content, found_links = fetch_security_txt(domain, 'found.txt')
                    all_found_links.extend(found_links)  # Ghi lại các links tìm thấy
        except FileNotFoundError:
            print(f"[-] The file {args.file} was not found.")
    elif args.url:
        # Check and add http:// or https:// if needed
        if not args.url.startswith(('http://', 'https://')):
            args.url = 'http://' + args.url
        content, found_links = fetch_security_txt(args.url, 'found.txt')
        all_found_links.extend(found_links)  # Ghi lại link tìm thấy

    # Lưu các links được tìm thấy vào tệp found.txt
    if all_found_links:
        with open('found.txt', 'w') as output_file:
            for link in all_found_links:
                output_file.write(link + '\n')
        print("[+] Found links saved to found.txt.")
    else:
        print("[-] No security.txt links found.")

if __name__ == "__main__":
    main()
