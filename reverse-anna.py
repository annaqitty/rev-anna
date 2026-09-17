import socket
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import dnspython for robust DNS resolution
try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    print("Error: 'dnspython' library is required for best results.")
    print("Please run: pip install dnspython3")
    sys.exit(1)

# ANSI escape codes for colors
CYAN = '\033[96m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
RESET = '\033[0m'

# Global variables
total_found_hosts_count = 0
output_file = 'OUTPUT_HOST.txt' 
results_set = set() # Use a set to automatically deduplicate results

def reverse_lookup(ip_address):
    """
    Performs reverse DNS lookup using dnspython for speed and reliability.
    """
    try:
        # Create a reverse name object
        rev_name = dns.reversename.from_ip(ip_address)
        # Query for PTR records
        answers = dns.resolver.resolve(rev_name, 'PTR', lifetime=2)
        hostname = str(answers[0])
        
        # Clean up the hostname
        cleaned_hostname = hostname.replace("www.", "").replace('error:Invalid IPv4 address', '')\
                                   .replace('api.', '').replace('cpanel.', '').replace('webmail.', '')\
                                   .replace('webdisk.', '').replace('ftp.', '').replace('cpcalendars.', '')\
                                   .replace('cpcontacts.', '').replace('mail.', '').replace('ns1.', '')\
                                   .replace('ns2.', '').replace('ns3.', '').replace('ns4.', '')\
                                   .replace('autodiscover.', '').replace('www.', '')
        
        return cleaned_hostname

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, Exception):
        return None

def get_dns_records(domain):
    """
    Fetches A, AAAA, NS, MX, and TXT records using dnspython.
    Returns a list of strings.
    """
    records = []
    try:
        # A Records (IPv4)
        answers = dns.resolver.resolve(domain, 'A', lifetime=2)
        for rdata in answers:
            records.append(str(rdata))
            
        # AAAA Records (IPv6)
        try:
            answers = dns.resolver.resolve(domain, 'AAAA', lifetime=2)
            for rdata in answers:
                records.append(str(rdata))
        except: pass
            
        # NS Records (Name Servers)
        try:
            answers = dns.resolver.resolve(domain, 'NS', lifetime=2)
            for rdata in answers:
                records.append(str(rdata))
        except: pass
            
        # MX Records (Mail Exchange)
        try:
            answers = dns.resolver.resolve(domain, 'MX', lifetime=2)
            for rdata in answers:
                records.append(str(rdata))
        except: pass
            
        # TXT Records (SPF, DMARC, etc.)
        try:
            answers = dns.resolver.resolve(domain, 'TXT', lifetime=2)
            for rdata in answers:
                records.append(str(rdata))
        except: pass
            
    except Exception:
        pass
    return records

def process_ip(ip_address):
    global total_found_hosts_count
    
    # 1. Reverse Lookup
    hostname = reverse_lookup(ip_address)
    
    if hostname:
        # 2. Add to results set (deduplication handled by set)
        results_set.add(hostname)
        total_found_hosts_count += 1
        
        # 3. Perform DNS Enumeration on the hostname
        dns_records = get_dns_records(hostname)
        for record in dns_records:
            # Add records found via DNS lookup
            # We check if it looks like an IP or a domain
            if '.' in record and not record.startswith('http'):
                results_set.add(record)

def read_ips_from_file(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file.readlines() if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        print(f"{RED}File '{filename}' not found.{RESET}")
        return []

def main():
    global output_file
    
    # Prompt user for input and output filenames
    input_file = input("Enter the name of the input file (e.g., IPS.txt): ").strip()
    output_file = input("Enter the name of the output file (e.g., OUTPUT_HOST.txt): ").strip()

    # Ensure the output file is empty before starting
    if os.path.exists(output_file):
        os.remove(output_file)
    
    print(f"{YELLOW}Starting DNS enumeration...{RESET}")

    # Read IP addresses from the input file
    ip_addresses = read_ips_from_file(input_file)
    
    if not ip_addresses:
        print(f"{RED}No IP addresses found in {input_file}.{RESET}")
        return

    # Define the number of threads
    num_threads = 300

    # Use ThreadPoolExecutor to handle threads
    start_time = time.time()
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        future_to_ip = {executor.submit(process_ip, ip): ip for ip in ip_addresses}
        
        # Wait for all futures to complete and handle exceptions
        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                future.result()
            except Exception as e:
                print(f"{RED}Error processing {ip}: {e}{RESET}")

    # Write results to file
    with open(output_file, 'w') as file:
        for host in sorted(results_set):
            file.write(f"{host}\n")
            
    end_time = time.time()
    duration = end_time - start_time

    # Print the final report
    print(f"\n{'='*50}")
    print(f"{GREEN}Results Summary:{RESET}")
    print(f"{CYAN}Total Unique Hosts Found: {total_found_hosts_count}{RESET}")
    print(f"{CYAN}Results saved to: {output_file}{RESET}")
    print(f"{CYAN}Time taken: {duration:.2f} seconds{RESET}")
    print(f"{'='*50}")

if __name__ == "__main__":
    main()
