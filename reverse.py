import socket
import threading
import os
from queue import Queue


results = set()
lock = threading.Lock()


def get_output_filename(filename):

    if not os.path.exists(filename):
        return filename

    name, ext = os.path.splitext(filename)

    count = 2

    while True:
        new_name = f"{name}({count}){ext}"

        if not os.path.exists(new_name):
            return new_name

        count += 1



def reverse_lookup(ip):

    try:
        # Reverse DNS lookup
        hostname, _, _ = socket.gethostbyaddr(ip)

        hostname = hostname.lower().strip()

        # Clean hostname
        hostname = hostname.replace("www.", "")

        parts = hostname.split(".")


        # Extract domain
        if len(parts) >= 2:
            domain = ".".join(parts[-2:])
        else:
            domain = hostname


        # Extract subdomain
        if len(parts) > 2:
            subdomain = hostname
        else:
            subdomain = None


        # Save results safely
        with lock:

            # Full hostname
            results.add(hostname)

            # Domain
            results.add(domain)

            # Subdomain
            if subdomain:
                results.add(subdomain)


        print(f"[+] {ip} -> {hostname}")


    except Exception:
        print(f"[-] {ip} -> No PTR")



def worker(queue):

    while True:

        ip = queue.get()

        if ip is None:
            break

        try:
            reverse_lookup(ip)

        finally:
            queue.task_done()



def read_ips(filename):

    with open(filename, "r") as f:

        return [
            line.strip()
            for line in f
            if line.strip()
        ]



def save_results(filename):

    with open(filename, "w", encoding="utf-8") as f:

        for item in sorted(results):
            f.write(item + "\n")



if __name__ == "__main__":


    input_file = "IPS.txt"
    output_file = "OUTPUT_HOST.txt"

    threads = 100


    # Create new filename if exists
    output_file = get_output_filename(output_file)


    ips = read_ips(input_file)


    print(f"[*] Loaded {len(ips)} IPs")
    print(f"[*] Output: {output_file}")


    queue = Queue()


    for ip in ips:
        queue.put(ip)



    workers = []

    for _ in range(threads):

        t = threading.Thread(
            target=worker,
            args=(queue,)
        )

        t.start()
        workers.append(t)



    queue.join()



    # Stop threads
    for _ in workers:
        queue.put(None)


    for t in workers:
        t.join()



    save_results(output_file)


    print("\nFinished!")
    print(f"Found {len(results)} domains/subdomains")
    print(f"Saved to {output_file}")
