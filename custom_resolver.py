#!/usr/bin/python3

import socket
import time
import sys
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype

# --- Configuration ---
# Root servers: a.root-servers.net to m.root-servers.net
ROOT_SERVERS = [
    "198.41.0.4", "199.9.14.201", "192.33.4.12", "199.7.91.13",
    "192.203.230.10", "192.5.5.241", "192.112.36.4", "198.97.190.53",
    "192.36.148.17", "192.58.128.30", "193.0.14.129", "199.7.83.42",
    "202.12.27.33"
]

LOG_FILE = "custom_resolver.log"
BIND_IP = "10.0.0.5"
BIND_PORT = 53

def log_message(msg):
    """Logs a message to the console and the log file."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    log_entry = f"[{now}] {msg}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def send_query(query_message, server_ip, timeout=2.0):
    """
    Sends a DNS query to a specific server IP.
    Returns the response and round-trip time (RTT).
    """
    start_time = time.time()
    try:
        # Use UDP for queries
        response = dns.query.udp(query_message, server_ip, timeout=timeout)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000  # RTT in ms
        return response, rtt
    except Exception as e:
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        log_message(f"  ERROR: Query to {server_ip} failed: {e}")
        return None, rtt

def resolve_iterative(domain_name):
    """
    Performs an iterative DNS resolution for the given domain name.
    Logs all steps as required by Task D.
    """
    log_message(f"--- New Query ---")
    log_message(f"Timestamp: {datetime.now()}")
    log_message(f"Domain Name: {domain_name}")
    log_message(f"Resolution Mode: Iterative")
    log_message(f"Cache Status: MISS (Caching not implemented)")

    # Start with the root servers
    current_servers = ROOT_SERVERS
    step_name = "Root"
    query_message = dns.message.make_query(domain_name, dns.rdatatype.A)
    total_start_time = time.time()

    # This loop will run until we find an answer (A record) or fail
    for _ in range(10): # Limit to 10 iterations to prevent infinite loops
        response = None
        rtt = 0
        
        # Try servers at the current level (Root, TLD, etc.)
        for server_ip in current_servers:
            log_message(f"Step: {step_name}")
            log_message(f"Contacting Server: {server_ip}")
            
            response, rtt = send_query(query_message, server_ip)
            log_message(f"RTT: {rtt:.2f} ms")

            if response:
                log_message(f"Response: Received response from {server_ip}")
                break
            else:
                log_message(f"Response: No response from {server_ip}")
        
        if not response:
            log_message("ERROR: No servers at this level responded.")
            return None # Failed to resolve

        # --- Analyze the response ---
        
        # 1. Check if we have an A record (the final answer)
        if response.answer:
            log_message(f"Step: Authoritative")
            log_message(f"Response: Found A-record in ANSWER section.")
            total_time = (time.time() - total_start_time) * 1000
            log_message(f"Total Time: {total_time:.2f} ms")
            log_message(f"--- Query End ---")
            return response

        # 2. If no answer, look in the AUTHORITY section for NS (referral)
        elif response.authority and response.authority[0].rdtype == dns.rdatatype.NS:
            # We got a referral to the next level (e.g., TLD servers)
            ns_records = response.authority[0]
            new_ns_domain = ns_records[0].to_text()
            log_message(f"Referral: Got referral to NS {new_ns_domain}")
            
            # Now we need the IP of that NS. Check the ADDITIONAL section.
            new_server_ips = []
            if response.additional:
                for record in response.additional:
                    if record.rdtype == dns.rdatatype.A:
                        new_server_ips.append(record[0].to_text())
            
            if new_server_ips:
                # Great, we have the IPs. Use them for the next iteration.
                current_servers = new_server_ips
                step_name = "TLD" if step_name == "Root" else "Authoritative"
                log_message(f"Referral: Found IPs in ADDITIONAL section: {new_server_ips}")
            else:
                # No IPs. We must resolve the NS domain itself.
                # This is a bit recursive, but it's part of the iterative process.
                log_message(f"Referral: No IPs in ADDITIONAL. Resolving NS {new_ns_domain}...")
                ns_response = resolve_iterative(new_ns_domain) # Recursive call to find IP
                if ns_response and ns_response.answer:
                    current_servers = [rec[0].to_text() for rec in ns_response.answer if rec.rdtype == dns.rdatatype.A]
                    step_name = "TLD" if step_name == "Root" else "Authoritative"
                    log_message(f"Referral: Resolved NS to IPs: {current_servers}")
                else:
                    log_message(f"ERROR: Could not resolve NS {new_ns_domain}.")
                    return None # Failed to resolve
        
        # 3. Handle CNAME (alias)
        elif response.answer and response.answer[0].rdtype == dns.rdatatype.CNAME:
            cname = response.answer[0][0].to_text()
            log_message(f"Response: Found CNAME alias: {cname}. Restarting query for {cname}")
            return resolve_iterative(cname) # Start over with the new name

        else:
            log_message("ERROR: Unhandled response type or empty response.")
            return None # Failed

    log_message("ERROR: Resolution failed after 10 iterations.")
    return None

def main():
    """
    The main DNS server loop.
    Listens for queries, passes them to the resolver, and sends back the response.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        sock.bind((BIND_IP, BIND_PORT))
    except PermissionError:
        log_message(f"FATAL: Permission denied. Did you forget 'sudo'?")
        sys.exit(1)
    except OSError as e:
        log_message(f"FATAL: Could not bind to {BIND_IP}:{BIND_PORT}. {e}")
        sys.exit(1)

    log_message(f"Custom DNS resolver listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        try:
            # Wait for a DNS query
            data, addr = sock.recvfrom(512)
            
            # Parse the query
            query_message = dns.message.from_wire(data)
            domain = query_message.question[0].name.to_text()

            # Resolve the domain
            response_message = resolve_iterative(domain)
            
            # Send the response back to the client
            if response_message:
                # Set the response ID to match the query ID
                response_message.id = query_message.id
                sock.sendto(response_message.to_wire(), addr)
            else:
                # If resolution failed, send a SERVFAIL response
                log_message(f"Sending SERVFAIL for {domain}")
                # Create a basic SERVFAIL response
                fail_response = dns.message.make_response(query_message)
                fail_response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(fail_response.to_wire(), addr)

        except Exception as e:
            log_message(f"SERVER ERROR: An error occurred: {e}")

if __name__ == "__main__":
    main()
