#!/usr/bin/python3

import socket
import time
import sys
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype
import os

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

DNS_CACHE = {} 
CACHE_HITS = 0
TOTAL_QUERIES_RESOLVED = 0

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
    """Performs ITERATIVE DNS resolution WITH CACHING."""
    global DNS_CACHE, CACHE_HITS, TOTAL_QUERIES_RESOLVED # Allow modification

    log_message(f"--- New Query (Iterative with Cache Check) ---")
    log_message(f"Timestamp: {datetime.now()}")
    log_message(f"Domain Name: {domain_name}")

    # --- CACHE CHECK ---
    if domain_name in DNS_CACHE:
        ip_address, expiration_time = DNS_CACHE[domain_name]
        if time.time() < expiration_time:
            # Cache HIT!
            CACHE_HITS += 1
            TOTAL_QUERIES_RESOLVED += 1
            log_message(f"Resolution Mode: Iterative (Cache HIT)")
            log_message(f"Cache Status: HIT") # Log HIT
            log_message(f"Returning cached IP: {ip_address}")
            log_message(f"--- Query End (Cache Hit) ---")
            response = dns.message.make_response(dns.message.make_query(domain_name, dns.rdatatype.A))
            ttl_remaining = int(expiration_time - time.time())
            response.answer.append(dns.rrset.from_text(domain_name, max(1, ttl_remaining), dns.rdataclass.IN, dns.rdatatype.A, ip_address))
            return response
        else:
            log_message(f"Cache entry for {domain_name} expired. Removing.")
            del DNS_CACHE[domain_name]
    # --- END CACHE CHECK ---

    log_message(f"Resolution Mode: Iterative (Cache MISS)")
    log_message(f"Cache Status: MISS") # Log MISS

    current_servers = ROOT_SERVERS
    step_name = "Root"
    query_message = dns.message.make_query(domain_name, dns.rdatatype.A)
    total_start_time = time.time()

    for _ in range(10): # Iterative lookup loop
        response = None; rtt = 0
        for server_ip in current_servers:
            log_message(f"Step: {step_name}"); log_message(f"Contacting Server: {server_ip}")
            response, rtt = send_query(query_message, server_ip)
            log_message(f"RTT: {rtt:.2f} ms")
            if response: log_message(f"Response: Received from {server_ip}"); break
            else: log_message(f"Response: No response from {server_ip}")
        if not response: log_message("ERROR: No servers responded."); return None

        # --- Analyze response ---
        if response.answer:
            answer_record = response.answer[0]; record_type = answer_record.rdtype
            if record_type == dns.rdatatype.A:
                ip_found = answer_record[0].to_text(); ttl = answer_record.ttl; expiration = time.time() + ttl
                log_message(f"Step: Authoritative"); log_message(f"Response: Found A-record: {ip_found} TTL: {ttl}s")
                # --- STORE IN CACHE ---
                DNS_CACHE[domain_name] = (ip_found, expiration)
                log_message(f"Stored in cache. Expires: {datetime.fromtimestamp(expiration)}")
                # --- END STORE ---
                total_time = (time.time() - total_start_time) * 1000; log_message(f"Total Time: {total_time:.2f} ms"); log_message(f"--- Query End ---")
                TOTAL_QUERIES_RESOLVED += 1; return response
            elif record_type == dns.rdatatype.CNAME:
                cname = answer_record[0].to_text(); log_message(f"Response: Found CNAME: {cname}. Restarting query...")
                return resolve_iterative(cname) # Follow CNAME
        elif response.authority and response.authority[0].rdtype == dns.rdatatype.NS:
             # (NS Referral logic - same as before)
             ns_records = response.authority[0]; new_ns_domain = ns_records[0].to_text()
             log_message(f"Referral: Got NS {new_ns_domain}"); new_server_ips = []
             if response.additional:
                  for record in response.additional:
                       if record.rdtype == dns.rdatatype.A: new_server_ips.append(record[0].to_text())
             if new_server_ips:
                  current_servers = new_server_ips; step_name = "TLD" if step_name == "Root" else "Authoritative"
                  log_message(f"Referral: IPs in ADDITIONAL: {new_server_ips}")
             else:
                  log_message(f"Referral: No IPs. Resolving NS {new_ns_domain}...")
                  ns_response = resolve_iterative(new_ns_domain) # Find glue
                  if ns_response and ns_response.answer:
                       current_servers = [rec[0].to_text() for rec in ns_response.answer if rec.rdtype == dns.rdatatype.A]
                       if not current_servers: log_message(f"ERROR: Could not resolve NS {new_ns_domain} to A."); return None
                       step_name = "TLD" if step_name == "Root" else "Authoritative"; log_message(f"Referral: Resolved NS IPs: {current_servers}")
                  else: log_message(f"ERROR: Could not resolve NS {new_ns_domain}."); return None
        else:
             # (Check for NXDOMAIN SOA - same as before)
             if response.authority and response.authority[0].rdtype == dns.rdatatype.SOA:
                  log_message("Response: NXDOMAIN."); total_time = (time.time() - total_start_time) * 1000
                  log_message(f"Total Time (NXDOMAIN): {total_time:.2f} ms"); log_message(f"--- Query End ---")
                  TOTAL_QUERIES_RESOLVED += 1; return response # Return SOA
             else: log_message("ERROR: Unhandled response."); return None
    log_message("ERROR: Failed after 10 iterations."); return None


def main():
    """Main DNS server loop for ITERATIVE resolution WITH CACHING."""
    global LOG_FILE # Allow modification of the global LOG_FILE name
    LOG_FILE = "caching_resolver.log" # <--- IMPORTANT: Use a new log file for Task F

    # (The socket creation and bind code remains the same)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND_IP, BIND_PORT))
    except PermissionError:
        log_message(f"FATAL: Permission denied. Did you forget 'sudo'?")
        sys.exit(1)
    except OSError as e:
        log_message(f"FATAL: Could not bind to {BIND_IP}:{BIND_PORT}. {e}")
        sys.exit(1)

    # <--- IMPORTANT: Updated startup message for clarity
    log_message(f"CACHING ITERATIVE DNS resolver (Task F) listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        try:
            # (The rest of the while loop remains the same)
            data, addr = sock.recvfrom(512)
            query_message = dns.message.from_wire(data)
            domain = query_message.question[0].name.to_text()

            # This correctly calls the iterative function (which now has caching)
            response_message = resolve_iterative(domain)
            
            if response_message:
                response_message.id = query_message.id
                sock.sendto(response_message.to_wire(), addr)
            else:
                log_message(f"Sending SERVFAIL for {domain} (Caching/Iterative failure)")
                fail_response = dns.message.make_response(query_message)
                fail_response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(fail_response.to_wire(), addr)

        except Exception as e:
            log_message(f"SERVER ERROR: An error occurred: {e}")


if __name__ == "__main__":
    # Add 'import os' at the top of your script if it's not already there
    LOG_FILE = "caching_resolver.log" # <--- Ensure correct log file is cleared
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
    main()
