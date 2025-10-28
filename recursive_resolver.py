#!/usr/bin/python3
# SCRIPT FOR BONUS TASK E (RECURSIVE RESOLUTION)

import socket
import time
import sys
import os
from datetime import datetime
import dns.message
import dns.query
import dns.rdatatype

# --- Configuration ---
LOG_FILE = "recursive_resolver.log"
BIND_IP = "10.0.0.5"
BIND_PORT = 53
FORWARDER_IP = "8.8.8.8" # Forward queries to Google DNS

def log_message(msg):
    """Logs a message to the console and the Task E log file."""
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    log_entry = f"[{now}] {msg}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def send_query(query_message, server_ip, timeout=5.0):
    """Sends a DNS query to a specific server IP."""
    start_time = time.time()
    try:
        response = dns.query.udp(query_message, server_ip, timeout=timeout)
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        return response, rtt
    except Exception as e:
        end_time = time.time()
        rtt = (end_time - start_time) * 1000
        log_message(f"  ERROR: Query to {server_ip} failed: {e}")
        return None, rtt

def resolve_recursive(domain_name, query_message):
    """Performs RECURSIVE resolution by forwarding."""
    log_message(f"--- New Query (Recursive Request) ---")
    log_message(f"Timestamp: {datetime.now()}")
    log_message(f"Domain Name: {domain_name}")
    log_message(f"Resolution Mode: Recursive (Forwarding to {FORWARDER_IP})")

    total_start_time = time.time()
    response, rtt = send_query(query_message, FORWARDER_IP)

    if response:
        log_message(f"Received response from {FORWARDER_IP}")
        log_message(f"RTT to forwarder: {rtt:.2f} ms")
    else:
        log_message(f"No response from forwarder {FORWARDER_IP}")

    total_time = (time.time() - total_start_time) * 1000
    log_message(f"Total Time (Recursive): {total_time:.2f} ms")
    log_message(f"--- Query End (Recursive) ---")
    return response

def main():
    """Main DNS server loop for RECURSIVE resolution."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind((BIND_IP, BIND_PORT))
    except PermissionError:
        log_message(f"FATAL: Permission denied. Did you forget 'sudo'?")
        sys.exit(1)
    except OSError as e:
        log_message(f"FATAL: Could not bind to {BIND_IP}:{BIND_PORT}. {e}")
        sys.exit(1)

    log_message(f"RECURSIVE DNS resolver (Task E) listening on {BIND_IP}:{BIND_PORT}...")

    while True:
        try:
            data, addr = sock.recvfrom(512)
            query_message = dns.message.from_wire(data)
            domain = query_message.question[0].name.to_text()

            response_message = resolve_recursive(domain, query_message)

            if response_message:
                response_message.id = query_message.id
                sock.sendto(response_message.to_wire(), addr)
            else:
                log_message(f"Sending SERVFAIL for {domain} (Recursive failure)")
                fail_response = dns.message.make_response(query_message)
                fail_response.set_rcode(dns.rcode.SERVFAIL)
                sock.sendto(fail_response.to_wire(), addr)
        except Exception as e:
            log_message(f"SERVER ERROR: An error occurred: {e}")

if __name__ == "__main__":
    if os.path.exists(LOG_FILE):
        open(LOG_FILE, 'w').close()
    main()
