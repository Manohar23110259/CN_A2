#!/usr/bin/python3
import os
import re
import sys
import matplotlib.pyplot as plt
import numpy as np

# The 10 target domains for H1 plots (First 10 URLs)
TARGET_DOMAINS = [
    "2brightsparks.co.uk",
    "41latitude.com",
    "7dfps.com",
    "advertos.ru",
    "afairjudgement.com",
    "afresnohomeinspector.com",
    "alchemedialtd.com",
    "alenpuaca.com",
    "amorefieldlife.com",
    "aqvr.com"
]

def extract_plot_data(log_file):
    """
    Reads the clean log file and extracts metrics for the 10 target domains.
    """
    try:
        with open(log_file, 'r') as f:
            log_content = f.read()
    except FileNotFoundError:
        print(f"Error: Log file not found at {log_file}")
        sys.exit(1)

    data = {}
    
    # Define regex patterns
    query_block_re = re.compile(r"--- New Query ---.*?--- Query End ---", re.DOTALL)
    domain_re = re.compile(r"Domain Name: (\S+)")
    latency_re = re.compile(r"Total Time: (\d+\.\d+) ms")
    server_re = re.compile(r"Contacting Server:")

    print("Extracting data for the first 10 unique H1 queries...")

    # Iterate through all query blocks found in the log
    for block in query_block_re.finditer(log_content):
        block_content = block.group(0)
        
        # 1. Find the Domain Name in this block
        match_domain = domain_re.search(block_content)
        if not match_domain:
            continue

        domain_name = match_domain.group(1).rstrip('.')
        
        # 2. Check if this is one of the 10 target domains
        if domain_name in TARGET_DOMAINS and domain_name not in data:
            
            # 3. Extract Latency
            match_latency = latency_re.search(block_content)
            latency = float(match_latency.group(1)) if match_latency else 0.0

            # 4. Count Servers Visited
            servers_visited = len(server_re.findall(block_content))
            
            # Store data
            data[domain_name] = {
                "latency": latency,
                "servers": servers_visited,
            }

        # Stop once all 10 are found
        if len(data) == len(TARGET_DOMAINS):
            break

    return data

def generate_plots(extracted_data):
    """Generates the two required plots from the extracted data."""
    
    # Prepare data arrays, ensuring order matches TARGET_DOMAINS
    domains = []
    latencies = []
    server_counts = []

    for domain in TARGET_DOMAINS:
        if domain in extracted_data:
            domains.append(domain.replace(".com", "").replace(".co.uk", "")) # Shorten names for readability
            latencies.append(extracted_data[domain]['latency'])
            server_counts.append(extracted_data[domain]['servers'])
        else:
            # Handle cases where resolution failed or wasn't logged
            domains.append(domain.replace(".com", "").replace(".co.uk", ""))
            latencies.append(0)
            server_counts.append(0)
            print(f"Warning: Data not found for {domain}. Plotting 0.")


    # --- Plot 1: Total Latency per Query ---
    plt.figure(figsize=(12, 6))
    plt.bar(domains, latencies, color='skyblue')
    plt.xlabel("Domain Name (First 10 H1 URLs)")
    plt.ylabel("Total Time to Resolution (ms)")
    plt.title("Plot 1: Custom Resolver Latency Per Query (H1)")
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--')
    plt.tight_layout()
    plt.savefig("Plot_1_H1_Latency.png")
    print("\n✅ Plot 1 saved as Plot_1_H1_Latency.png")
    # plt.show() # Uncomment this line to display the plot immediately

    # --- Plot 2: Total Servers Visited per Query ---
    plt.figure(figsize=(12, 6))
    plt.bar(domains, server_counts, color='lightcoral')
    plt.xlabel("Domain Name (First 10 H1 URLs)")
    plt.ylabel("Total DNS Servers Visited")
    plt.title("Plot 2: Custom Resolver Server Count Per Query (H1)")
    plt.xticks(rotation=45, ha='right')
    plt.grid(axis='y', linestyle='--')
    plt.tight_layout()
    plt.savefig("Plot_2_H1_Servers.png")
    print("✅ Plot 2 saved as Plot_2_H1_Servers.png")
    # plt.show() # Uncomment this line to display the plot immediately


if __name__ == "__main__":
    if not os.path.exists("custom_resolver.log"):
        print("Error: custom_resolver.log not found. Please ensure you ran the final H1 test.")
        sys.exit(1)
        
    extracted_data = extract_plot_data("custom_resolver.log")
    
    if len(extracted_data) > 0:
        generate_plots(extracted_data)
    else:
        print("Error: Could not extract any data. Ensure your custom_resolver.log is not empty.")
