# CN_A2
# CS331: Computer Networks Assignment 2 - DNS Query Resolution


## [cite_start]Task A: Network Simulation and Connectivity (20 Points) [cite: 11]

**Objective:** Simulate the provided network topology in Mininet and verify connectivity among all nodes.

**Implementation:**
* [cite_start]A Python script (`topology.py`) was created using the Mininet API to define hosts (H1-H4, DNS Resolver `10.0.0.5`) [cite: 12-22, 31][cite_start], switches (S1-S4) [cite: 23, 25, 27, 29][cite_start], and links with specified bandwidths and delays (e.g., 100Mbps, 1ms-10ms) [cite: 16, 17, 19, 22, 24, 26, 28, 30] using `TCLink`.
* A NAT node was added to `topology.py` to provide internet access for later tasks.

**Verification:**
* The `topology.py` script was executed using `sudo python3`.
* Inside the Mininet CLI (`mininet>`), the `pingall` command was run.

**Result:**
* The `pingall` command showed **0% packet loss (30/30 received)**, confirming successful connectivity between all nodes, including the NAT gateway.
* *(Refer to report screenshot for Task A verification)*.

---

## [cite_start]Task B: Baseline DNS Performance (Default Resolver) (10 Points) [cite: 33]

**Objective:** Measure baseline DNS performance (latency, throughput, success/fail counts) using the default system resolver (simulated by querying `8.8.8.8`).

**Implementation:**
* Unique domain names were extracted from provided PCAP files (e.g., `PCAP_1_H1.pcap`) using `tshark` and saved to `h*_domains.txt` files.
* The Mininet simulation (with NAT) was started.
* A `bash` loop was executed on each host (H1-H4) to query every domain in its list using `dig @8.8.8.8 $domain`.
* Results were saved to `h*_default_results.txt`.
* After exiting Mininet, `grep` and `awk` commands were used to parse these files and calculate statistics.

**Result:** The following baseline performance was recorded:

| Host | Avg Latency (ms) | Success | Fail | Throughput (q/s) |
| :--- | :--------------- | :------ | :--- | :--------------- |
| H1   | 186.52           | 76      | 24   | 5.36             |
| H2   | 209.2            | 72      | 28   | 4.78             |
| H3   | 180.08           | 72      | 28   | 5.55             |
| H4   | 218.08           | 77      | 23   | 4.59             |

---

## [cite_start]Task C: Configure Custom DNS Resolver (10 Points) [cite: 35]

**Objective:** Modify host configurations to use a custom DNS resolver (`10.0.0.5`) instead of the default.

**Implementation:**
* An iterative DNS server script (`custom_resolver.py` or `iterative_resolver.py`) was created using Python, `socket`, and `dnspython`.
* Mininet was started.
* The custom server script was launched on the `dns` host (10.0.0.5) using `sudo python3 ...`.
* On each host (H1-H4), the `/etc/resolv.conf` file was overwritten using `hX sh -c 'echo "nameserver 10.0.0.5" > /etc/resolv.conf'`.

**Verification:**
* A test query (`h1 dig google.com`) was executed from host H1.
* The output confirmed the query was successful (`status: NOERROR`) and was answered by the custom server (`SERVER: 10.0.0.5#53`).

**Result:**
* Hosts were successfully configured to use the custom resolver.
* *(Refer to report screenshot for Task C verification)*.

---

## [cite_start]Task D: Custom Resolver Performance and Analysis (60 Points) [cite: 37]

[cite_start]**Objective:** Measure the performance of the custom iterative resolver, log detailed steps [cite: 38-49][cite_start], compare with Task B, and visualize results for H1[cite: 50].

**Implementation:**
* Using the setup from Task C (Mininet running, custom iterative server running on `dns`, hosts configured), the `dig` loops were re-run for H1-H4.
* This time, `dig $domain` (without `@8.8.8.8`) automatically queried `10.0.0.5`.
* Results were saved to `h*_custom_results.txt`.
* [cite_start]The server automatically logged detailed steps (Timestamp, Domain, Mode, Server IP, Step, RTT, Total Time, Cache Status) to `iterative_resolver.log` (or `custom_resolver.log`) [cite: 39-49].
* After exiting, `grep`/`awk` were used on `h*_custom_results.txt` for statistics.
* A Python script (`extract_plot_data_clean.py`) parsed `iterative_resolver.log` to get data for the first 10 H1 URLs.
* Another Python script (`create_plots.py`) generated the plots using `matplotlib`.

**Results:**

1.  **Statistics:**

    | Host | Avg Latency (ms) | Success | Fail | Throughput (q/s) |
    | :--- | :--------------- | :------ | :--- | :--------------- |
    | H1   | 783.36           | 69      | 31   | 1.28             |
    | H2   | 743.0            | 65      | 35   | 1.35             |
    | H3   | 763.4            | 71      | 29   | 1.31             |
    | H4   | 854.4            | 72      | 28   | 1.17             |

2.  **Comparison Table:**

    | Host | Default Latency (ms) | **Custom Latency (ms)** | Default Throughput (q/s) | **Custom Throughput (q/s)** |
    | :--- | :------------------- | :---------------------- | :----------------------- | :-------------------------- |
    | H1   | 186.52               | **783.36** | 5.36                     | **1.28** |
    | H2   | 209.2                | **743.0** | 4.78                     | **1.35** |
    | H3   | 180.08               | **763.4** | 5.55                     | **1.31** |
    | H4   | 218.08               | **854.4** | 4.59                     | **1.17** |

3.  **Analysis:** The custom iterative resolver was significantly slower (~3.6-4.6x higher latency, ~3.5-4.5x lower throughput) due to performing full iterative lookups without caching, unlike the optimized default resolver.

4.  **Logs:** The detailed logs were successfully generated in `iterative_resolver.log`. *(Refer to report screenshot for Task D log snippet)*.

5.  **Plots:** Two plots (`Plot_1_H1_Latency.png`, `Plot_2_H1_Servers.png`) were generated showing latency and servers visited for the first 10 H1 URLs. *(Refer to report for plot images)*.

---

## [cite_start]Bonus Task E: Recursive Resolution (2.5 Points) [cite: 53]

**Objective:** Implement and test a recursive resolution mode in the custom resolver by forwarding queries.

**Implementation:**
* A separate script (`recursive_resolver.py`) was created.
* The `resolve_recursive` function forwarded queries to an external resolver (`8.8.8.8`).
* The `main` function was modified to call this function.
* The experiment was run similarly to Task D, saving results to `h*_recursive_results.txt`.

**Result:** Performance was much faster than iterative mode and similar to Task B, as expected. Cache hit rate was 0%.

| Host | Avg Latency (ms) | Success | Fail | Throughput (q/s) | % Cache |
| :--- | :--------------- | :------ | :--- | :--------------- | :------ |
| H1   | 174.32           | 76      | 24   | 5.74             | 0.00 %  |
| H2   | 114.32           | 73      | 27   | 8.75             | 0.00 %  |
| H3   | 175.48           | 72      | 28   | 5.70             | 0.00 %  |
| H4   | 222.52           | 77      | 23   | 4.49             | 0.00 %  |

---

## [cite_start]Bonus Task F: Caching Implementation (2.5 Points) [cite: 58]

**Objective:** Implement caching in the custom iterative resolver to improve performance.

**Implementation:**
* A separate script (`caching_resolver.py`) was created by copying the iterative script.
* A dictionary (`DNS_CACHE`) was added to store `(ip, expiration_time)` tuples.
* The `resolve_iterative` function was modified to:
    * Check the cache before performing lookups.
    * Return cached results if valid (HIT).
    * Store new results (A-records with their TTL) in the cache after a MISS.
* The experiment was run, saving results to `h*_caching_results.txt`.
* Cache hit percentage was calculated from `caching_resolver.log`.

**Result:** Caching was functional but yielded a low hit rate (1.93%) for this workload, resulting in minimal performance improvement over the non-caching iterative server.

| Host | Avg Latency (ms) | Success | Fail | Throughput (q/s) | % Cache |
| :--- | :--------------- | :------ | :--- | :--------------- | :------ |
| H1   | 709.72           | 73      | 27   | 1.41             | 1.93 %  |
| H2   | 748.40           | 70      | 29   | 1.34             | 1.93 %  |
| H3   | 711.72           | 71      | 29   | 1.41             | 1.93 %  |
| H4   | 764.44           | 76      | 24   | 1.31             | 1.93 %  |

---

## Project Files

* `topology.py`: Mininet script to create the network topology.
* `iterative_resolver.py`: Custom iterative DNS server (Task D).
* `recursive_resolver.py`: Custom recursive (forwarding) DNS server (Task E).
* `caching_resolver.py`: Custom iterative DNS server with caching (Task F).
* `h*_domains.txt`: Extracted unique domain lists.
* `h*_default_results.txt`: Raw `dig` output from Task B.
* `h*_custom_results.txt`: Raw `dig` output from Task D (Iterative).
* `h*_recursive_results.txt`: Raw `dig` output from Task E (Recursive).
* `h*_caching_results.txt`: Raw `dig` output from Task F (Caching).
* `iterative_resolver.log`: Detailed logs from Task D server.
* `recursive_resolver.log`: Detailed logs from Task E server.
* `caching_resolver.log`: Detailed logs from Task F server.
* `extract_plot_data_clean.py`: Script to extract data for Task D plots.
* `create_plots.py`: Script to generate Task D plots.
* `Plot_*.png`: Generated plot images for Task D.

---

## How to Run

1.  Ensure Mininet and `python3-dnspython`, `python3-matplotlib` are installed (`sudo apt install mininet python3-dnspython python3-matplotlib`).
2.  Clone the repository.
3.  Navigate to the project directory.
4.  To run Task D (Iterative):
    * Start Mininet: `sudo PYTHONPATH=/path/to/mininet python3 topology.py`
    * Inside Mininet, start server: `dns sudo PYTHONPATH=/usr/lib/python3/dist-packages python3 /full/path/to/iterative_resolver.py > dns.log 2>&1 &`
    * Configure hosts: `hX sh -c 'echo "nameserver 10.0.0.5" > /etc/resolv.conf'`
    * Run loops: `hX rm ... dig $domain >> /full/path/to/hX_custom_results.txt ...`
    * Stop server and exit.
    * Run analysis: `grep ... hX_custom_results.txt ...`
    * Check log: `cat iterative_resolver.log`
    * Generate plots: `python3 create_plots.py` (uses `iterative_resolver.log`)
5.  (Similar steps for Task E using `recursive_resolver.py` and Task F using `caching_resolver.py`, adjusting filenames).
