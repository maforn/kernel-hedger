import socket
import time
import struct
import statistics
import matplotlib.pyplot as plt
import numpy as np
import sys
import csv

# CONFIGURATION
SERVER_IP = "127.0.0.1"
PORT_BASELINE = 9997 
PORT_APP      = 9998
PORT_KERNEL   = 9999

N_REQUESTS = 5000
WARMUP     = 200
MAX_TIME   = 1.0
HEDGE_WAIT = 0.010 # 10ms

def print_progress(current, total, label):
    percent = (current / total) * 100
    sys.stdout.write(f"\r[*] {label}: {percent:.1f}% ({current}/{total})")
    sys.stdout.flush()
    if current == total: print("")

def run_client(mode, port, id_offset):
    print(f"--- Running {mode.upper()} (Port {port}) ---")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    latencies = []
    total_runs = N_REQUESTS + WARMUP
    
    for i in range(total_runs):
        req_id = i + id_offset
        packet = struct.pack('I', req_id)
        start = time.time()
        
        success = False
        
        # --- APP HEDGING LOGIC ---
        if mode == "app":
            sock.settimeout(HEDGE_WAIT) # 10ms
            sock.sendto(packet, (SERVER_IP, port))
            
            try:
                while True:
                    data, _ = sock.recvfrom(1024)
                    if len(data) < 4: continue
                    resp_id = struct.unpack('I', data[0:4])[0]
                    if resp_id == req_id:
                        success = True
                        break
            except socket.timeout:
                # timeout -> hedge
                sock.sendto(packet, (SERVER_IP, port))
                sock.settimeout(MAX_TIME)
                try:
                    while True:
                        data, _ = sock.recvfrom(1024)
                        if len(data) < 4: continue
                        resp_id = struct.unpack('I', data[0:4])[0]
                        if resp_id == req_id:
                            success = True
                            break
                except socket.timeout:
                    pass

        # --- KERNEL / BASELINE LOGIC ---
        else:
            sock.settimeout(MAX_TIME)
            sock.sendto(packet, (SERVER_IP, port))
            try:
                while True:
                    data, _ = sock.recvfrom(1024)
                    if len(data) < 4: continue
                    resp_id = struct.unpack('I', data[0:4])[0]
                    if resp_id == req_id:
                        success = True
                        break
            except socket.timeout:
                pass

        end = time.time()
        
        if i >= WARMUP:
            if success:
                latencies.append((end - start) * 1000)
            else:
                latencies.append(MAX_TIME * 1000)
        
        # drain ghosts
        try:
            sock.setblocking(0)
            while True: sock.recvfrom(1024)
        except BlockingIOError: pass
        
        time.sleep(0.001)
        print_progress(i + 1, total_runs, mode)
        
    return latencies

def save_raw_data(results_map, filename="thesis_latencies.csv"):
    print(f"\n[*] Saving raw data to {filename}...")
    
    # get keys sorted for consistent column order
    headers = sorted(results_map.keys())
    
    # organize data into rows
    max_len = max(len(v) for v in results_map.values())
    
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(headers)
        
        for i in range(max_len):
            row = []
            for key in headers:
                if i < len(results_map[key]):
                    row.append(f"{results_map[key][i]:.4f}")
                else:
                    row.append("")
            writer.writerow(row)
            
    print(f"    -> Data saved successfully.")

def plot_graph(results_map, filename, title, x_limit=None):
    print(f"[*] Plotting {filename}...")
    plt.figure(figsize=(10, 6))
    
    colors = {'Baseline': 'red', 'App-Hedged': 'blue', 'Kernel-Hedged': 'green'}
    styles = {'Baseline': ':', 'App-Hedged': '--', 'Kernel-Hedged': '-'}
    
    sorted_keys = sorted(results_map.keys())
    
    for label in sorted_keys:
        data = np.sort(results_map[label])
        yvals = np.arange(len(data)) / float(len(data))
        
        plt.plot(data, yvals, label=label, color=colors[label], linestyle=styles[label], linewidth=2)

    plt.xscale('log')
    plt.xlabel('Latency (ms) [Log Scale]')
    plt.ylabel('CDF')
    plt.title(f'{title} (N={N_REQUESTS})')
    plt.grid(True, which="both", alpha=0.5)
    plt.legend()
    
    plt.axvline(x=10, color='gray', linestyle='--', alpha=0.5, label='Hedge Timer (10ms)')
    
    if x_limit:
        plt.xlim(right=x_limit)
        
    plt.savefig(filename)
    print(f"    -> Saved {filename}")

if __name__ == "__main__":
    results = {}
    
    results['Baseline'] = run_client("baseline", PORT_BASELINE, 0)
    results['App-Hedged'] = run_client("app", PORT_APP, 1000000)
    results['Kernel-Hedged'] = run_client("kernel", PORT_KERNEL, 2000000)
    
    save_raw_data(results)

    print("\n" + "="*65)
    print(f"{'METHOD':<15} | {'P50 (ms)':<10} | {'P95 (ms)':<10} | {'P99 (ms)':<10} | {'MAX (ms)':<10}")
    print("-" * 65)
    for label, data in results.items():
        data = np.sort(data)
        p50 = np.percentile(data, 50)
        p95 = np.percentile(data, 95)
        p99 = np.percentile(data, 99)
        mx  = np.max(data)
        print(f"{label:<15} | {p50:<10.2f} | {p95:<10.2f} | {p99:<10.2f} | {mx:<10.2f}")
    print("="*65)

    plot_graph(results, "../plots/thesis_full.png", "Tail Latency Reduction (Full View)")
    
    zoomed_results = {
        'App-Hedged': results['App-Hedged'],
        'Kernel-Hedged': results['Kernel-Hedged']
    }
    plot_graph(zoomed_results, "../plots/thesis_zoomed.png", "App vs Kernel Hedging (Zoomed)", x_limit=50)
