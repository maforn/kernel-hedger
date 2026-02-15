#!/usr/bin/python3
from bcc import BPF
from pyroute2 import IPRoute
import time
import os
import sys

# --- 1. NETWORK SETUP ---
def setup_network():
    print("[*] Setting up Network (Stable Mode)...")
    
    os.system("ip link del veth_hedge 2>/dev/null")

    # setup Shadow Interface
    os.system("ip link add veth_hedge type veth peer name veth_dumm")
    os.system("ip link set veth_hedge up")
    os.system("ip link set veth_dumm up")
    os.system("ip link set veth_hedge promisc on")
    os.system("ip link set veth_dumm promisc on")
    
    # 10ms Delay
    os.system("tc qdisc add dev veth_dumm root netem delay 10ms")
    
    # prevents the OS from generating "Partial" checksums that break during injection
    print("[*] Disabling Loopback Checksum Offloading...")
    os.system("ethtool -K lo tx off rx off > /dev/null 2>&1")
    os.system("ethtool -K veth_hedge tx off rx off > /dev/null 2>&1")
    os.system("ethtool -K veth_dumm tx off rx off > /dev/null 2>&1")
    
    # allow 127.0.0.1 packets on "foreign" interfaces
    os.system("sysctl -w net.ipv4.conf.all.accept_local=1 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.veth_hedge.accept_local=1 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.lo.accept_local=1 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.all.route_localnet=1 > /dev/null")
    
    # disable spoof checking
    os.system("sysctl -w net.ipv4.conf.all.rp_filter=0 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.default.rp_filter=0 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.veth_hedge.rp_filter=0 > /dev/null")
    os.system("sysctl -w net.ipv4.conf.lo.rp_filter=0 > /dev/null")

def cleanup_network():
    print("\n[*] Cleaning up...")
    os.system("ip link del veth_hedge 2>/dev/null")
    # re-enable optimizations
    os.system("ethtool -K lo tx on rx on > /dev/null 2>&1")

# --- 2. KERNEL C CODE ---
bpf_code = """
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/pkt_cls.h>

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2
#define TC_ACT_REDIRECT 7
#define TARGET_PORT 9999

BPF_HASH(scoreboard, u32, u64);

struct packet_meta {
    u16 dest_port;
    u16 src_port;
    u32 payload_offset;
    bool is_udp;
};

static inline int parse_packet(struct __sk_buff *skb, struct packet_meta *meta) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end) return -1;
    struct iphdr *ip = (void*)(eth + 1);
    if ((void*)(ip + 1) > data_end) return -1;
    if (ip->protocol != 17) { meta->is_udp = false; return 0; }
    meta->is_udp = true;
    u32 ip_len = ip->ihl * 4;
    u32 udp_offset = 14 + ip_len;
    struct udphdr udp;
    if (bpf_skb_load_bytes(skb, udp_offset, &udp, sizeof(udp)) < 0) return -1;
    meta->src_port = bpf_ntohs(udp.source);
    meta->dest_port = bpf_ntohs(udp.dest);
    meta->payload_offset = udp_offset + sizeof(udp);
    return 0;
}

// EGRESS: Splitter
int handle_egress(struct __sk_buff *skb) {
    if (skb->mark == 42) return TC_ACT_OK;
    struct packet_meta meta = {};
    if (parse_packet(skb, &meta) < 0) return TC_ACT_OK;
    if (!meta.is_udp || meta.dest_port != TARGET_PORT) return TC_ACT_OK;

    u32 req_id = 0;
    if (bpf_skb_load_bytes(skb, meta.payload_offset, &req_id, 4) < 0) return TC_ACT_OK;
    u64 status = 0;
    scoreboard.update(&req_id, &status);

    bpf_clone_redirect(skb, IFINDEX_SHADOW, 0); 
    return TC_ACT_OK;
}

// SHADOW: Rescuer
int handle_shadow(struct __sk_buff *skb) {
    struct packet_meta meta = {};
    if (parse_packet(skb, &meta) < 0) return TC_ACT_OK;
    if (meta.dest_port != TARGET_PORT) return TC_ACT_SHOT;

    u32 req_id = 0;
    if (bpf_skb_load_bytes(skb, meta.payload_offset, &req_id, 4) < 0) return TC_ACT_SHOT;

    u64 *val = scoreboard.lookup(&req_id);
    if (val && *val == 1) return TC_ACT_SHOT; 

    bpf_trace_printk("RESCUE: Req %d -> Injecting to LO\\n", req_id);
    skb->mark = 42; 

    // MAC to zero
    u8 zeros[12] = {0}; 
    bpf_skb_store_bytes(skb, 0, &zeros, 12, 0);

    // disable UDP checksum (ignore validation)
    u16 zero_csum = 0;
    bpf_skb_store_bytes(skb, 34 + 6, &zero_csum, 2, 0);

    // redirect to LO ingress
    bpf_redirect(IFINDEX_REAL, 1);
    
    return TC_ACT_REDIRECT;
}

// ACK Listener
int handle_ack(struct __sk_buff *skb) {
    struct packet_meta meta = {};
    if (parse_packet(skb, &meta) < 0) return TC_ACT_OK;
    if (!meta.is_udp || meta.src_port != TARGET_PORT) return TC_ACT_OK;
    u32 req_id = 0;
    if (bpf_skb_load_bytes(skb, meta.payload_offset, &req_id, 4) < 0) return TC_ACT_OK;
    u64 status = 1;
    scoreboard.update(&req_id, &status);
    return TC_ACT_OK;
}
"""

try:
    setup_network()
    ip = IPRoute()
    idx_lo = ip.link_lookup(ifname="lo")[0]
    idx_shadow = ip.link_lookup(ifname="veth_dumm")[0]
    idx_hedge = ip.link_lookup(ifname="veth_hedge")[0]
    
    bpf_code = bpf_code.replace("IFINDEX_SHADOW", str(idx_shadow))
    bpf_code = bpf_code.replace("IFINDEX_REAL", str(idx_lo))

    b = BPF(text=bpf_code)
    
    fn_egress = b.load_func("handle_egress", BPF.SCHED_CLS)
    fn_shadow = b.load_func("handle_shadow", BPF.SCHED_CLS)
    fn_ack    = b.load_func("handle_ack", BPF.SCHED_CLS)

    try: ip.tc("del", "clsact", idx_lo); 
    except: pass
    try: ip.tc("del", "clsact", idx_hedge); 
    except: pass
    
    ip.tc("add", "clsact", idx_lo)
    ip.tc("add-filter", "bpf", idx_lo, ":1", fd=fn_egress.fd, name=fn_egress.name, parent="ffff:fff3", classid=1, direct_action=True)
    ip.tc("add-filter", "bpf", idx_lo, ":1", fd=fn_ack.fd, name=fn_ack.name, parent="ffff:fff2", classid=1, direct_action=True)
    ip.tc("add", "clsact", idx_hedge)
    ip.tc("add-filter", "bpf", idx_hedge, ":1", fd=fn_shadow.fd, name=fn_shadow.name, parent="ffff:fff2", classid=1, direct_action=True)

    print("="*40)
    print("[*] eBPF HEDGER: STABLE MODE")
    print("[*] (Permissive + Ethtool Fix)")
    print("="*40)
    
    with open("/sys/kernel/debug/tracing/trace_pipe", "r") as t:
        while True:
            line = t.readline()
            if "RESCUE" in line: print(line.strip())

except KeyboardInterrupt:
    pass
finally:
    cleanup_network()
