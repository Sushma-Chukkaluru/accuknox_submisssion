// Problem_2_Drop_Process_Packets.c
// Author: Chukkaluru Sushma
// Candidate ID: Naukri1025
// Email: sushmareddychukkaluru@gmail.com
//
// Description:
// cgroup_skb eBPF program that allows traffic for a given process name only on TARGET_PORT (default 4040).
// All other ports for that process are dropped. This program should be attached to the cgroup of the target process.
//
// Compile (native Linux):
//   clang -O2 -target bpf -c Problem_2_Drop_Process_Packets.c -o drop_process.o
// Attach example (requires cgroup v2 and bpftool):
//   sudo bpftool prog load drop_process.o /sys/fs/bpf/drop_process type cgroup_skb
//   sudo bpftool cgroup attach /sys/fs/cgroup/unified/ egress pinned /sys/fs/bpf/drop_process
//
// Then run the target process in that cgroup (cgexec/cgcreate or systemd-run --scope)

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Change TARGET_PROC to the exact process name you want to match (max 15 chars)
#define TARGET_PORT 4040
#define TARGET_PROC "myprocess"

SEC("cgroup_skb/egress")
int filter_process_egress(struct __sk_buff *skb)
{
    // Buffer for the process comm
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    // Quick compare of comm to TARGET_PROC
    int match = 1;
#pragma unroll
    for (int i = 0; i < sizeof(TARGET_PROC) - 1; i++) {
        if (comm[i] != TARGET_PROC[i]) {
            match = 0;
            break;
        }
    }
    if (!match) {
        // Not the target process: allow
        return 1;
    }

    // Parse Ethernet/IP/TCP headers from skb (best-effort)
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return 1;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return 1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return 1;

    if (ip->protocol != IPPROTO_TCP)
        return 1;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return 1;

    // If this packet is NOT to/from the allowed port, drop it for this process
    if (tcp->dest != __constant_htons(TARGET_PORT) && tcp->source != __constant_htons(TARGET_PORT)) {
        bpf_printk("[drop_process] Dropping for proc %s (not on port %d)\n", comm, TARGET_PORT);
        return 0; // drop
    }
    return 1; // allow
}

char _license[] SEC("license") = "GPL";
