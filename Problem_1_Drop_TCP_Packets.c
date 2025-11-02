// Problem_1_Drop_TCP_Packets.c
// Author: Chukkaluru Sushma
// Candidate ID: Naukri1025
// Email: sushmareddychukkaluru@gmail.com
//
// Description:
// XDP eBPF program to drop TCP packets whose source or destination port matches DROP_PORT (default 4040).
// The DROP_PORT is declared as a volatile const so it can be patched or updated from userspace (bonus).
//
// Compile (native Linux):
//   clang -O2 -target bpf -c Problem_1_Drop_TCP_Packets.c -o drop_tcp.o
// Attach (example):
//   sudo ip link set dev eth0 xdp obj drop_tcp.o sec xdp
// Detach:
//   sudo ip link set dev eth0 xdp off

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

// Default port (can be updated via userspace map in more advanced version)
static volatile const __u16 DROP_PORT = 4040;

SEC("xdp")
int xdp_drop_tcp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Ensure Ethernet header is readable
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    // Only handle IPv4
    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only TCP
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    // Drop if source or dest port matches DROP_PORT
    if (tcp->dest == __constant_htons(DROP_PORT) || tcp->source == __constant_htons(DROP_PORT)) {
        bpf_printk("[drop_tcp] dropped packet on port %d\n", DROP_PORT);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
