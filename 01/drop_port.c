#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") port_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u16),
    .max_entries = 1,
};
SEC("xdp")
int xdp_drop_tcp_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    struct iphdr *ip;
    struct tcphdr *tcp;
    __u16 *port;
    __u32 key = 0;

    bpf_printk("XDP program started\n");

    if ((void *)(eth + 1) > data_end) {
        bpf_printk("XDP_PASS: Ethernet header check failed\n");
        return XDP_PASS;
    }

    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("XDP_PASS: Not an IP packet\n");
        return XDP_PASS;
    }

    ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        bpf_printk("XDP_PASS: IP header check failed\n");
        return XDP_PASS;
    }

    if (ip->protocol != IPPROTO_TCP) {
        bpf_printk("XDP_PASS: Not a TCP packet\n");
        return XDP_PASS;
    }

    tcp = (void *)ip + sizeof(*ip);
    if ((void *)(tcp + 1) > data_end) {
        bpf_printk("XDP_PASS: TCP header check failed\n");
        return XDP_PASS;
    }

    port = bpf_map_lookup_elem(&port_map, &key);
    if (!port) {
        bpf_printk("XDP_PASS: Port map lookup failed\n");
        return XDP_PASS;
    }

    if (tcp->dest == __constant_htons(*port)) {
        bpf_printk("XDP_DROP: Dropping packet on port: %d\n", *port);
        return XDP_DROP;
    }

    bpf_printk("XDP_PASS: Packet passed\n");
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
