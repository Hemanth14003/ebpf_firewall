#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/filter.h>
#include <linux/socket.h>
#include <bpf/bpf_helpers.h>


struct{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10000);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    } blocked_ips SEC(".maps");


SEC("tc/ingress")


int block_incoming_ips(struct __sk_buff *skb) {
    void *data = (void *)(long)(skb->data);  // Get a pointer to the packet data
    void *data_end = (void *)(long)(skb->data_end);

    if (data > data_end) {
        return TC_ACT_SHOT;  // Drop the packet if out of bounds
    }

    struct ethhdr *eth = data;  // Pointer to the Ethernet header

    // Check if the Ethernet header is within bounds
    if (data + sizeof(struct ethhdr) > data_end) {
        return TC_ACT_SHOT;  // Drop the packet if out of bounds
    }

    struct iphdr *ip = data + sizeof(struct ethhdr);


    // Check if the IP header is within bounds
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return TC_ACT_SHOT;
    }  // Pointer to the Ethernet header


    __u32 src_ip = ip->saddr;

    if (bpf_map_lookup_elem(&blocked_ips, &src_ip)){
        return TC_ACT_SHOT;
    }

    src_ip = ntohl(src_ip);
    __u32 subnet_mask_24 = 0xFFFFFF00;  // Example subnet mask (adjust as needed)
    __u32 subnet_24 = src_ip & subnet_mask_24;

    if (bpf_map_lookup_elem(&blocked_ips, &subnet_24)) {
        return TC_ACT_SHOT;  // Allow the packet
    }
    __u32 subnet_mask_16 = 0xFFFF0000;
    __u32 subnet_16 = src_ip & subnet_mask_16;

    if (bpf_map_lookup_elem(&blocked_ips, &subnet_16)) {
        return TC_ACT_SHOT;  // Allow the packet
    }
    __u32 subnet_mask_8 = 0xFF000000;
    __u32 subnet_8 = src_ip & subnet_mask_8;

    if (bpf_map_lookup_elem(&blocked_ips, &subnet_8)) {
        return TC_ACT_SHOT;  // Allow the packet
    }

    return TC_ACT_OK;

}

