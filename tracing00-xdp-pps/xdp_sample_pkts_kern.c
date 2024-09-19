// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

#define SAMPLE_SIZE 1024ul
#define MAX_CPUS 128

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define min(x, y) ((x) < (y) ? (x) : (y))

/* Metadata will be in the perf event before the packet data. */
struct S {
	__u16 cookie;
	__u16 pkt_len;
} __packed;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__type(key, int);
	__type(value, __u32);
	__uint(max_entries, MAX_CPUS);
} my_map SEC(".maps");

SEC("xdp")
int xdp_sample_prog(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct hdr_cursor nh = {.pos = data};
	struct ethhdr *eth;
	int eth_type;
	int ip_type;
	struct iphdr *iphdr;
	__u32 action = XDP_DROP;

	/* Parse Ethernet and IP/IPv6 headers */
	eth_type = parse_ethhdr(&nh, data_end, &eth);
	if (eth_type == bpf_htons(ETH_P_ARP)) 
		action = XDP_PASS;
	else if (eth_type == bpf_htons(ETH_P_IP)) {
		ip_type = parse_iphdr(&nh, data_end, &iphdr);
		if (ip_type == IPPROTO_ICMP)
			action = XDP_PASS;
	}

	/* Just send ICMP/ARP to usespace application */
	if (action == XDP_PASS) {
		__u64 flags = BPF_F_CURRENT_CPU;
		__u16 sample_size = (__u16)(data_end - data);
		int ret;
		struct S metadata;

		metadata.cookie = 0xdead;
		metadata.pkt_len = min(sample_size, SAMPLE_SIZE);

		flags |= (__u64)sample_size << 32;

		ret = bpf_perf_event_output(ctx, &my_map, flags,
					    &metadata, sizeof(metadata));
		if (ret)
			bpf_printk("perf_event_output failed: %d\n", ret);
	}

	return action;
}

char _license[] SEC("license") = "GPL";
