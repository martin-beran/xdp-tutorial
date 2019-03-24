/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
        return h_proto == ETH_P_8021Q || h_proto == ETH_P_8021AD;
}

#define VLAN_MAX_DEPTH 4

static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);
	int proto;

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	proto = bpf_ntohs(eth->h_proto);

#pragma unroll
	for (int depth = 0; depth < VLAN_MAX_DEPTH; ++depth) {
		if (!proto_is_vlan(proto))
			break;
		struct vlan_hdr *vlan = nh->pos;
		int vlansize = sizeof(*vlan);
		if (nh->pos + vlansize > data_end)
			return -1;
		proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		nh->pos += vlansize;
	}

	*ethhdr = eth;
	return proto;
}

/* Assignment 2: Implement and use this */
static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ipv6hdr)
{
	struct ipv6hdr *ip6 = nh->pos;
	int hdrsize = sizeof(*ip6);

	if (ip6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*ipv6hdr = ip6;

	return ip6->nexthdr;
}

/* Assignment 3: Implement and use this */
static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;
	int hdrsize = sizeof(*icmp6);

	if (icmp6 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type;
}

static __always_inline int parse_ip4hdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **ipv4hdr)
{
	struct iphdr *ip4 = nh->pos;
	int hdrsize = sizeof(*ip4);

	if (ip4 + 1 > data_end)
		return -1;
	hdrsize = ip4->ihl * 4;
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ipv4hdr = ip4;

	return ip4->protocol;
}

static __always_inline int parse_icmp4hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmp4hdr)
{
	struct icmphdr *icmp4 = nh->pos;
	int hdrsize = sizeof(*icmp4);

	if (icmp4 + 1 > data_end)
		return -1;

	nh->pos += hdrsize;
	*icmp4hdr = icmp4;

	return icmp4->type;
}

SEC("xdp_packet_parser")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
	struct iphdr *ip4;
	struct icmphdr *icmp4;
	struct ipv6hdr *ip6;
	struct icmp6hdr *icmp6;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
	switch (nh_type) {
		case ETH_P_IP:
			nh_type = parse_ip4hdr(&nh, data_end, &ip4);
			if (nh_type != IPPROTO_ICMP)
				goto out;
			nh_type = parse_icmp4hdr(&nh, data_end, &icmp4);
			if (nh_type != ICMP_ECHO)
				goto out;
			if (bpf_ntohs(icmp4->un.echo.sequence) % 2 == 0)
				goto out;
			break;
		case ETH_P_IPV6:
			nh_type = parse_ip6hdr(&nh, data_end, &ip6);
			if (nh_type != IPPROTO_ICMPV6)
				goto out;
			nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
			if (nh_type != ICMPV6_ECHO_REQUEST)
				goto out;
			if (bpf_ntohs(icmp6->icmp6_sequence) % 2 == 0)
				goto out;
			break;
		default:
			goto out;
	}


	action = XDP_DROP;
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
