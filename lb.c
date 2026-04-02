//go:build ignore
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include "parse_helpers.h"

#define NUM_BACKENDS 2 // Hardcoded number of backends
#define ETH_ALEN 6 // Octets in one ethernet addr
#define AF_INET 2 // Instead of including the whole sys/socket.h header
#define IPROTO_TCP 6 // TCP
#define MAX_TCP_CHECK_WORDS 750 // max 1500 bytes to check in TCP checksum. This is MTU dependent

struct endpoint {
  __u32 ip;
};

struct five_tuple_t {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u8  protocol;
};

// Backend IPs
// We could also include port information but we simplify
// and assume that both LB and Backend listen on the same port for requests
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, NUM_BACKENDS);
  __type(key, __u32);
  __type(value, struct endpoint);
} backends SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __uint(max_entries, 1000);
  __type(key, struct five_tuple_t);
  __type(value, struct endpoint);
} conntrack SEC(".maps");

// FNV-1a hash implementation for load balancing
static __always_inline __u32 xdp_hash_tuple(struct five_tuple_t *tuple) {
  __u32 hash = 2166136261U;
  hash = (hash ^ tuple->src_ip) * 16777619U;
  hash = (hash ^ tuple->dst_ip) * 16777619U;
  hash = (hash ^ tuple->src_port) * 16777619U;
  hash = (hash ^ tuple->dst_port) * 16777619U;
  hash = (hash ^ tuple->protocol) * 16777619U;
  return hash;
}

static __always_inline void log_fib_error(int rc) {
  switch (rc) {
  case BPF_FIB_LKUP_RET_BLACKHOLE:
    bpf_printk("FIB lookup failed: BLACKHOLE route. Check 'ip route' – the "
               "destination may have a blackhole rule.");
    break;
  case BPF_FIB_LKUP_RET_UNREACHABLE:
    bpf_printk("FIB lookup failed: UNREACHABLE route. Kernel routing table "
               "explicitly marks this destination unreachable.");
    break;
  case BPF_FIB_LKUP_RET_PROHIBIT:
    bpf_printk("FIB lookup failed: PROHIBITED route. Forwarding is "
               "administratively blocked.");
    break;
  case BPF_FIB_LKUP_RET_NOT_FWDED:
    bpf_printk("FIB lookup failed: NOT_FORWARDED. Destination likely on the "
               "same subnet – try BPF_FIB_LOOKUP_DIRECT for on-link lookup.");
    break;
  case BPF_FIB_LKUP_RET_FWD_DISABLED:
    bpf_printk("FIB lookup failed: FORWARDING DISABLED. Enable it via 'sysctl "
               "-w net.ipv4.ip_forward=1' or IPv6 equivalent.");
    break;
  case BPF_FIB_LKUP_RET_UNSUPP_LWT:
    bpf_printk("FIB lookup failed: UNSUPPORTED LWT. The route uses a "
               "lightweight tunnel not supported by bpf_fib_lookup().");
    break;
  case BPF_FIB_LKUP_RET_NO_NEIGH:
    bpf_printk("FIB lookup failed: NO NEIGHBOR ENTRY. ARP/NDP unresolved – "
               "check 'ip neigh show' or ping the target to populate cache.");
    break;
  case BPF_FIB_LKUP_RET_FRAG_NEEDED:
    bpf_printk("FIB lookup failed: FRAGMENTATION NEEDED. Packet exceeds MTU; "
               "adjust packet size or enable PMTU discovery.");
    break;
  case BPF_FIB_LKUP_RET_NO_SRC_ADDR:
    bpf_printk(
        "FIB lookup failed: NO SOURCE ADDRESS. Kernel couldn’t choose a source "
        "IP – ensure the interface has an IP in the correct subnet.");
    break;
  default:
    bpf_printk("FIB lookup failed: rc=%d (unknown). Check routing and ARP/NDP "
               "configuration.",
               rc);
    break;
  }
}

static __always_inline __u16 recalc_ip_checksum(struct iphdr *ip) {
  // Clear checksum
  ip->check = 0;

  // Compute incremental checksum difference over the header
  __u64 csum = bpf_csum_diff(0, 0, (unsigned int *)ip, sizeof(struct iphdr), 0);

// fold 64-bit csum to 16 bits (the “carry add” loop)
#pragma unroll
  for (int i = 0; i < 4; i++) {
    if (csum >> 16)
      csum = (csum & 0xffff) + (csum >> 16);
  }

  return ~csum;
}

static __always_inline __u16 recalc_tcp_checksum(struct tcphdr *tcph, struct iphdr *iph, void *data_end) {
    tcph->check = 0;
    __u32 sum = 0;

    // Pseudo-header: IP addresses
    sum += (__u16)(iph->saddr >> 16) + (__u16)(iph->saddr & 0xFFFF);
    sum += (__u16)(iph->daddr >> 16) + (__u16)(iph->daddr & 0xFFFF);
    sum += bpf_htons(IPPROTO_TCP);

    // Pseudo-header: TCP Length (Total IP len - IP header len)
    // IMPORTANT: Use the IP header, not data_end
    __u16 tcp_len = bpf_ntohs(iph->tot_len) - (iph->ihl * 4);
    sum += bpf_htons(tcp_len);

    // TCP Header + Payload
    // Use a safe bound check against data_end for the pointer,
    // but the loop limit should be based on the actual packet size
    __u16 *ptr = (__u16 *)tcph;
    #pragma unroll
    for (int i = 0; i < MAX_TCP_CHECK_WORDS; i++) {
        if ((void *)(ptr + 1) > data_end || (void *)ptr >= (void *)tcph + tcp_len)
            break;
        sum += *ptr;
        ptr++;
    }

    // Handle odd-length packets (the last byte)
    if (tcp_len & 1) {
        if ((void *)ptr + 1 <= data_end) {
            sum += bpf_htons(*(__u8 *)ptr << 8);
        }
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ~sum;
}

static __always_inline int fib_lookup_v4_full(struct xdp_md *ctx,
                                              struct bpf_fib_lookup *fib,
                                              __u32 src, __u32 dst,
                                              __u16 tot_len) {
  // Zero and populate only what a full lookup needs
  __builtin_memset(fib, 0, sizeof(*fib));
  // Hardcode address family: AF_INET for IPv4
  fib->family = AF_INET;
  // Source IPv4 address used by the kernel for policy routing and source
  // address–based decisions
  fib->ipv4_src = src;
  // Destination IPv4 address (in network byte order)
  // The address we want to reach; used to find the correct egress route
  fib->ipv4_dst = dst;
  // Hardcoded Layer 4 protocol: TCP, UDP, ICMP
  fib->l4_protocol = IPPROTO_TCP;
  // Total length of the IPv4 packet (header + payload)
  fib->tot_len = tot_len;
  // Interface for the lookup
  fib->ifindex = ctx->ingress_ifindex;

  return bpf_fib_lookup(ctx, fib, sizeof(*fib), 0);
}

SEC("xdp")
int xdp_load_balancer(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct hdr_cursor nh;
  nh.pos = data;

  // Parse Ethernet header to extract source and destination MAC address
  struct ethhdr *eth;
  int eth_type = parse_ethhdr(&nh, data_end, &eth);
  // For simplicity we only show IPv4 load-balancing
  if (eth_type != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  // Parse IP header to extract source and destination IP
  struct iphdr *ip;
  int ip_type = parse_iphdr(&nh, data_end, &ip);
  if ((void *)(ip + 1) > data_end) {
    return XDP_PASS;
  }

  // For simplicity only load-balance TCP traffic
  if (ip->protocol != IPPROTO_TCP) {
    return XDP_PASS;
  }

  // Parse TCP header to extract source and destination port
  struct tcphdr *tcp;
  int tcp_type = parse_tcphdr(&nh, data_end, &tcp);
  if ((void *)(tcp + 1) > data_end) {
    return XDP_PASS;
  }

  // We could technically load-balance all the traffic but
  // we only focus on port 8000 to not impact any other network traffic in the playground
  if (bpf_ntohs(tcp->source) != 8000 && bpf_ntohs(tcp->dest) != 8000) {
    return XDP_PASS;
  }

  bpf_printk("IN: SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);
  bpf_printk("IN: SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC "
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);

  // Store Load Balancer IP for later
  __u32 lb_ip = ip->daddr;

  // Lookup conntrack (connection tracking) information - actually eBPF map
  // Connection exist: backend response
  // No Connection: client request
  struct five_tuple_t in = {};
  in.src_ip = ip->daddr;     // LB IP
  in.dst_ip = ip->saddr;     // Client or Backend IP
  in.src_port = tcp->dest;   // LB destination port same as source port from which it redirected the request to backend
  in.dst_port = tcp->source; // Client or Backend source port
  in.protocol = IPPROTO_TCP; // TCP protocol

  struct bpf_fib_lookup fib = {};
  struct endpoint *out = bpf_map_lookup_elem(&conntrack, &in);
  if (!out) {
    bpf_printk("Packet from client because no such connection exists yet");

    // Choose backend using simple hashing
    struct five_tuple_t five_tuple = {};
    five_tuple.src_ip = ip->saddr;
    five_tuple.dst_ip = ip->daddr;
    five_tuple.src_port = tcp->source;
    five_tuple.dst_port = tcp->dest;
    five_tuple.protocol = IPPROTO_TCP;
    // Hash the 5-tuple for persistent backend routing and
    // perform modulo with the number of backends (NUM_BACKENDS=2 hardcoded for simplicity)
    __u32 key = xdp_hash_tuple(&five_tuple) % NUM_BACKENDS;
    // Lookup calculated key and retrieve the backend endpoint information
    // NOTE: The 'backends' eBPF Map is populated from user space
    struct endpoint *backend = bpf_map_lookup_elem(&backends, &key);
    if (!backend) {
      return XDP_ABORTED;
    }

    // Perform a FIB lookup
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, backend->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Store connection in the conntrack eBPF map (client -> backend)
    struct five_tuple_t in_loadbalancer = {};
    in_loadbalancer.src_ip = ip->daddr;   // LB IP
    in_loadbalancer.dst_ip = backend->ip; // Backend IP
    in_loadbalancer.src_port = tcp->source; // Client source port equal to the LB source port since we don't modify it!
    in_loadbalancer.dst_port = tcp->dest; // LB destination port
    in_loadbalancer.protocol = IPPROTO_TCP; // TCP protocol 
    struct endpoint client;
    client.ip = ip->saddr; // Client IP
    int ret =
        bpf_map_update_elem(&conntrack, &in_loadbalancer, &client, BPF_ANY);
    if (ret != 0) {
      bpf_printk("Failed to update conntrack eBPF map");
      return XDP_ABORTED;
    }

    // Replace destination IP with backends' IP
    ip->daddr = backend->ip;
    // Replace destination MAC with backends' MAC
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
  } else {
    bpf_printk("Packet from backend because the connection exists - "
               "redirecting back to client");

    // Perform a FIB lookup - same as above
    int rc = fib_lookup_v4_full(ctx, &fib, ip->daddr, out->ip,
                                bpf_ntohs(ip->tot_len));
    if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
      log_fib_error(rc);
      return XDP_ABORTED;
    }

    // Replace destination IP and MAC with clients' IP and MAC
    ip->daddr = out->ip;
    __builtin_memcpy(eth->h_dest, fib.dmac, ETH_ALEN);
  }

  // Replace source IP with load balancers' IP
  ip->saddr = lb_ip;
  // Replace source MAC with load balancers' MAC
  __builtin_memcpy(eth->h_source, fib.smac, ETH_ALEN);

  // We need to recalculate IP checksum because we modified the IP header
  ip->check = recalc_ip_checksum(ip);

  // As well as TCP Checksum
  tcp->check = recalc_tcp_checksum(tcp, ip, data_end);

  // We don’t need to recalculate a Ethernet frame checksum after changing
  // Ethernet MACs because the Ethernet frame checksum (FCS) isn’t in the header
  // but instead is automatically recomputed by the NIC hardware when the packet
  // is transmitted.

  bpf_printk("OUT: SRC IP %pI4 -> DST IP %pI4", &ip->saddr, &ip->daddr);
  bpf_printk("OUT: SRC MAC %02x:%02x:%02x:%02x:%02x:%02x -> DST MAC "
             "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);

  // Return XDP_TX to transmit the modified packet back to the network
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
