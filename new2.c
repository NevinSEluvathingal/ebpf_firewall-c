#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

struct user_downstream_event {
    __u64 bytes;
    __u32 ip;
    __u8 mac[6];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(max_entries, 64);
} perf_events SEC(".maps");

SEC("xdp")
int count_downstream(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    // Only downstream: destination IP is local? (You can filter here)
    // For example, ignore packets that are not destined to this host.

    struct user_downstream_event event = {};
    event.bytes = (__u64)(data_end - data);
    event.ip = ip->daddr;
    __builtin_memcpy(event.mac, eth->h_dest, 6);

    bpf_perf_event_output(ctx, &perf_events, BPF_F_CURRENT_CPU, &event, sizeof(event));

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
