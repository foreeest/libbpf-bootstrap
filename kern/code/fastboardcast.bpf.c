#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h> 
// TC_ACT_OK
//#include <linux/in.h> 
// IPPROTO_UDP
//#include "linux/tools/lib/bpf/bpf_helpers.h"
// 0513
//#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// #include <string.h>

// #define TC_ACT_OK 0
// #define TC_ACT_SHOT 2
// #define IPPROTO_UDP 17

#include <arpa/inet.h>

#include "fastboardcast.h"


#define ADJUST_HEAD_LEN 128
#define MTU 1500
#define MAX_DATA_LEN 64
#define REQ_MAX_DATA_LEN 128


struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct paxos_configure);
	__uint(max_entries, FAST_REPLICA_MAX);
} map_configure SEC(".maps");

// control state, only changes in user-space(except lastOp).
// ctr_state被获取了fd，然后pin
struct paxos_ctr_state {
	enum ReplicaStatus state; // asd123www: maybe we don't need it...
	int myIdx, leaderIdx, batchSize; // it's easier to maintain in user-space.
	__u64 view, lastOp;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct paxos_ctr_state);
	__uint(max_entries, 1);
} map_ctr_state SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, 1);
} map_msg_lastOp SEC(".maps");


struct paxos_quorum {
	__u32 view, opnum, bitset;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct paxos_quorum);
	__uint(max_entries, QUORUM_BITSET_ENTRY);
} map_quorum SEC(".maps");



// IPv4头校验和，检测是否在传输中发生错误
static inline __u16 compute_ip_checksum(struct iphdr *ip) {
    __u32 csum = 0;
    __u16 *next_ip_u16 = (__u16 *)ip;

    ip->check = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < (sizeof(*ip) >> 1); i++) {
        csum += *next_ip_u16++;
    }

	return ~((csum & 0xffff) + (csum >> 16));// 低16+高16
}

static inline int compute_message_type(char *payload, void *data_end) {
	if (payload + PREPARE_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='M') {
			// PrepareMessage in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPARE;// 宏是在common.h中定义的enum
	} else if (payload + REQUEST_TYPE_LEN < data_end && 
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'R' && 
		payload[20] == 'e' && payload[21] =='q' && payload[22] =='u' && 
	 	payload[23] =='e' && payload[24] =='s' && payload[25] =='t' && payload[26] =='M') {
			// Request message in `vr`.
		return FAST_PROG_XDP_HANDLE_REQUEST;
	} else if (payload + PREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='O') {
			// PrepareOK message in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPAREOK;
	} else if (payload + MYPREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[13] == 'M' &&
	 	payload[14] == 'y' && payload[15] =='P' && payload[16] =='r') {
			// MyPrepareOK message in `vr`.
		return FAST_PROG_XDP_HANDLE_PREPAREOK;
	}
	return -1;
}

SEC("tc")
int FastBroadCast_main(struct __sk_buff *skb) {// sk 指 socket
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);//指针

	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;
	if (udp -> source != htons(12345)) return TC_ACT_OK; // port 也先12345

	if (payload + MAGIC_LEN > data_end) return TC_ACT_OK; // don't have magic bits...
	if (payload[0] != 0x18 || payload[1] != 0x03 || payload[2] != 0x05 || payload[3] != 0x20) return TC_ACT_OK;
	payload = payload + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return TC_ACT_OK; // don't have typelen...
	__u64 typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	char *type_str = payload;
	if (type_str + 5 >= data_end) return TC_ACT_OK;// + 5是啥
	if (typeLen >= MTU || payload + typeLen > data_end) return TC_ACT_OK; // don't have type str...
	payload += typeLen;
	if (payload + FAST_PAXOS_DATA_LEN > data_end) return TC_ACT_OK;

	// 以下操作：正是vr的sgn bit置的1<<31
	__u32 msg_view = *(__u32*)payload;
	__u32 is_broadcast = msg_view & BROADCAST_SIGN_BIT;
	msg_view ^= is_broadcast; // 最高位 置1
	__u32 msg_lastOp = *((__u32*)payload + 1);
	int msg_type = compute_message_type(type_str, data_end);

	if (msg_type == FAST_PROG_XDP_HANDLE_PREPARE) { // clear bitset entry.
		__u32 idx = msg_lastOp & (QUORUM_BITSET_ENTRY - 1); // bitset 即mod1024
		struct paxos_quorum *entry = bpf_map_lookup_elem(&map_quorum, &idx);
		if (entry) { // 不等就清零，相等说明有人来清零过就不重复了
			if (entry -> view != msg_view || entry -> opnum != msg_lastOp) {
				entry -> view = msg_view;
				entry -> opnum = msg_lastOp;
				entry -> bitset = 0;
			}
		}
	}

	if (!is_broadcast) return TC_ACT_OK;// 不优化的直接发了

	__u32 zero = 0;
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!ctr_state) return TC_ACT_OK; // can't find the context...

	char id, nxt; // sp 如 specpaxos.vr.MyPrepareOK，除了是sp还能是啥，就是xM，意思应该是多播，x是目标follower的idx
	if (type_str[0] == 's' && type_str[1] == 'p') { 
		id = !ctr_state -> leaderIdx;// ! 0 变 1，其它数字变0

		nxt = id + 1;
		nxt += ctr_state -> leaderIdx == nxt;
		type_str[0] = nxt;
		type_str[1] = 'M'; // sign for multicast. 这个会影响后续处理吗？
		if (nxt < CLUSTER_SIZE) bpf_clone_redirect(skb, skb -> ifindex, 0);// ifindex 就是ensp1那个
	} else {
		id = type_str[0];

		nxt = id + 1;
		nxt += ctr_state -> leaderIdx == nxt;
		type_str[0] = nxt;
		if (nxt < CLUSTER_SIZE) bpf_clone_redirect(skb, skb -> ifindex, 0);// 关键函数
	}

	// Why so verbose? `bpf_clone_redirect` may change buffer — from linux manual. 确实
	data_end = (void *)(long)skb->data_end;
	data     = (void *)(long)skb->data;
	eth = data;
	ip = data + sizeof(struct ethhdr);
	udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return TC_ACT_OK; // don't have typelen...
	typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	type_str = payload;
	// TC_ACT_OK (0) - Signals that the packet should proceed.
	// TC_ACT_SHOT (2) - Signals that the packet should be dropped, no other TC processing should happen.
	if (type_str + 5 >= data_end) return TC_ACT_SHOT;
	if (typeLen >= MTU || payload + typeLen > data_end) return TC_ACT_SHOT; // don't have type str...
	payload += typeLen;
	if (payload + FAST_PAXOS_DATA_LEN > data_end) return TC_ACT_SHOT;

	*(__u32*)payload = msg_view;
	type_str[0] = 's', type_str[1] = 'p';
	struct paxos_configure *replicaInfo = bpf_map_lookup_elem(&map_configure, &id);
	if (!replicaInfo) return TC_ACT_SHOT;
	// 改成目标地址
	udp -> dest = replicaInfo -> port;
	udp -> check = 0;
	ip -> daddr = replicaInfo -> addr;
	ip -> check = compute_ip_checksum(ip);
	memcpy(eth -> h_dest, replicaInfo -> eth, ETH_ALEN);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
