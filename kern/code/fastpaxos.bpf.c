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
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, FAST_PROG_XDP_MAX);
} map_progs_xdp SEC(".maps");

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
	__u32 view, opnum, bitset; // opnum是论文中的seq，bitset用于标记收到哪些follower的回复
};

// xdp_ebpf中用到 ,每一项对应一次广播与回复
// 这个应该是bitset array 在tc和xdp间共享
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct paxos_quorum);
	__uint(max_entries, QUORUM_BITSET_ENTRY);
} map_quorum SEC(".maps");


struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<20);
} map_prepare_buffer SEC(".maps");


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

SEC("xdp")
int fastPaxos_main(struct xdp_md *ctx) {
	// 一大坨的就是确认是否是vr的包，以及是vr的哪个类型的包
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return XDP_PASS; // boundary check.
	/*查linux kernel
	IPPROTO_UDP = 17,		// User Datagram Protocol		
	define IPPROTO_UDP		IPPROTO_UDP
	*/
	if (ip->protocol != IPPROTO_UDP) return XDP_PASS; // check it's udp packet.
	if (udp + 1 > data_end) return XDP_PASS; // boundary check.
	/* config.txt 中端口皆为 12345
	*/
	if (udp -> dest != htons(12345)) return XDP_PASS; // port check, our process bound to 12345.
	if (payload + MAGIC_LEN > data_end) return XDP_PASS; // don't have magic bits...
	// asd123www: currently, we don't support reassembly.
	// 什么是reassembly？下面这4个数，common.h中定义，但是为什么头尾倒置
	if (payload[0] != 0x18 || payload[1] != 0x03 || payload[2] != 0x05 || payload[3] != 0x20) return XDP_PASS;
	payload = payload + MAGIC_LEN;
	if (payload + sizeof(__u64) > data_end) return XDP_PASS; // don't have typelen...

	__u64 typeLen = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
	if (typeLen >= MTU || payload + typeLen > data_end) return XDP_PASS; // don't have type str...
	
	__u32 zero = 0;
// typeLen这64个bits谁来写的？用户程序的哪里？
#ifdef FAST_REPLY 
	if (payload + PREPARE_TYPE_LEN < data_end && // PREPARE_TYPE_LEN = 33
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='M') {
			// PrepareMessage in `vr`.
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPARE); // go to fastACK
		return XDP_PASS;
	}
#endif

#ifdef FAST_QUORUM_PRUNE
	if (payload + PREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'P' &&
	 	payload[20] == 'r' && payload[21] =='e' && payload[22] =='p' && 
	 	payload[23] =='a' && payload[24] =='r' && payload[25] =='e' && payload[26] =='O') {
			// PrepareOK message in `vr`. // 下面那个一毛一样
		__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
		if (context) { // leader 没有op就不进行wait on quorum
			*context = (void *)payload + typeLen - data;
			// 由eBPF Docs 知，此函数调整（移动）xdp_md->data指针，移动delta字节，这里意思应该是从头开始
			bpf_xdp_adjust_head(ctx, *context);
			bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPAREOK);
		}
		return XDP_PASS;
	}
	if (payload + MYPREPAREOK_TYPE_LEN < data_end &&
		payload[10] == 'v' && payload[11] == 'r' && payload[13] == 'M' &&
	 	payload[14] == 'y' && payload[15] =='P' && payload[16] =='r') {
			// MyPrepareOK message in `vr`.
		__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
		if (context) {
			*context = (void *)payload + typeLen - data;
			bpf_xdp_adjust_head(ctx, *context);
			bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_PREPAREOK);
		}
		return XDP_PASS;
	}
#endif

	/* Optimization for adaptive batching, ignore.
	else if (payload + REQUEST_TYPE_LEN < data_end && 
		payload[10] == 'v' && payload[11] == 'r' && payload[19] == 'R' && 
		payload[20] == 'e' && payload[21] =='q' && payload[22] =='u' && 
	 	payload[23] =='e' && payload[24] =='s' && payload[25] =='t' && payload[26] =='M') {
			// Request message in `vr`.
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_HANDLE_REQUEST);
	} */
	return XDP_PASS;
}

SEC("xdp")
int HandlePrepareOK_main(struct xdp_md *ctx) {// prepareOK指follower完成了改statemachine,告诉leader，md指metadata
	// now data points to `fastPaxos header`.
	// we should parse this.
	void *data_end = (void *)(long)ctx->data_end;// 这个挺特殊不用从头解析
	void *data = (void *)(long)ctx->data;

	if (data + FAST_PAXOS_DATA_LEN > data_end) return XDP_DROP;
	__u32 msg_view = *((__u32*)data + 0);
	__u32 msg_opnum = *((__u32*)data + 1);
	__u32 msg_replicaIdx = *((__u32*)data + 2);
	__u32 idx = msg_opnum & (QUORUM_BITSET_ENTRY - 1); // 与 1023(10个1) 即 mod 1024
	struct paxos_quorum *entry = bpf_map_lookup_elem(&map_quorum, &idx); 
	if (!entry) return XDP_PASS; // 何时会!entry？


	__u32 count = 0;//                    seq不等
	if (entry -> view != msg_view || entry -> opnum != msg_opnum) return XDP_PASS;//tc改了
	// 去到HandlePrepareOK函数
	entry -> bitset |= 1 << msg_replicaIdx;// bitset 相应位置置一
	count = __builtin_popcount(entry -> bitset); // 数 到没到quorum

	if (count != QUORUM_SIZE - 1) return XDP_DROP; // ignore PrepareOK that will not affect consensus.
	// asd123www: may change buffering here in the future.
	__u32 zero = 0;
	//修改维护的变量
	__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
	if (context) bpf_xdp_adjust_head(ctx, -((int)*context)); // ？这个是mark？那怎么影响上层？
	return XDP_PASS;
}

// §5 handle_preparation: 识别 non-critical path ,大部分情况直接调用Write Buffer实现fastACK
// 这个函数raft要做比较多相应修改？
SEC("xdp")
int HandlePrepare_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	// parsing message's info.
	if (payload + MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN > data_end) return XDP_PASS;
	payload += MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN; // point to our extra_data.
	__u64 msg_view = *((__u32*)payload + 0);// 这个就是加在
	__u64 msg_lastOp = *((__u32*)payload + 1);
	__u64 msg_batchStart = *((__u32*)payload + 2);
	payload += 3 * sizeof(__u32);

	__u32 zero = 0;
	__u64 *context = bpf_map_lookup_elem(&map_msg_lastOp, &zero);// 这啥？op mod 1024 = seq，维护这个干啥
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);// 判断所用的三大变量
	if (!context || !ctr_state) return XDP_PASS; // can't find the context...
	/*raftmodified*/
	// 对应non-critical path detect §6 Listing 2
	// asd123www: rare case, not handled properly now.
	// the follower is during a leader election or recovering
	if (ctr_state -> state != STATUS_NORMAL) return XDP_DROP;//1
	// the follower receives a message with an unmatched view that is stale
	//2a
	if (msg_view < ctr_state -> view) return XDP_DROP; // hear a stale  message, we shouldn't respond to that.
	// the follower receives a message with an unmatched view that is newer or 
	// non-strictlyincreasing seq caused by message (a) loss/reordering
	//2b
	if (msg_view > ctr_state -> view) return XDP_PASS; // view change... offload to user-space.

	// Resend the prepareOK message
	// reply_ack(pkt)//3b
	if (msg_lastOp <= ctr_state -> lastOp) {// 这个是seq
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_PREPARE_REPLY);
		return XDP_PASS;
	}// reply but not append log
	// rare case, to user-space.
	// asd123www: actually there is a buffering thing...
	// the follower receives a message with an unmatched view that is newer or 
	// non-strictlyincreasing seq caused by message (a) loss/reordering 
	if (msg_batchStart > ctr_state -> lastOp + 1) return XDP_PASS;//3a
	// 上面都是不同的特殊情况
	// 一般应该是 view 相同，msg_lastOp = lastOp + 1 ，append_log(++ebpf_seq, pkt)
	*context = msg_lastOp; // 为什么要弄两个一样的东西
	ctr_state -> lastOp = msg_lastOp;
	bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_WRITE_BUFFER);
	return XDP_PASS;
	/*
	原论文§6提到一个问题：
	用户的paxos和ebpf是并发的，而map中维护的view，status，seq等不保证同步
	解决方法是先暂时分离eBPF程序 或者
	在paxos那里收到第一个non-critical包就暂停electrode，全部接受，然后稍后再开启
	*/
}

// §5 write_buffer 存入ring buffer,然后调用fastACK回复leader
// currently we don't support reassembly, modify this in future if we want.
SEC("xdp")
int WriteBuffer_main(struct xdp_md *ctx) {

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + 
					MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN; // points to .proto message.
	if (payload >= data_end) return XDP_PASS;
	if (payload + MAX_DATA_LEN < data_end) return XDP_PASS;

	// buffer not enough, offload to user-space.
	// It's easy to avoid cause VR sends `CommitMessage` make followers keep up with the leader.
	char *pt = bpf_ringbuf_reserve(&map_prepare_buffer, MAX_DATA_LEN, 0);//留空间
	if (pt) {
		for (int i = 0; i < MAX_DATA_LEN; ++i) 
			if (payload + i + 1 <= data_end) pt[i] = payload[i];
		bpf_ringbuf_submit(pt, 0); // guarantee to succeed. 写入
		bpf_tail_call(ctx, &map_progs_xdp, FAST_PROG_XDP_PREPARE_REPLY); // 尾调用fastACK
	}
	return XDP_PASS;// pass就到handelPrepare那了
}

// §5 fastACK 发回信给leader
// 可能是同view msg.seq<=local.seq，也可能是正常的已经write buffer的
SEC("xdp")
int PrepareFastReply_main(struct xdp_md *ctx) {
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (payload + MAGIC_LEN + sizeof(__u64) + PREPARE_TYPE_LEN + FAST_PAXOS_DATA_LEN + sizeof(__u64) >= data_end) return XDP_PASS;	
	
	// read our state.
	__u32 zero = 0;
	__u64 *msg_lastOp = bpf_map_lookup_elem(&map_msg_lastOp, &zero);
	struct paxos_ctr_state *ctr_state = bpf_map_lookup_elem(&map_ctr_state, &zero);
	if (!msg_lastOp || !ctr_state) return XDP_PASS; // can't find the context...

	struct paxos_configure *leaderInfo = bpf_map_lookup_elem(&map_configure, &ctr_state -> leaderIdx);
	if (!leaderInfo) return XDP_PASS;

	// 修改报文：在magic这里开始改
	// do reply.
	*(__u32 *)payload = NONFRAG_MAGIC;
	payload += sizeof(__u32);
	*(__u64 *)payload = MYPREPAREOK_TYPE_LEN;
	payload += sizeof(__u64); 
	// change "specpaxos.vr.proto.PrepareMessage" to "specpaxos.vr.MyPrepareOK"
	payload[13] = 'M', payload[14] = 'y', payload[15] = 'P', payload[16] = 'r',
	payload[17] = 'e', payload[18] = 'p', payload[19] = 'a', payload[20] = 'r',
	payload[21] = 'e', payload[22] = 'O', payload[23] = 'K';
	payload += MYPREPAREOK_TYPE_LEN;

	*(__u32 *)payload = ctr_state -> view; // must equal to message.
	*((__u32 *)payload + 1) = *msg_lastOp; // must equal to message.
	*((__u32 *)payload + 2) = ctr_state -> myIdx; // our's may advance.
	payload += FAST_PAXOS_DATA_LEN;
	if (payload + sizeof(__u64) * 3 + sizeof(__u32) > data_end) {
		// asd123www: wrong!!! foreeest: 这老铁在搞啥？
		// make sure message length is big enough!
		return XDP_PASS;
	}// 这里为什么要写两次？
	*(__u64 *)payload = sizeof(__u64) * 2 + sizeof(__u32);
	*((__u64 *)payload + 1) = ctr_state -> view; // must equal to message.
	*((__u64 *)payload + 2) = *msg_lastOp; // our's may advance.
	payload += sizeof(__u64) * 3;
	*(__u32 *)payload = ctr_state -> myIdx;
	payload += sizeof(__u32);

	// 目标为leader，改udp ip
	udp -> source = udp -> dest;
	udp -> dest = leaderInfo -> port;
	udp -> len = htons(payload - (char *)udp); // calc length. char *还是别的应该都一样吧感觉
	// host to net
	udp -> check = 0; // computing udp checksum is not required

	ip -> tot_len = htons(payload - (char *)udp + sizeof(struct iphdr)); // 为何不直接写(char *)ip?
	ip -> saddr = ip -> daddr; // source -> destination 
	ip -> daddr = leaderInfo -> addr;
	ip -> check = compute_ip_checksum(ip);// 凡改ip目标就checksum，本函数的另一次出现在fast boardcast另一端

	unsigned char tmp_mac[ETH_ALEN];// 一个简单的交换
	memcpy(tmp_mac, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, tmp_mac, ETH_ALEN);
	// 调用此辅助函数会改变底层的数据包缓冲区，指针从头来
	bpf_xdp_adjust_tail(ctx, (void *)payload - data_end);
	return XDP_TX;// Accodring to Docs :Send the packet back out the same network port it arrived on. 
	//The packet can be manipulated before hand.
}

char _license[] SEC("license") = "GPL";
