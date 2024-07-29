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
#include <string.h>

#include "fastudp.h"

// this is from Electrode, I don't know what is this
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

static inline __u32 FindFirstBit_u16(__u16 n)
{
    n = (n-1) & ~n;
    n = ((n & 0xAAAA) >> 1) + (n & 0x5555);
    n = ((n & 0xCCCC) >> 2) + (n & 0x3333);
    n = ((n & 0xF0F0) >> 4) + (n & 0x0F0F);
    n = ((n & 0xFF00) >> 8) + (n & 0x00FF);
    return (__u32)n;
}

/*
unmarshal the msg,and get:
    To
    Type
*/
// static inline __u32 UnmarshalType(char* payload, void* data_end){
//     __u8 b = 0;
//     __u64 wire = 0;
//     __u32 shift = 0;
//     __u32 fieldNum = 0;
//     __u32 wireType = 0;

//     if (payload + sizeof(__u8) > data_end) return -1;
//     b = *payload; // 0xa
//     payload = payload + sizeof(__u8);
//     wire |= ((__u64)b & 0x7F);
//     fieldNum = (__u32)(wire>>3); // 1
//     wireType = (__u32)(wire&0x7);  // 2

//     __u32 msgLen = 0; // how long is a Message that is marshalled
//     #pragma clang loop unroll(full)
//     for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
//         shift = i * 7;
//         if (payload + sizeof(__u8) > data_end) return -1;
//         b = *payload;
//         payload = payload + sizeof(__u8);
//         msgLen |= ((__u64)b & 0x7F) << shift;
//         if(b < 0x80){ // the Varint is over
// 			break;
// 		}
//     }

//     if (payload + sizeof(__u8) > data_end) return -1;
//     b = *payload; // 0x8
//     payload = payload + sizeof(__u8);
//     wire |= ((__u64)b & 0x7F);
//     fieldNum = (__u32)(wire>>3); // 1
//     wireType = (__u32)(wire&0x7);  // 0

//     __u32 Type = 0; // Message Type
//     #pragma clang loop unroll(full)
//     for(int i=0;i<20;i++){
//         shift = i * 7;
//         if (payload + sizeof(__u8) > data_end) return -1;
//         b = *payload;
//         payload = payload + sizeof(__u8);
//         Type |= ((__u64)b & 0x7F) << shift;
//         if(b < 0x80){
// 			break;
// 		}
//     }

//     return Type;
// }

// static inline __u32 UnmarshalTo(__u64* To, char* payload, void* data_end){
//     __u8 b = 0;
//     __u64 wire = 0;
//     __u32 shift = 0;
//     __u32 fieldNum = 0;
//     __u32 wireType = 0;

//     __u32 lenTo = 0;

//     #pragma clang loop unroll(full)
//     for(int i=0;i<NODE_MAX_NUM;i++){
//         if (payload + sizeof(__u8) > data_end) return -1;
//         b = *payload; // 0x12
//         payload = payload + sizeof(__u8);
//         wire |= ((__u64)b & 0x7F);
//         fieldNum = (__u32)(wire>>3); // 2
//         wireType = (__u32)(wire&0x7);  // 2
//         if(fieldNum != 2) break; // 0x18 -> next field
//         lenTo++;

//         __u32 msgLen = 0; // how long is a To[i] that is marshalled
//         #pragma clang loop unroll(full)
//         for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
//             shift = i * 7;
//             if (payload + sizeof(__u8) > data_end) return -1;
//             b = *payload;
//             payload = payload + sizeof(__u8);
//             msgLen |= ((__u64)b & 0x7F) << shift;
//             if(b < 0x80){ // the Varint is over
//                 break;
//             }
//         }

//         __u32 Toi = 0; // how long is a To[i] that is marshalled
//         #pragma clang loop unroll(full)
//         for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
//             shift = i * 7;
//             if (payload + sizeof(__u8) > data_end) return -1;
//             b = *payload;
//             payload = payload + sizeof(__u8);
//             Toi |= ((__u64)b & 0x7F) << shift;
//             if(b < 0x80){ // the Varint is over
//                 break;
//             }
//         }
//         To[i] = Toi;

//     }

//     return lenTo;    
// }

/*
stop a message from functions below:
    func (r *raft) sendHeartbeatMessage
    func (r *raft) sendReplicateMessage(to uint64) -> func (r *raft) makeReplicateMessage
*/
SEC("tc")
int FastBroadCast_main(struct __sk_buff *skb) {
	void *data_end = (void *)(__u64)skb->data_end;
	void *data = (void *)(__u64)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
	if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

	if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

	// print origin ip and mac addr if you like
	// __u32 ipadd = ntohl(ip->daddr);
	// bpf_printk("ip is %u.%u.%u",((ipadd)>>24) & 0xFF, ((ipadd)>>16) & 0xFF,((ipadd)>>8) & 0xFF);
	// bpf_printk(".%u:%d \n",(ipadd) & 0xFF,ntohs(udp->dest));
	// bpf_printk("eth is %02X:%02X:%02X",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2]);
	// bpf_printk("%02X:%02X:%02X\n",eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);

	// extend it
	if (udp->dest!=htons(12379)&&udp->dest!=htons(22379)&&udp->dest!=htons(32379)
	&&udp->dest!=htons(60000)&&udp->dest!=htons(60001)&&udp->dest!=htons(60002)&&udp->dest!=htons(60003)) return TC_ACT_OK; // local port
	
	// bpf_printk("from %d to %d\n",(int)ntohs(udp->source),(int)ntohs(udp->dest),(int)ntohs(udp->check));

    /* ---parse appl head---
	Dragonboat's Appl: magic(2byte) -- requestHeader = method uint16 + size uint64
	+ checksum uint32 +crc uint32 -- bitset uint64(lowest bit represent No.0) */
	if ((void *)(payload + MAGIC_LEN) > data_end) return TC_ACT_OK; // don't have magic bits...
    // net use:bigEidian & raft magic: magicNumber = [2]byte{0xAE, 0x7D}
	// bpf_printk("magic num is %d and %d\n",(int)magic_0,(int)magic_1);
    if ((__u8)(payload[0]) != (__u8)0xAE || (__u8)(payload[1]) != (__u8)0x7D) return TC_ACT_OK;
	payload = payload + MAGIC_LEN;

	if ((void *)(payload + sizeof(__u16)) > data_end) return TC_ACT_OK; 
	__u16 method = *(__u16 *)payload;
    if(method != htons((__u16)raftType)) return TC_ACT_OK;
	payload = payload + sizeof(__u16);
    if ((void *)(payload + sizeof(__u64)) > data_end) return TC_ACT_OK; 
	__u64 size = *(__u64 *)payload;
	payload = payload + sizeof(__u64);
    if ((void *)(payload + sizeof(__u32)) > data_end) return TC_ACT_OK; 
	__u32 checksum = *(__u32 *)payload;
	payload = payload + sizeof(__u32);
    if ((void *)(payload + sizeof(__u32)) > data_end) return TC_ACT_OK; 
	__u32 crc = *(__u32 *)payload;
	payload = payload + sizeof(__u32);

    if ((void *)(payload + sizeof(__u64)) > data_end) return TC_ACT_OK; 
	// current only handle 32bit, beacuse ntoh only have 16 bit and 32 bit, and I don't want to do it myself
	__u16* bitset_1 = (__u16 *)payload; // This is used to store the origin bitset
	payload = payload + sizeof(__u16);
	__u32 bitset_2 = *(__u32 *)payload; // I don't modify this
	payload = payload + sizeof(__u32);
	__u16* bitset_3 = (__u16 *)payload; // pointer, beacause I will modify
	payload = payload + sizeof(__u16);    
	bpf_printk("%d %d\n",(int)ntohs(*bitset_1),(int)ntohs(*bitset_3));

	if (__builtin_popcount((__u32)(*bitset_3))==1&&(*bitset_1) == 0){ // don't need broadcast,just process
		// __u32 ipadd = ntohl(ip->daddr);
		// bpf_printk("st:ip is %u.%u.%u",((ipadd)>>24) & 0xFF, ((ipadd)>>16) & 0xFF,((ipadd)>>8) & 0xFF);
		// bpf_printk(".%u:%d \n",(ipadd) & 0xFF,ntohs(udp->dest));
		// bpf_printk("st:eth is %02X:%02X:%02X",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2]);
		// bpf_printk("%02X:%02X:%02X\n",eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		return TC_ACT_OK;
	}

	if (*bitset_1 == 0){ // first store the origin biset, so I don't modify the appl in the end
		*bitset_1 = *bitset_3;
	}

	__u16 host_bs = ntohs((*bitset_3));	
	__u32 id = FindFirstBit_u16(host_bs); // id start from 0
	__u32 is_broadcast = __builtin_popcount((__u32)(host_bs)); // more than 1, need to broadcast
	__u16 low_one = (host_bs) & (~(host_bs) + 1);
	host_bs = host_bs ^ low_one; // clear the lowest one

	*bitset_3 = htons(host_bs);

	if (is_broadcast > 1){
		bpf_printk("broadcast,bitset is %d\n",host_bs);
		bpf_clone_redirect(skb, skb -> ifindex, 0);
	}

	// bpf_printk("after clone, this id is %d\n", id);
	// Why so verbose? `bpf_clone_redirect` may change buffer — from linux manual. 确实
	data_end = (void *)(long)skb->data_end;
	data     = (void *)(long)skb->data;
	eth = data;
	ip = data + sizeof(struct ethhdr);
	udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MAGIC_LEN;
    // TC_ACT_OK (0) - Signals that the packet should proceed.
	// TC_ACT_SHOT (2) - Signals that the packet should be dropped, no other TC processing should happen.
	if ((void *)(payload + sizeof(__u16)) > data_end) return TC_ACT_SHOT; // drop all the broken msg
	// method = *(__u16 *)payload;
	payload = payload + sizeof(__u16); // skip method
	if ((void *)(payload + sizeof(__u64) + sizeof(__u32) + sizeof(__u32) + sizeof(__u64)) > data_end) return TC_ACT_SHOT;
	payload = payload + sizeof(__u64) + sizeof(__u32) + sizeof(__u32);

	bitset_1 = (__u16 *)payload; 
	payload = payload + sizeof(__u16);
	bitset_2 = *(__u32 *)payload; 
	payload = payload + sizeof(__u32);
	bitset_3 = (__u16 *)payload; 
	payload = payload + sizeof(__u16);
	// get it back
	*bitset_3 = *bitset_1;
	*bitset_1 = 0;

	struct paxos_configure *replicaInfo = bpf_map_lookup_elem(&map_configure, &id);
	if (!replicaInfo) return TC_ACT_SHOT;
	// 改成目标地址
	udp -> dest = replicaInfo -> port;
	udp -> check = 0; // just don't do checksum
	ip -> daddr = replicaInfo -> addr; 
	ip -> check = compute_ip_checksum(ip);
	memcpy(eth -> h_dest, replicaInfo -> eth, ETH_ALEN);

	bpf_printk("sent %d, %d\n",(int)ntohs(*bitset_1),(int)ntohs(*bitset_3));

	// ipadd = ntohl(ip->daddr);
	// bpf_printk("sent:ip is %u.%u.%u",((ipadd)>>24) & 0xFF, ((ipadd)>>16) & 0xFF,((ipadd)>>8) & 0xFF);
	// bpf_printk(".%u:%d \n",(ipadd) & 0xFF,ntohs(udp->dest));
	// bpf_printk("sent:eth is %02X:%02X:%02X",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2]);
	// bpf_printk("%02X:%02X:%02X\n",eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);


	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";