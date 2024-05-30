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

/*
unmarshal the msg,and get:
    To
    Type
*/
static inline __u32 UnmarshalType(char* payload, void* data_end){
    __u8 b = 0;
    __u64 wire = 0;
    __u32 shift = 0;
    __u32 fieldNum = 0;
    __u32 wireType = 0;

    if (payload + sizeof(__u8) > data_end) return -1;
    b = *payload; // 0xa
    payload = payload + sizeof(__u8);
    wire |= ((__u64)b & 0x7F);
    fieldNum = (__u32)(wire>>3); // 1
    wireType = (__u32)(wire&0x7);  // 2

    __u32 msgLen = 0; // how long is a Message that is marshalled
    #pragma clang loop unroll(full)
    for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
        shift = i * 7;
        if (payload + sizeof(__u8) > data_end) return -1;
        b = *payload;
        payload = payload + sizeof(__u8);
        msgLen |= ((__u64)b & 0x7F) << shift;
        if(b < 0x80){ // the Varint is over
			break;
		}
    }

    if (payload + sizeof(__u8) > data_end) return -1;
    b = *payload; // 0x8
    payload = payload + sizeof(__u8);
    wire |= ((__u64)b & 0x7F);
    fieldNum = (__u32)(wire>>3); // 1
    wireType = (__u32)(wire&0x7);  // 0

    __u32 Type = 0; // Message Type
    #pragma clang loop unroll(full)
    for(int i=0;i<20;i++){
        shift = i * 7;
        if (payload + sizeof(__u8) > data_end) return -1;
        b = *payload;
        payload = payload + sizeof(__u8);
        Type |= ((__u64)b & 0x7F) << shift;
        if(b < 0x80){
			break;
		}
    }

    return Type;
}

static inline __u32 UnmarshalTo(__u64* To, char* payload, void* data_end){
    __u8 b = 0;
    __u64 wire = 0;
    __u32 shift = 0;
    __u32 fieldNum = 0;
    __u32 wireType = 0;

    __u32 lenTo = 0;

    #pragma clang loop unroll(full)
    for(int i=0;i<NODE_MAX_NUM;i++){
        if (payload + sizeof(__u8) > data_end) return -1;
        b = *payload; // 0x12
        payload = payload + sizeof(__u8);
        wire |= ((__u64)b & 0x7F);
        fieldNum = (__u32)(wire>>3); // 2
        wireType = (__u32)(wire&0x7);  // 2
        if(fieldNum != 2) break; // 0x18 -> next field
        lenTo++;

        __u32 msgLen = 0; // how long is a To[i] that is marshalled
        #pragma clang loop unroll(full)
        for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
            shift = i * 7;
            if (payload + sizeof(__u8) > data_end) return -1;
            b = *payload;
            payload = payload + sizeof(__u8);
            msgLen |= ((__u64)b & 0x7F) << shift;
            if(b < 0x80){ // the Varint is over
                break;
            }
        }

        __u32 Toi = 0; // how long is a To[i] that is marshalled
        #pragma clang loop unroll(full)
        for(int i=0;i<20;i++){ // 20 is just a number that is big eunogh
            shift = i * 7;
            if (payload + sizeof(__u8) > data_end) return -1;
            b = *payload;
            payload = payload + sizeof(__u8);
            Toi |= ((__u64)b & 0x7F) << shift;
            if(b < 0x80){ // the Varint is over
                break;
            }
        }
        To[i] = Toi;

    }

    return lenTo;    
}

/*
stop a message from functions below:
    func (r *raft) sendHeartbeatMessage
    func (r *raft) sendReplicateMessage(to uint64) -> func (r *raft) makeReplicateMessage
*/
SEC("tc")
int FastBroadCast_main(struct __sk_buff *skb) {
	void *data_end = (void *)(long)skb->data_end;
	void *data     = (void *)(long)skb->data;
	struct ethhdr *eth = data;
	struct iphdr *ip = data + sizeof(struct ethhdr);
	struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	char *payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);

	if (ip + 1 > data_end) return TC_ACT_OK;
	if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;
	if (udp + 1 > data_end) return TC_ACT_OK;
	if (udp -> source != htons(12345)) return TC_ACT_OK; // port 也先12345

    /* ---parse appl head---
    Electorde's Appl: magic -- typelen -- typestr -- FAST_PAXOS_DATA_LEN
	Dragonboat's Appl: magic(2byte) -- requestHeader = method uint16 + size uint64
	+ checksum uint32 +crc uint32 -- FAST_DATA_LEN */
	if (payload + MAGIC_LEN > data_end) return TC_ACT_OK; // don't have magic bits...
    // net use:bigEidian & raft magic: magicNumber = [2]byte{0xAE, 0x7D}
    if (payload[0] != 0x7D || payload[1] != 0xAE) return TC_ACT_OK;
	payload = payload + MAGIC_LEN;

	if (payload + sizeof(__u16) > data_end) return TC_ACT_OK; 
	__u16* method = *(__u16 *)payload; // it's a pointer, because I will modify it
    // the low 8 bit indicate type(beacause 100 and 200 is less then 255), but 
    // high 8 bit is used to indicate the destination of the msg
    __u16 methodC = (*method) & (1 << 8 - 1);
    if(methodC != raftType) return TC_ACT_OK;
	payload = payload + sizeof(__u16);

    if (payload + sizeof(__u64) > data_end) return TC_ACT_OK; 
	__u64 size = *(__u64 *)payload;
    // check it ? what is size?
	payload = payload + sizeof(__u64);

    if (payload + sizeof(__u32) > data_end) return TC_ACT_OK; 
	__u32 checksum = *(__u32 *)payload;
    // check it ?don't do this ,I have modify `method`,or we will do IEEECheckSum
	payload = payload + sizeof(__u32);

    if (payload + sizeof(__u32) > data_end) return TC_ACT_OK; 
	__u32 crc = *(__u32 *)payload;
    // check it ?
	payload = payload + sizeof(__u32);

    /* ---parse the user data--- */
    __u32 Type = UnmarshalType(payload, data_end);
    __u32 lenTo = 0;
    __u64 To[NODE_MAX_NUM];
    lenTo = UnmarshalTo(To, payload, data_end);

    // Type: pb.Replicate pb.Heartbeat
    if(Type != Replicate && Type != Heartbeat) return TC_ACT_OK; 
    // we do not use bitset for now

    /* do the clone */
    __u32 id = 0;
    if((*method)>>8 == 0){ // the boardcast msg
        for(int i=1;i<lenTo;i++){
            id = To[i];
            *method = (*method) | (__u16)(id << 8);
            bpf_clone_redirect(skb, skb -> ifindex, 0);
        }
        id = To[0];
    }else{ // the cloned msg
        id = (*method) >> 8;
    }

	// Why so verbose? `bpf_clone_redirect` may change buffer — from linux manual. 确实
	data_end = (void *)(long)skb->data_end;
	data     = (void *)(long)skb->data;
	eth = data;
	ip = data + sizeof(struct ethhdr);
	udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
	payload = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr) + MAGIC_LEN;
    // TC_ACT_OK (0) - Signals that the packet should proceed.
	// TC_ACT_SHOT (2) - Signals that the packet should be dropped, no other TC processing should happen.
	if (payload + sizeof(__u16) > data_end) return TC_ACT_SHOT; // drop all the broken msg
	method = payload;
	payload = payload + sizeof(__u16);
	if (payload + sizeof(__u64) + sizeof(__u32) + sizeof(__u32) > data_end) return TC_ACT_SHOT;

    *method = (*method) & (1 << 8 - 1);
	struct paxos_configure *replicaInfo = bpf_map_lookup_elem(&map_configure, &id);
	if (!replicaInfo) return TC_ACT_SHOT;
	// 改成目标地址
	udp -> dest = replicaInfo -> port;
	udp -> check = 0; // just don't do checksum
	ip -> daddr = replicaInfo -> addr;
	ip -> check = compute_ip_checksum(ip);
	memcpy(eth -> h_dest, replicaInfo -> eth, ETH_ALEN);

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";