/*
 *  Software Name : fast-paxos
 *  SPDX-FileCopyrightText: Copyright (c) 2022 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: asd123www <wzz@pku.edu.cn> et al.
 */
// can be include ?
#include <stdint.h>
#include <stdbool.h>

#ifndef _FAST_COMMON_H
#define _FAST_COMMON_H

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */

#define CLUSTER_SIZE 3 // need 
#define FAST_REPLICA_MAX 100 // max # of replicas.
#define NONFRAG_MAGIC 0x20050318 // 用于区分碎片信息
#define FRAG_MAGIC 0x20101010


#define MAGIC_LEN 2
#define REQUEST_TYPE_LEN 33
#define PREPARE_TYPE_LEN 33
#define PREPAREOK_TYPE_LEN 35
#define MYPREPAREOK_TYPE_LEN 24

#define FAST_PAXOS_DATA_LEN 12
#define BROADCAST_SIGN_BIT (1<<31)
#define QUORUM_SIZE ((CLUSTER_SIZE + 1) >> 1)
#define QUORUM_BITSET_ENTRY 1024 // must be 2^t

#define NODE_MAX_NUM 32

// very complex msg, can not parse the whole

typedef enum {
    Replicate = 12,
    ReplicateResp = 13,
	Heartbeat = 17,
	HeartbeatResp = 18
} MessageType;

typedef enum {
    raftType = 100,
    snapshotType = 200
} Method;

typedef struct {
} Entry;
typedef struct {
} Snapshot;

typedef struct {
    MessageType Type;
    uint64_t* To;           // 指向目标 Replica 的动态数组
    size_t ToCount;         // 动态数组的长度
    uint64_t From;
    uint64_t ShardID;
    uint64_t Term;
    uint64_t LogTerm;
    uint64_t LogIndex;
    uint64_t Commit;
    bool Reject;
    uint64_t Hint;
    Entry* Entries;         // 指向 Entry 动态数组
    size_t EntriesCount;    // 动态数组的长度
    Snapshot Snapshot;
    uint64_t HintHigh;
} MY_Message;


enum ReplicaStatus {
    STATUS_NORMAL,
    STATUS_VIEW_CHANGE,
    STATUS_RECOVERING
};

// XDP 广播类型

enum {
	FAST_PROG_XDP_HANDLE_PREPARE = 0,
	FAST_PROG_XDP_HANDLE_REQUEST,
	FAST_PROG_XDP_HANDLE_PREPAREOK,
    FAST_PROG_XDP_WRITE_BUFFER,
	FAST_PROG_XDP_PREPARE_REPLY,

	FAST_PROG_XDP_MAX
};

// TC 广播类型

enum {
	FAST_PROG_TC_BROADCAST = 0,

	FAST_PROG_TC_MAX
};

struct paxos_configure {
	__u32 addr; // ipv4.
	__u16 port;
	char eth[ETH_ALEN];
};

#endif
