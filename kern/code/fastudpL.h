/*
 *  Software Name : fast-paxos
 *  SPDX-FileCopyrightText: Copyright (c) 2022 Orange
 *  SPDX-License-Identifier: LGPL-2.1-only
 *
 *  This software is distributed under the
 *  GNU Lesser General Public License v2.1 only.
 *
 *  Author: asd123www <wzz@pku.edu.cn> et al.
 * 
 *  ^ 2024 foreeest modify based on this code  
 */

#include <stdint.h>
#include <stdbool.h>

#ifndef _FASTUDPL_H
#define _FASTUDPL_H

#define ETH_ALEN	6		/* Octets in one ethernet addr	 */
#define MAGIC_LEN 2
#define NODE_MAX_NUM 16


typedef enum {
    raftType = 100,
    snapshotType = 200
} Method;


struct paxos_configure {
	__u32 addr; // ipv4.
	__u16 port;
	unsigned char eth[ETH_ALEN];
};

#endif
