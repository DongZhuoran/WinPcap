// pcap.cpp
// 
// Created by Dong Zhuoran on 6/4/2017
// Reference on http://www.cnblogs.com/hnrainll/archive/2012/06/17/2552943.html
//
#include "stdafx.h"
#include <winsock2.h>
#pragma comment(lib,"ws2_32.lib")
#include <stdio.h>
#include "pcap.h"

/*
 * 打印.pcap文件头
 */
void printPcapFileHeader(pcap_file_header *pfh) {
	
	if (pfh == NULL) {
		return;
	}

	printf("==========pcap_file_header==========\n"
		"magic: 0x%0x\n"
		"version_major: %u\n"
		"version_minor: %u\n"
		"thisZone: %d\n"
		"sigFigs: %u\n"
		"snapLen: %u\n"
		"linkType: %u\n"
		"==========pcap_file_header==========\n\n\n",
		pfh->magic,
		pfh->major,
		pfh->minor,
		pfh->thisZone,
		pfh->sigFigs,
		pfh->snapLen,
		pfh->linkType);
}

/*
 * 打印packet头
 */
void printPacketHeader(packet_header *ph) {
	
	if (ph == NULL) {
		return;
	}

	printf("============packet_header============\n"
		"timestamp.s: %u\n"
		"timestamp.ms: %u\n"
		"captureLen: %u\n"
		"len: %u\n"
		"============packet_header============\n\n",
		(ph->ts).timestamp_s,
		(ph->ts).timestamp_ms,
		ph->capLen,
		ph->len);
}

/* 
 * 打印packet数据
 */
void printPacketData(void *data, size_t size) {
	u_short iPos = 0;
	if (data == NULL) {
		return;
	}

	printf("========data: 0x%x, len: %u========\n", data, size);

	for (iPos = 0; iPos < size / sizeof(u_short); iPos++) {
		u_short a = ntohs(*(u_short*)data + iPos);
		if (iPos != 0) printf(" ");
		if (iPos != 0 && iPos % 8 == 0) printf("\n");
		if (iPos % 4 == 0) printf(" ");

		printf("%04x", a);
	}

	printf("\n========data: 0x%x, len: %u========\n\n\n", data, size);
}
