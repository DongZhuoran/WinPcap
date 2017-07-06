// pcap.h
// 
// Created by Dong Zhuoran on 6/4/2017
// Reference on http://www.cnblogs.com/hnrainll/archive/2012/06/17/2552943.html
//
#pragma once
#ifndef pcap_h
#define pcap_h

typedef unsigned int bpf_u_int32;
typedef unsigned short u_short;
typedef int bpf_int32;

/*
Pcap文件头24B各字段说明：
Magic：4B：0x1A 2B 3C 4D:用来标示文件的开始
Major：2B，0x02 00:当前文件主要的版本号
Minor：2B，0x04 00当前文件次要的版本号
ThisZone：4B当地的标准时间；全零
SigFigs：4B时间戳的精度；全零
SnapLen：4B最大的存储长度
LinkType：4B链路类型
常用类型：
0            BSD loopback devices, except for later OpenBSD
1            Ethernet, and Linux loopback devices
6            802.5 Token Ring
7            ARCnet
8            SLIP
9            PPP
*/
typedef struct {
	bpf_u_int32 magic;
	u_short major;
	u_short minor;
	bpf_int32 thisZone;
	bpf_u_int32 sigFigs;
	bpf_u_int32 snapLen;
	bpf_u_int32 linkType;
}pcap_file_header;

/*
Packet包头和Packet数据组成字段说明：

Packet包头：
Timestamp：时间戳高位，精确到seconds
Timestamp：时间戳低位，精确到microseconds
Caplen：当前数据区的长度，即抓取到的数据帧长度，由此可以得到下一个数据帧的位置。
Len：离线数据长度：网络中实际数据帧的长度，一般不大于caplen，多数情况下和Caplen数值相等。

Packet 数据：
即 Packet（通常就是链路层的数据帧）具体内容，长度就是Caplen，这个长度的后面，就是当前
PCAP文件中存放的下一个Packet数据包，也就 是说：PCAP文件里面并没有规定捕获的Packet数据
包之间有什么间隔字符串，下一组数据在文件中的起始位置。我们需要靠第一个Packet包确定。
*/
typedef struct {
	bpf_u_int32 timestamp_s;
	bpf_u_int32 timestamp_ms;
}timestamp;

typedef struct {
	timestamp ts;
	bpf_u_int32 capLen;
	bpf_u_int32 len;
}packet_header;

void printPcapFileHeader(pcap_file_header *pfh);
void printPacketHeader(packet_header *ph);
void printPacketData(void *data, size_t size);

#endif