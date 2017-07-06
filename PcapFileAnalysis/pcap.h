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
Pcap�ļ�ͷ24B���ֶ�˵����
Magic��4B��0x1A 2B 3C 4D:������ʾ�ļ��Ŀ�ʼ
Major��2B��0x02 00:��ǰ�ļ���Ҫ�İ汾��
Minor��2B��0x04 00��ǰ�ļ���Ҫ�İ汾��
ThisZone��4B���صı�׼ʱ�䣻ȫ��
SigFigs��4Bʱ����ľ��ȣ�ȫ��
SnapLen��4B���Ĵ洢����
LinkType��4B��·����
�������ͣ�
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
Packet��ͷ��Packet��������ֶ�˵����

Packet��ͷ��
Timestamp��ʱ�����λ����ȷ��seconds
Timestamp��ʱ�����λ����ȷ��microseconds
Caplen����ǰ�������ĳ��ȣ���ץȡ��������֡���ȣ��ɴ˿��Եõ���һ������֡��λ�á�
Len���������ݳ��ȣ�������ʵ������֡�ĳ��ȣ�һ�㲻����caplen����������º�Caplen��ֵ��ȡ�

Packet ���ݣ�
�� Packet��ͨ��������·�������֡���������ݣ����Ⱦ���Caplen��������ȵĺ��棬���ǵ�ǰ
PCAP�ļ��д�ŵ���һ��Packet���ݰ���Ҳ�� ��˵��PCAP�ļ����沢û�й涨�����Packet����
��֮����ʲô����ַ�������һ���������ļ��е���ʼλ�á�������Ҫ����һ��Packet��ȷ����
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