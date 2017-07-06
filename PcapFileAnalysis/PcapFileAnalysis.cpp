// PcapFileAnalysis.cpp : 定义控制台应用程序的入口点。
// 
// Created by Dong Zhuoran on 6/4/2017
// Reference on http://www.cnblogs.com/hnrainll/archive/2012/06/17/2552943.html
//

#include "stdafx.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include "pcap.h"

#define PCAP_FILE "TCP_example.pcap"
#define MAX_ETH_FRAME 1514
#define ERROR_FILE_OPEN_FAILED -1
#define ERROR_MEM_ALLOC_FAILED -2
#define ERROR_PCAP_PARSE_FAILED -3

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{

	pcap_file_header pfh;
	packet_header ph;
	int count = 0;
	void * buff = NULL;
	int readSize = 0;
	int ret = 0;

	fstream file;
	file.open(PCAP_FILE, ios::binary | ios::in);
	if (!file.is_open()) {
		return ERROR_FILE_OPEN_FAILED;
	}
	file.read((char*)&pfh, sizeof(pcap_file_header));
	printPcapFileHeader(&pfh);

	buff = (void*)malloc(MAX_ETH_FRAME);
	if (buff == NULL) {
		return ERROR_MEM_ALLOC_FAILED;
	}
	while (file.read((char*)&ph, sizeof(packet_header))) {
		memset(buff, 0, MAX_ETH_FRAME);
		
		printPacketHeader(&ph);

		file.read((char*)buff, ph.capLen);
		printPacketData(buff, ph.capLen);
	}
	file.close();

	// 文件追加测试
	/*file.open("D:/a.txt", ios::out | ios::binary);
	file << "This is the first line.\n";
	file.close();

	file.open("D:/a.txt", ios::out | ios::binary | ios::app);
	file << "This is an appended line.\n";
	file.close();*/
	
	system("Pause");
	return 0;
}

