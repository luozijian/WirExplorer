/*****************************************************************************
  文件名：ResPro.h
  内容：数据包结构解析类，提供一些常见的数据包结构解析，包括以太网包，ip包，tcp包等等。
        该类使用到WinPcap开发库，和微软的IphlpApi库（如果使用vc6.0需要下载最新SDK）,
		运行使用该类生成的可执行文件时候需要计算机安装WinPcap的相关dll,
		需要编译该文件需要正确配置winpcap路径和iphlpapi路径，
		遇到某些结构或宏未定义的时候，首选Tool-Options-Include把下载的新SDK包路径放在vc98路径之前，
		这样可以解决大多数问题
*****************************************************************************/


#ifndef _RES_PRO_H_
#define _RES_PRO_H_

#include "Winsock2.h"
#include "pcap.h"
#include "iphlpapi.h"
#include "ProHeader.h"

#pragma comment(lib,"wpcap.lib")
#pragma comment(lib,"iphlpapi.lib")
#pragma comment(lib,"Ws2_32.lib")

class CResPro
{
#define MAX_FILTER_SIZE 256
//调用dll文件函数定义
typedef void (*PCAP_breakloop)(pcap_t*);

public:
	//调用Iphlpapi库函数
	MIB_IPADDRTABLE *m_pIPAddrTable;//ip地址列表
	MIB_IFTABLE     *m_pIfTable;//设备接口表

	//调用WinPcap库函数
	pcap_t          *m_hpcap;
	pcap_if_t       *m_alldevs;
	
	char            m_errbuf[PCAP_ERRBUF_SIZE];
	bool			m_threadCap;//是否启动了抓包线程，如果没有启动，那么在调用pcap_breakloop和pcap_close会出现错误
private:
	HINSTANCE       m_hwpcap;//文件句柄
	PCAP_breakloop  m_pFunBreakloop;

	//数据包过滤规则
    struct bpf_program m_filter;//规律规则结构
    char               m_filterStr[MAX_FILTER_SIZE];//过滤规则字符串
	pcap_dumper_t     *m_pdumpfile;

public:
	CResPro();
	~CResPro();
	/*
	 *注意：外部指针ptable不要在函数外面使用free(ptable)，ptable所指向的内存由函数内部释放。
	 *如果外部函数企图释放内存，那么在下一次调用该函数时候会出现重复释放同一块内存导致异常。
	 */
	int GetIPAddrList(MIB_IPADDRTABLE **ptable);
	int GetIfList(MIB_IFTABLE **ptable);
	int FindAllDevs();
	int OpenDev(char *devName);
	int ConfigFilter(char *devName,char *filterStr);
	int CapLoop(void * callbackfun);
	void BreakLoop();
	void CloseDev();
protected:
private:

};
#endif