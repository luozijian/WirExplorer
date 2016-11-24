/*****************************************************************************
  �ļ�����ResPro.h
  ���ݣ����ݰ��ṹ�����࣬�ṩһЩ���������ݰ��ṹ������������̫������ip����tcp���ȵȡ�
        ����ʹ�õ�WinPcap�����⣬��΢���IphlpApi�⣨���ʹ��vc6.0��Ҫ��������SDK��,
		����ʹ�ø������ɵĿ�ִ���ļ�ʱ����Ҫ�������װWinPcap�����dll,
		��Ҫ������ļ���Ҫ��ȷ����winpcap·����iphlpapi·����
		����ĳЩ�ṹ���δ�����ʱ����ѡTool-Options-Include�����ص���SDK��·������vc98·��֮ǰ��
		�������Խ�����������
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
//����dll�ļ���������
typedef void (*PCAP_breakloop)(pcap_t*);

public:
	//����Iphlpapi�⺯��
	MIB_IPADDRTABLE *m_pIPAddrTable;//ip��ַ�б�
	MIB_IFTABLE     *m_pIfTable;//�豸�ӿڱ�

	//����WinPcap�⺯��
	pcap_t          *m_hpcap;
	pcap_if_t       *m_alldevs;
	
	char            m_errbuf[PCAP_ERRBUF_SIZE];
	bool			m_threadCap;//�Ƿ�������ץ���̣߳����û����������ô�ڵ���pcap_breakloop��pcap_close����ִ���
private:
	HINSTANCE       m_hwpcap;//�ļ����
	PCAP_breakloop  m_pFunBreakloop;

	//���ݰ����˹���
    struct bpf_program m_filter;//���ɹ���ṹ
    char               m_filterStr[MAX_FILTER_SIZE];//���˹����ַ���
	pcap_dumper_t     *m_pdumpfile;

public:
	CResPro();
	~CResPro();
	/*
	 *ע�⣺�ⲿָ��ptable��Ҫ�ں�������ʹ��free(ptable)��ptable��ָ����ڴ��ɺ����ڲ��ͷš�
	 *����ⲿ������ͼ�ͷ��ڴ棬��ô����һ�ε��øú���ʱ�������ظ��ͷ�ͬһ���ڴ浼���쳣��
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