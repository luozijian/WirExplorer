//////////////////////////////////////////////////////////////////////////
//CResPro����Դ���

#include "stdAfx.h"
#include "ResPro.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	CResPro resPro;
	
	//Ѱ���豸�б�
	int devNum;       //�豸����Ŀ
	pcap_if_t *dev;   //�豸ָ��
	in_addr *addr;    //����ת��ý��
	int i = 0;        
	//�豸��ip��ַ���������룬�����ַ����Ϊ����ʹ����Ϊ���㣬�ṹ��in_addr������λ����
	u_long *ipAddr;
	u_long *netmask;
	u_long  netIP;

	devNum = resPro.FindAllDevs();//��ȡ�豸�б�
	for(dev = resPro.m_alldevs;dev;dev = dev->next) {
		printf("---------------------  �豸  %d  ---------------------\n",++i);
		printf("DevName.............:%s\n",dev->name);          //�豸���֣����������ģ�
		printf("Description.........:%s\n\n",dev->description); //�豸���������˿��ģ�
		/*
		 * struct sockaddr -->struct sockaddr_in
		 * sa_family          sin_family
		 * sa_data[14]        sin_port�������sa_data[2]�����ƶ��������ֽڣ�,������Ūһ��sockaddr_in���м�ת����ͷ��
		 *                    in_addr sin_addr��4�ֽڣ�
		 *                    sin_zero[8]
		 */
		//  ��ȡip��ַ
		addr   = (in_addr*)(&dev->addresses->addr->sa_data[2]);
		ipAddr = (u_long*)addr;
		printf("IP..................:\t%s\n",inet_ntoa(*addr));

		//  ��ȡ��������
		addr    = (in_addr*)(&dev->addresses->netmask->sa_data[2]);
		netmask = (u_long*)addr;
		printf("NetMask.............:\t%s\n",inet_ntoa(*addr));

		//  ���������ַ
		netIP   = (u_long)(*ipAddr) & (u_long)(*netmask);
		addr = (in_addr*)&netIP;
		printf("NetIP...............:\t%s\n\n",inet_ntoa(*addr));  
	}

	//ѡ���豸
	int chDev=1;

	for(dev = resPro.m_alldevs;--chDev;dev = dev->next);

	resPro.OpenDev(dev->name);        //��ָ���豸
	resPro.ConfigFilter(dev->name,"");//��һ��ȥ����ʾ�����й���
	resPro.CapLoop(dev->name);        //��ʼѭ��
	return 0;
}
