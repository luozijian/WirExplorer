//////////////////////////////////////////////////////////////////////////
//CResPro类测试代码

#include "stdAfx.h"
#include "ResPro.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
	CResPro resPro;
	
	//寻找设备列表
	int devNum;       //设备总数目
	pcap_if_t *dev;   //设备指针
	in_addr *addr;    //数据转换媒介
	int i = 0;        
	//设备的ip地址、子网掩码，网络地址，因为下面使用了为运算，结构体in_addr不允许位运算
	u_long *ipAddr;
	u_long *netmask;
	u_long  netIP;

	devNum = resPro.FindAllDevs();//获取设备列表
	for(dev = resPro.m_alldevs;dev;dev = dev->next) {
		printf("---------------------  设备  %d  ---------------------\n",++i);
		printf("DevName.............:%s\n",dev->name);          //设备名字（给机器看的）
		printf("Description.........:%s\n\n",dev->description); //设备描述（给人看的）
		/*
		 * struct sockaddr -->struct sockaddr_in
		 * sa_family          sin_family
		 * sa_data[14]        sin_port（下面的sa_data[2]就是移动这两个字节）,懒得在弄一个sockaddr_in做中间转换，头晕
		 *                    in_addr sin_addr（4字节）
		 *                    sin_zero[8]
		 */
		//  获取ip地址
		addr   = (in_addr*)(&dev->addresses->addr->sa_data[2]);
		ipAddr = (u_long*)addr;
		printf("IP..................:\t%s\n",inet_ntoa(*addr));

		//  获取网络掩码
		addr    = (in_addr*)(&dev->addresses->netmask->sa_data[2]);
		netmask = (u_long*)addr;
		printf("NetMask.............:\t%s\n",inet_ntoa(*addr));

		//  计算网络地址
		netIP   = (u_long)(*ipAddr) & (u_long)(*netmask);
		addr = (in_addr*)&netIP;
		printf("NetIP...............:\t%s\n\n",inet_ntoa(*addr));  
	}

	//选择设备
	int chDev=1;

	for(dev = resPro.m_alldevs;--chDev;dev = dev->next);

	resPro.OpenDev(dev->name);        //打开指定设备
	resPro.ConfigFilter(dev->name,"");//这一句去掉表示不进行过滤
	resPro.CapLoop(dev->name);        //开始循环
	return 0;
}
