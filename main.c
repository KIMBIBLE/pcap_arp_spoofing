#include <pcap/pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

//const uint64_t BUF_LEN = 1024;
//const uint64_t IP_STRING_BUF_LEN = 6;
//const uint64_t MAC_STRING_BUF_LEN = 18;

#define BUF_LEN 1024
#define IP_STRING_BUF_LEN 16
#define MAC_STRING_BUF_LEN 18

int getLoalAddrInfo(char *ipBuf, char *macBuf);
void errorHandling(char * message);


int main(int argc, char * argv[])
{
	struct in_addr addr;	// for binary type ip addr

	if(argc != 2){
		fprintf(stdout, "Usage : %s [target IP]\n", argv[0]);
		exit(1);
	}

	// convert string type target address to binary type 
	inet_pton(AF_INET, argv[1], &addr.s_addr);

	char localIpStrBuf[IP_STRING_BUF_LEN] = {0, };
	char localMacStrBuf[MAC_STRING_BUF_LEN] = {0, };	
	if(!getLoalAddrInfo(localIpStrBuf, localMacStrBuf))
		errorHandling("ERROR OCCURED IN getLocalAddrInfo()\n");



	return 0;
}

int getLoalAddrInfo(char *ipBuf, char *macBuf)
{
	FILE * fp;

	/*	[start] : get local ip address	*/
	// get local ip addr in *.*.*.* format
	fp = popen("ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}'", "r");
	if(fp == NULL)
		errorHandling("FILE OPEN ERROR IN getLocalAddrInfo (get ip addr)\n");

	if(fgets(ipBuf, IP_STRING_BUF_LEN, fp) == NULL)
		return 0;	// return error code '0' if read error

	pclose(fp);
	/*	[end] : get local ip address	*/

	/*	[start] : get local mac address	*/
	// get local mac addr in *:*:*:*:*:* format
	fp = popen("ifconfig eth0 | grep HWaddr | awk '{print $5}'", "r");
	if(fp == NULL)
		errorHandling("FILE OPEN ERROR IN getLocalAddrInfo (get mac addr)\n");
	if(fgets(macBuf, MAC_STRING_BUF_LEN, fp) == NULL)
		return 0;	// return error code '0' if read error

	pclose(fp);
	/*	[end] : get local mac address	*/

	printf("[*] local IP addr : %s", ipBuf);
	printf("[*] local MAC addr : %s\n", macBuf);

	return 1;
}


void errorHandling(char * message)
{
	fprintf(stdout, "%s", message);
	exit(1);
}


