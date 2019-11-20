#include <stdio.h>

#include <string.h>

#include <pcap.h>

#include <net/ethernet.h>

#include <arpa/inet.h>

#include <libnet.h>

#include <sys/socket.h>

#include <sys/ioctl.h>

#include <linux/if.h>

#include <netdb.h>

 

void usage() {

	printf("syntax: tcp_block <interface> <host>\n");

	printf("sample: tcp_block wlan0 test.gilgil.net\n");

 

}

 

char bad_site[100] = { "Host: " };

 

struct tcp_header {

	uint8_t eth_dmac[6];             /* ether destination (MAC) Address (6 Byte) */

	uint8_t eth_smac[6];             /* ether source (MAC) Address (6 Byte)*/

	uint16_t eth_type;               /* ether type (2 Byte) */

	uint8_t ip_version;             /* IP version (1 byte) */

	uint8_t ip_tos;					  /* TOS (1 Byte) */

	uint16_t total_len;				/* Total length (2 Byte) */

	uint16_t ip_identifier;            /* Fragment Identifier  (2 Byte) */

	uint32_t ip_etc;                /* (4 Byte) */

	uint16_t header_check;          /* Header Checksum (MAC) Address (2 Byte) */

	uint8_t srd_addr[4];          /* Sender Protocol(IP) Address (4 Byte) */

	uint8_t sdt_addr[4];          /* Target Protocol(IP) Address (4 Byte) */

	uint16_t src_port;

	uint16_t dst_port;

	uint16_t seq_fro;

	uint16_t seq_end;

	uint16_t ack_fro;

	uint16_t ack_end;

	uint8_t tcp_len;

	uint8_t flag;

	uint16_t wnd_size;

	uint16_t checksum;

	uint16_t urgent_point;

};

struct captured_packet {

	tcp_header eth;

	uint32_t tcp_data[100];

};

 

tcp_header make_packet(uint8_t *dmac, uint8_t *smac, uint8_t *si, uint8_t *di, uint16_t sp, uint16_t dp, int seq, int ack, char flag) {

	tcp_header ret;

	memcpy(ret.eth_dmac, dmac, sizeof(ret.eth_dmac));

	memcpy(ret.eth_smac, smac, sizeof(ret.eth_smac));  

	ret.eth_type = 8;              

	ret.ip_version = 69;           

	ret.ip_tos = 0;

	ret.total_len = htons(40);

	ret.ip_identifier = 0;        

	ret.ip_etc = 101187648;

	memcpy(ret.srd_addr, si, sizeof(ret.srd_addr));

	memcpy(ret.sdt_addr, di, sizeof(ret.sdt_addr));

	ret.src_port = sp;

	ret.dst_port = dp;

	ret.seq_fro = seq >> 16;

	ret.seq_end = seq;

	ret.ack_fro = ack >> 16;

	ret.ack_end = ack;

	ret.tcp_len = 80;

	ret.flag = flag;

	ret.wnd_size = 1000;

	ret.urgent_point = 0;

	ret.checksum = 0;

	int ipcheck = 69 * 256 + 40 + 0 + 16384 + 32774 + 256 * si[0] + si[1] + 256 * si[2] + si[3] + 256 * di[0] + di[1] + 256 * di[2] + di[3];

	ret.header_check = ipcheck % 65535;

	int tcpcheck = 256 * si[0] + si[1] + 256 * si[2] + si[3] + 256 * di[0] + di[1] + 256 * di[2] + di[3] + 6 + 20;

	for (int i = 0;i < 10;i++) {

		tcpcheck += ret.srd_addr[i * 2] * 256 + ret.srd_addr[i * 2 + 1];

	}

	ret.checksum = tcpcheck % 65535;

}

 

int main(int argc, char* argv[]) {

 

	int ip_length;

	int tcp_length;

	int data_length;

	int total_length;

	char lowbit = 0x0f;

	if (argc != 3) {

		usage();

		return -1;

	}

	strcat(bad_site, argv[2]);

	captured_packet cap_pac;

	u_char http_data[100];

	char* dev = argv[1];

	char errbuf[PCAP_ERRBUF_SIZE];

	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) {

		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);

		return -1;

	}

	while (true) {

		struct pcap_pkthdr* header;

		const u_char* packet;

		int res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;

		if (res == -1 || res == -2) break;

		printf("%u bytes captured\n", header->caplen);

		

		memcpy(&cap_pac, packet, sizeof(cap_pac));

		

		if (cap_pac.eth.eth_type == 8 && cap_pac.eth.ip_version == 69 && (cap_pac.eth.ip_etc >> 24) == 6 && cap_pac.eth.dst_port == 20480) {

			

			memcpy(http_data, packet, sizeof(http_data));

			int http_start = 14 + 20 + cap_pac.eth.tcp_len /4 + 16;

			int tot_len = 14+ ntohs(cap_pac.eth.total_len);


			if(tot_len>http_start+strlen(bad_site))

			{	

				int match=0;

				for(int i=0;i<strlen(bad_site);i++){

					if(http_data[http_start+i]==bad_site[i])

						match++;	

				}

				if (match == strlen(bad_site))

				{

					int next_seq = cap_pac.eth.seq_fro * 65536 + cap_pac.eth.seq_end + cap_pac.eth.total_len - 20 - cap_pac.eth.tcp_len / 4 + 1;

					int next_ack = cap_pac.eth.ack_fro * 65536 + cap_pac.eth.ack_end;

					tcp_header f1 = make_packet(cap_pac.eth.eth_dmac, cap_pac.eth.eth_smac, cap_pac.eth.srd_addr, cap_pac.eth.sdt_addr, cap_pac.eth.src_port, cap_pac.eth.dst_port, next_seq, next_ack, 4);

					tcp_header f2 = make_packet(cap_pac.eth.eth_dmac, cap_pac.eth.eth_smac, cap_pac.eth.srd_addr, cap_pac.eth.sdt_addr, cap_pac.eth.src_port, cap_pac.eth.dst_port, next_seq, next_ack, 1);

					tcp_header b1 = make_packet(cap_pac.eth.eth_smac, cap_pac.eth.eth_dmac, cap_pac.eth.sdt_addr, cap_pac.eth.srd_addr, cap_pac.eth.dst_port, cap_pac.eth.src_port, next_ack, next_seq, 4);

					tcp_header b2 = make_packet(cap_pac.eth.eth_smac, cap_pac.eth.eth_dmac, cap_pac.eth.sdt_addr, cap_pac.eth.srd_addr, cap_pac.eth.dst_port, cap_pac.eth.src_port, next_ack, next_seq, 1);

 

					// 아래 코드에 f1을 f2로 바꾸거나 b1을 b2로 바꾸기 가능

					if (pcap_sendpacket(handle, (const uint8_t*)&f1, (sizeof(f1))) != 0)

					{

						printf("pcap_sendpacket error\n");

					}

					else

					{

						printf("packet send\n");

					}

					if (pcap_sendpacket(handle, (const uint8_t*)&b1, (sizeof(f1))) != 0)

					{

						printf("pcap_sendpacket error\n");

					}

					else

					{

						printf("packet send\n");

					}

				}

			}

		}

	}

	pcap_close(handle);

	return 0;

 

}
