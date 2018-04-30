#include <winsock2.h>
#include <Ws2tcpip.h>	// inet_ntop()
#include <windows.h>
#include <stdio.h>		// printf()
#include <stdint.h>		// uintN_t
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF			0xFFFF
#define IPv4			0x0800
#define PROTOCOL_TCP	0x06

int main() {
	typedef struct
	{
		WINDIVERT_IPHDR ip;
		WINDIVERT_TCPHDR tcp;
	} TCPPACKET, *PTCPPACKET;

	uint16_t priority = 0;
	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)	{
		fprintf(stderr, "error: failed to open the WinDivert device\n");
		return 1;
	}
	while(TRUE) {
		uint8_t packet[MAXBUF];
		uint32_t packet_len;
		WINDIVERT_ADDRESS recv_addr, send_addr;
		if(!WinDivertRecv(handle, packet, sizeof(packet), &recv_addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}
		PTCPPACKET blocked_pkt = (TCPPACKET*)packet;
		if( ntohs(blocked_pkt->ip.Version)==IPv4 && ntohs(blocked_pkt->ip.Protocol)==PROTOCOL_TCP &&
			ntohs(blocked_pkt->tcp.SrcPort)==80 || ntohs(blocked_pkt->tcp.DstPort)==80) {
			uint8_t ip_buf[INET_ADDRSTRLEN];
			printf("\nSource IP\t: %s\n", inet_ntop(AF_INET, &blocked_pkt->ip.SrcAddr, ip_buf, INET_ADDRSTRLEN));
			printf("Destination IP\t: %s\n", inet_ntop(AF_INET, &blocked_pkt->ip.DstAddr, ip_buf, INET_ADDRSTRLEN));
			printf("Source Port\t: %u\n", ntohs(blocked_pkt->tcp.SrcPort));
			printf("Destination Port: %u\n", ntohs(blocked_pkt->tcp.DstPort));
			continue;
		}

		if(!WinDivertSend(handle, packet, packet_len, &send_addr, NULL)) {
			fprintf(stderr, "warning: failed to send\n");
		}
	}
}