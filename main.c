#include <winsock2.h>
#include <Ws2tcpip.h>		// inet_ntop()
#include <windows.h>
#include <stdio.h>		// printf()
#include <stdint.h>		// uintN_t
#include <stdlib.h>
#include <string.h>
#include "windivert.h"

#define MAXBUF			0xFFFF
#define IPv4			4
#define PROTOCOL_TCP		6
#define PORT_HTTP		80

int main() {
	uint16_t priority = 0;
	HANDLE handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, priority, 0);
	if (handle == INVALID_HANDLE_VALUE)	{
		fprintf(stderr, "error: failed to open the WinDivert device\n");
		return 1;
	}
	while(TRUE) {
		uint8_t packet[MAXBUF];
		uint32_t packet_len;
		WINDIVERT_ADDRESS addr;
		if(!WinDivertRecv(handle, packet, sizeof(packet), &addr, &packet_len)) {
			fprintf(stderr, "warning: failed to read packet\n");
			continue;
		}

		WINDIVERT_IPHDR *ip = (WINDIVERT_IPHDR*)packet;
		if(ip->Version==IPv4 && ip->Protocol==PROTOCOL_TCP) {
			WINDIVERT_TCPHDR *tcp = (WINDIVERT_TCPHDR*)(packet+(ip->HdrLength)*4);
			if(ntohs(tcp->SrcPort)==PORT_HTTP || ntohs(tcp->DstPort)==PORT_HTTP) {
				uint8_t ip_buf[INET_ADDRSTRLEN];
				printf("\nSource IP\t: %s\n", inet_ntop(AF_INET, &ip->SrcAddr, ip_buf, INET_ADDRSTRLEN));
				printf("Destination IP\t: %s\n", inet_ntop(AF_INET, &ip->DstAddr, ip_buf, INET_ADDRSTRLEN));
				printf("Source Port\t: %u\n", ntohs(tcp->SrcPort));
				printf("Destination Port: %u\n", ntohs(tcp->DstPort));
				continue;
			}
		}

		if(!WinDivertSend(handle, packet, packet_len, &addr, NULL)) {
			fprintf(stderr, "warning: failed to send\n");
		}
	}
}
