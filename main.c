//
// Created by zeawhy on 2020/6/19.
//
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "errno.h"
#include "string.h"
#include "stdlib.h"
#include "stdio.h"
#include "packet_ip.h"

int main() {
    int sock, n_read, i, j;
    int ip_header_len = IP_HEADER_SIZE, tcp_header_len = TCP_HEADER_SIZE;
    unsigned char buffer[1500];
    struct in_addr des_addr, src_addr;
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror(strerror(errno));
        fprintf(stdout, "create socket error\n");
        exit(0);
    }

    while (1){
    bzero(buffer, sizeof(buffer));
    n_read = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
    if (n_read < (MAC_HEADER_SIZE + ip_header_len + UDP_HEADER_SIZE)) {
        fprintf(stdout, "\n");
    }
    /********************mac header*******************/

    PMAC_HEADER pmacHeader = (MAC_HEADER *) buffer;
    printf("IP ");
    printf("Source Mac:");
    for (i = 0; i < 6; ++i) {
        printf("%02x", pmacHeader->SrcMacAddr[i]);
    }
    printf("  ");
    printf("Dest Mac:");
    for (i = 0; i < 6; ++i) {
        printf("%02x", pmacHeader->DesMacAddr[i]);
    }
    printf("\n");

    /********************ip header**********************/
    PIP_HEADER pipHeader = (PIP_HEADER) (buffer + MAC_HEADER_SIZE);

    int total_len = ntohs(pipHeader->total_len);
    ip_header_len = pipHeader->hdr_len * 4;

    if (ip_header_len > 20 || ip_header_len > 60)
    {
        continue;
    }

    memcpy(&des_addr, &pipHeader->dest_ip, 4);
    memcpy(&src_addr, &pipHeader->source_ip, 4);

    int proto = pipHeader->protocol;
    switch (proto) {
        case IPPROTO_ICMP:
            printf("ICMP\n");
            break;
        case IPPROTO_IGMP:
            printf("IGMP\n");
            break;
        case IPPROTO_IPIP:
            printf("IPIP\n");
            break;
        case IPPROTO_TCP :
            printf("TCP:");
            PTCP_HEADER tcpHeader = (PTCP_HEADER) (buffer + MAC_HEADER_SIZE + ip_header_len);
            tcp_header_len = ((tcpHeader->m_uiHeadOff & 0xf0) >> 4) * 4;
            int data_len = total_len - ip_header_len - tcp_header_len;
            printf("%s.%u-->%s.%u Len:%d\n", inet_ntoa(src_addr), tcpHeader->m_sSourPort, inet_ntoa(des_addr),
                   tcpHeader->m_sDestPort, data_len);
            int tcp_data_index = MAC_HEADER_SIZE + ip_header_len + tcp_header_len;
            unsigned char *p = buffer + tcp_data_index;

            if (data_len > 0) {
                printf("Data:");
                for (int k = 0; k < n_read - tcp_data_index; ++k) {
                    printf("%02x ", p[k]);
                }
                //printf("\n");
                for (int k = 0; k < n_read - tcp_data_index; ++k) {
                    printf("%c", p[k]);
                }
                printf("\n");
            }
            break;
        case IPPROTO_UDP :
            printf("UDP\n");
            break;
        case IPPROTO_RAW :
            printf("RAW\n");
            break;
        default:
            printf("Unkown\n");
    }
    }
    close(sock);
    return 0;
}