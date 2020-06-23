//
// Created by zhangy on 2020/6/23.
//

#ifndef CPCAP_PACKETCAP_H
#define CPCAP_PACKETCAP_H

#include "packet_ip.h"

#include "pcap/bpf.h"
#include "pcap/pcap.h"
#include "string.h"

#include "iostream"
#include "string"

using namespace std;

class Packetcap {
    char dev[32];
    pcap_t *handle;        /* Session handle */
    char errbuf[PCAP_ERRBUF_SIZE];    /* Error string */
    struct bpf_program fp;        /* The compiled filter expression */
    char filter_exp[256];    /* The filter expression */
    bpf_u_int32 mask;        /* The netmask of our sniffing device */
    bpf_u_int32 net;        /* The IP of our sniffing device */
public:
    Packetcap() {
        memset(dev, 0, sizeof(dev));
        strcpy(filter_exp, "port 23");/* The filter expression */
        memset(errbuf, 0, sizeof(errbuf));
    }

    ~Packetcap() {}

    bool init(const char *dev) {
        bool ret = true;
        if (dev != NULL)
            strcpy(this->dev, dev);
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
            fprintf(stderr, "Can't get netmask for device %s\n", dev);
            net = 0;
            mask = 0;
            ret = false;
        }
        return ret;
    }

/*
 * 获取一个包捕获句柄
 */
    int open() {
        int ret = 0;
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
            return (2);
        }
        return ret;
    }

    int close() {
        pcap_close(handle);
    }

    const char *getDev() const {
        return dev;
    }

    pcap_t *getHandle() const {
        return handle;
    }

    void setHandle(pcap_t *handle) {
        Packetcap::handle = handle;
    }

    const char *getErrbuf() const {
        return errbuf;
    }

    const bpf_program &getFp() const {
        return fp;
    }

    void setFp(const bpf_program &fp) {
        Packetcap::fp = fp;
    }

    const char *getFilterExp() const {
        return filter_exp;
    }

    void setFilterExp(const char *filterExp) {
        strcpy(this->filter_exp, filterExp);
    }

    bpf_u_int32 getMask() const {
        return mask;
    }

    void setMask(bpf_u_int32 mask) {
        Packetcap::mask = mask;
    }

    bpf_u_int32 getNet() const {
        return net;
    }

    void setNet(bpf_u_int32 net) {
        Packetcap::net = net;
    }

    int setFilter() {
        int ret = 0;
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
            return (2);
        }
        return ret;
    }

    const u_char *getNextpacket() {
        struct pcap_pkthdr header;    /* The header that pcap gives us */
        const u_char *packet;        /* The actual packet */
        packet = pcap_next(handle, &header);
        if (packet != NULL) {
            printf("len=%d  caplen=%d  sec=%ld usec=%ld\n", header.len, header.caplen, header.ts.tv_sec,
                   header.ts.tv_usec);
        }
        parsePacket(packet, &header);
        return packet;
    }

    static int packetHandle(u_char *args, const struct pcap_pkthdr *header,
                            const u_char *packet) {
        parsePacket(packet, header);
        return 0;
    }


    int getPacketloop() {
        int ret = pcap_loop(handle, 1, reinterpret_cast<pcap_handler>(packetHandle), NULL);
        return ret;
    }

    static void parsePacket(const u_char *packet, const struct pcap_pkthdr *header) {
        int i;
        int ip_header_len = IP_HEADER_SIZE, tcp_header_len = TCP_HEADER_SIZE;
        const unsigned char *buffer = packet;
        struct in_addr des_addr, src_addr;
        int n_read = header->caplen;
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

        if (ip_header_len > 20 || ip_header_len > 60) {
            return;
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
            case IPPROTO_TCP : {
                printf("TCP:");
                PTCP_HEADER tcpHeader = (PTCP_HEADER) (buffer + MAC_HEADER_SIZE + ip_header_len);
                tcp_header_len = ((tcpHeader->m_uiHeadOff & 0xf0) >> 4) * 4;
                int data_len = total_len - ip_header_len - tcp_header_len;
                printf("%s.%u-->%s.%u Len:%d\n", inet_ntoa(src_addr), tcpHeader->m_sSourPort, inet_ntoa(des_addr),
                       tcpHeader->m_sDestPort, data_len);
                int tcp_data_index = MAC_HEADER_SIZE + ip_header_len + tcp_header_len;
                const unsigned char *p = buffer + tcp_data_index;

                if (data_len > 0) {
                    printf("Data:");
                    for (int k = 0; k < n_read - tcp_data_index; ++k) {
                        printf("%02x ", p[k]);
                    }
                    printf("\n");
                    for (int k = 0; k < n_read - tcp_data_index; ++k) {
                        if ((p[k] >= 0 && p[k] <= 9) ||
                            (p[k] >= 'a' && p[k] <= 'z') ||
                            (p[k] >= 'A' && p[k] <= 'Z'))
                            printf("%c", p[k]);
                        else
                            printf(".");
                    }
                    printf("\n");
                }
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


};


#endif //CPCAP_PACKETCAP_H
