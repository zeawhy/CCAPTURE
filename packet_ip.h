//
// Created by zhangy on 2020/6/19.

//

#ifndef CCAPTURE_PACKET_IP_H
#define CCAPTURE_PACKET_IP_H
//MAC header
typedef struct {
    unsigned char DesMacAddr[6];
    unsigned char SrcMacAddr[6];
    short LengthOrType;
}__attribute__((packed)) MAC_HEADER, *PMAC_HEADER;

//IP header
typedef struct {
    unsigned char hdr_len: 4;
    unsigned char version: 4;
    unsigned char tos;
    unsigned short total_len;
    unsigned short identifier;
    unsigned short frag_and_flags;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned int source_ip;
    unsigned int dest_ip;
}__attribute__((packed)) IP_HEADER, *PIP_HEADER;

/*TCP*/
typedef struct _TCP_HEADER {
    unsigned short m_sSourPort;
    unsigned short m_sDestPort;
    unsigned int m_uiSequNum;
    unsigned int m_uiAcknowledgeNum;
    unsigned char m_uiHeadOff;
#define TH_OFF(th)    (((th)->th_offx2 & 0xf0) >> 4)
    unsigned char m_uiHeaderFlag;
#define    TH_FIN    0x01
#define    TH_SYN    0x02
#define    TH_RST    0x04
#define    TH_PUSH    0x08
#define    TH_ACK    0x10
#define    TH_URG    0x20
#define TH_ECNECHO    0x40    /* ECN Echo */
#define TH_CWR        0x80    /* ECN Cwnd Reduced */
    short m_sWindowSize;
    short m_sCheckSum;
    short m_surgentPointer;
}__attribute__((packed)) TCP_HEADER, *PTCP_HEADER;

typedef struct _TCP_OPTIONS {
    char m_ckind;
    char m_cLength;
    char m_cContext[32];
}__attribute__((packed)) TCP_OPTIONS, *PTCP_OPTIONS;

typedef struct _UDP_HEADER {
    unsigned short m_usSourPort;
    unsigned short m_usDestPort;
    unsigned short m_usLength;
    unsigned short m_usCheckSum;
}__attribute__((packed)) UDP_HEADER, *PUDP_HEADER;
#define  MAC_HEADER_SIZE  14
#define  IP_HEADER_SIZE 20
#define  UDP_HEADER_SIZE 8
#define  TCP_HEADER_SIZE 20
#endif //CCAPTURE_PACKET_IP_H
