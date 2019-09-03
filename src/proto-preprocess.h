/* Copyright: (c) 2009-2010 by Robert David Graham */
#ifndef PREPROCESS_H
#define PREPROCESS_H

enum {
    FOUND_NOTHING=0,
    FOUND_ETHERNET,
    FOUND_IPV4,
    FOUND_IPV6,
    FOUND_ICMP,
    FOUND_TCP,
    FOUND_UDP,
    FOUND_SCTP,
    FOUND_DNS,
    FOUND_IPV6_HOP,
    FOUND_8021Q,
    FOUND_MPLS,
    FOUND_WIFI_DATA,
    FOUND_WIFI,
    FOUND_RADIOTAP,
    FOUND_PRISM,
    FOUND_LLC,
    FOUND_ARP,
    FOUND_SLL, /* Linux SLL */ //-Q0-支持Linux Cooked-mode 抓包
    FOUND_OPROTO, /* 其他IP承载的协议 */
};
struct PreprocessedInfo {
    const unsigned char *mac_src;
    const unsigned char *mac_dst;
    const unsigned char *mac_bss;
    unsigned ip_offset;     /* 14 以太网头 */
    unsigned ip_version;    /* 4 or 6 */  //-Q0-支持IPv6！但是没有相关协议模板！
    unsigned ip_protocol;   /* 6 for TCP, 11 for UDP */
    unsigned ip_length;     /* IP数据报文长度 */
    unsigned ip_ttl;
    const unsigned char *ip_src;
    const unsigned char *ip_dst;
    unsigned transport_offset;  /* 34 字节对于以太网报文 */
    unsigned transport_length;
    unsigned port_src;
    unsigned port_dst;

    unsigned app_offset; /* TCP payload起始位置 */
    unsigned app_length; /* TCP payload长度 */

    int found;
    int found_offset;
};

/**
 * @return 1 如果找到有用的东西，否则为0
 */
unsigned
preprocess_frame(const unsigned char *px, unsigned length, unsigned link_type, struct PreprocessedInfo *info);  //-Q0-预处理过程不过就直接continue到下一轮了。

#endif
