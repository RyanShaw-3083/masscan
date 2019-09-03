#include "masscan.h"
#include "logger.h"
#include "rawsock.h"


/***************************************************************************
 * 网络适配器初始化.
 *
 * 这需要找到我们的IP地址，MAC地址和路由器
 * MAC地址。用户可以手动配置这些东西。
 *
 * 注意，我们不更新“静态”配置与发现值，而是将它们作为“正在运行”配置返回。这是
 * 因为，如果我们暂停并继续扫描，自动发现的值不会被保存在配置文件中。
 ***************************************************************************/
int
masscan_initialize_adapter(
    struct Masscan *masscan,
    unsigned index,
    unsigned char *adapter_mac,
    unsigned char *router_mac
    )
{
    char *ifname;
    char ifname2[256];
    unsigned adapter_ip = 0;
    
    if (masscan == NULL)
        return -1;

    LOG(1, "if: initializing adapter interface\n");

    /*
     * 适配器/网络接口
     *
     * 如果没有配置网络接口，我们需要进行搜索
     * 使用最佳接口。以“预设路线”(即“网关”)定义的，我们选择第一个。
     */
    if (masscan->nic[index].ifname[0])
        ifname = masscan->nic[index].ifname;
    else {
        /* 没有指定网卡，默认选择第一个 */
        int err;
        ifname2[0] = '\0';
        err = rawsock_get_default_interface(ifname2, sizeof(ifname2));
        if (err || ifname2[0] == '\0') {
            fprintf(stderr, "FAIL: could not determine default interface\n");
            fprintf(stderr, "FAIL:... try \"--interface ethX\"\n");
            return -1;
        }
        ifname = ifname2;
    }
    LOG(2, "if: interface=%s\n", ifname);

    /*
     * IP地址
     * 
     * 我们需要找出发送数据包的IP地址。
     * 这通过查询适配器(或由用户配置)来完成。
     * 如果适配器没有，那么用户必须配置一个。
     */
    adapter_ip = masscan->nic[index].src.ip.first;
    if (adapter_ip == 0) {
        adapter_ip = rawsock_get_adapter_ip(ifname);
        masscan->nic[index].src.ip.first = adapter_ip;
        masscan->nic[index].src.ip.last = adapter_ip;
        masscan->nic[index].src.ip.range = 1;
    }
    if (adapter_ip == 0) {
        fprintf(stderr, "FAIL: failed to detect IP of interface \"%s\"\n",
                        ifname);
        fprintf(stderr, " [hint] did you spell the name correctly?\n");
        fprintf(stderr, " [hint] if it has no IP address, manually set with "
                        "\"--adapter-ip 192.168.100.5\"\n");
        return -1;
    }
    LOG(2, "if:%s: adapter-ip=%u.%u.%u.%u\n",
        ifname,
        (adapter_ip>>24)&0xFF,
        (adapter_ip>>16)&0xFF,
        (adapter_ip>> 8)&0xFF,
        (adapter_ip>> 0)&0xFF
        );

    /* MAC地址
     *
     * 这是我们发送数据包的地址。
     * 实际上并不是这样无论这个地址是什么，但作为一个“靠谱”的人，我们尝试使用网卡中的硬件地址。
     */
    memcpy(adapter_mac, masscan->nic[index].my_mac, 6);
    if (masscan->nic[index].my_mac_count == 0) {
        if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
            rawsock_get_adapter_mac(ifname, adapter_mac);
        }
        if (memcmp(adapter_mac, "\0\0\0\0\0\0", 6) == 0) {
            fprintf(stderr, "FAIL: failed to detect MAC address of interface:"
                    " \"%s\"\n", ifname);
            fprintf(stderr, " [hint] try something like "
                    "\"--adapter-mac 00-11-22-33-44-55\"\n");
            return -1;
        }
    }
    LOG(2, "if:%s: adapter-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
        ifname,
        adapter_mac[0],
        adapter_mac[1],
        adapter_mac[2],
        adapter_mac[3],
        adapter_mac[4],
        adapter_mac[5]
        );


    /*
     * 启动适配器
     *
     * 找到合适的适配器，随即启动它.
     */
    masscan->nic[index].adapter = rawsock_init_adapter(
                                            ifname,
                                            masscan->is_pfring,
                                            masscan->is_sendq,
                                            masscan->nmap.packet_trace,
                                            masscan->is_offline,
                                            (void*)masscan->bpf_filter,
                                            masscan->nic[index].is_vlan,
                                            masscan->nic[index].vlan_id);
    if (masscan->nic[index].adapter == 0) {
        LOG(1, "if:%s:init: failed\n", ifname);
        return -1;
    }
    rawsock_ignore_transmits(masscan->nic[index].adapter, adapter_mac, ifname);
    


    /* 路由器MAC地址
     * 注意:这是代码中最不容易理解的方面之一。
     * 我们必须发送数据包到本地路由器，这意味着MAC地址(不是路由器的IP地址)。
     * 注意:为了ARP路由器，我们需要首先启用libpcap。
     * */
    memcpy(router_mac, masscan->nic[index].router_mac, 6);
    if (masscan->is_offline) {
        memcpy(router_mac, "\x66\x55\x44\x33\x22\x11", 6);
    } else if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        unsigned router_ipv4 = masscan->nic[index].router_ip;
        int err = 0;


        LOG(1, "if:%s: looking for default gateway\n", ifname);
        if (router_ipv4 == 0)
            err = rawsock_get_default_gateway(ifname, &router_ipv4);
        if (err == 0) {
            LOG(2, "if:%s: router-ip=%u.%u.%u.%u\n",
                ifname,
                (router_ipv4>>24)&0xFF,
                (router_ipv4>>16)&0xFF,
                (router_ipv4>> 8)&0xFF,
                (router_ipv4>> 0)&0xFF
                );

            LOG(1, "if:%s:arp: resolving IPv4 address\n", ifname);
            arp_resolve_sync(
                    masscan->nic[index].adapter,
                    adapter_ip,
                    adapter_mac,
                    router_ipv4,
                    router_mac);

        }
    }
    LOG(2, "if:%s: router-mac=%02x-%02x-%02x-%02x-%02x-%02x\n",
        ifname,
        router_mac[0],
        router_mac[1],
        router_mac[2],
        router_mac[3],
        router_mac[4],
        router_mac[5]
        );
    if (memcmp(router_mac, "\0\0\0\0\0\0", 6) == 0) {
        LOG(0, "FAIL: failed to detect router for interface: \"%s\"\n", ifname);
        LOG(0, " [hint] try something like \"--router-mac 66-55-44-33-22-11\" to specify router\n");
        LOG(0, " [hint] try something like \"--interface eth0\" to change interface\n");
        return -1;
    }


    LOG(1, "if:%s: initialization done.\n", ifname);
    return 0;
}
