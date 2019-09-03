#include "proto-icmp.h"
#include "proto-preprocess.h"
#include "syn-cookie.h"
#include "logger.h"
#include "output.h"
#include "masscan-status.h"
#include "templ-port.h"
#include "main-dedup.h"

//-Q2-以ICMP协议作为无状态协议模板
/***************************************************************************
 ***************************************************************************/
static int
matches_me(struct Output *out, unsigned ip, unsigned port)
{
    unsigned i;

    for (i=0; i<8; i++) {
        if (is_myself(&out->src[i], ip, port))
            return 1;
    }
    return 0;
}  //-Q2-ICMP-本地IP检查/排除 @ Ln 139

/***************************************************************************
 ***************************************************************************/
static int
parse_port_unreachable(const unsigned char *px, unsigned length,
        unsigned *r_ip_me, unsigned *r_ip_them,
        unsigned *r_port_me, unsigned *r_port_them,
        unsigned *r_ip_proto)
{
    if (length < 24)
        return -1;
    *r_ip_me = px[12]<<24 | px[13]<<16 | px[14]<<8 | px[15];
    *r_ip_them = px[16]<<24 | px[17]<<16 | px[18]<<8 | px[19];
    *r_ip_proto = px[9]; /* TCP=6, UDP=17 */

    px += (px[0]&0xF)<<2;
    length -= (px[0]&0xF)<<2;

    if (length < 4)
        return -1;

    *r_port_me = px[0]<<8 | px[1];
    *r_port_them = px[2]<<8 | px[3];

    return 0;
}

/***************************************************************************
 * 这是我们处理所有传入ICMP包的地方。其中一些包将由于扫描我们正在做，如ping(回声)。
 * 有些回应会忽略掉，例如“目的地不可到达”消息。
 ***************************************************************************/
void
handle_icmp(struct Output *out, time_t timestamp,
            const unsigned char *px, unsigned length,
            struct PreprocessedInfo *parsed,  //-Q0-接收到的数据包进行预处理后结果，将关键字段值提取。
            uint64_t entropy)
{   //-Q0-handle过程中的数据包已经被`初步解析`了一次（*parsed），该过程的实现并未依赖libpcap或内核相关过程！
    unsigned type = parsed->port_src;
    unsigned code = parsed->port_dst;
    unsigned seqno_me;
    unsigned ip_me;
    unsigned ip_them;
    unsigned cookie;

    /* 为ICMP回应消息去重 */
    static struct DedupTable *echo_reply_dedup = NULL;


    if (!echo_reply_dedup)
        echo_reply_dedup = dedup_create();    //-Q0-新建去重表（dedup）的过程。 Ln 69 ～ 73

    ip_me = parsed->ip_dst[0]<<24 | parsed->ip_dst[1]<<16
            | parsed->ip_dst[2]<< 8 | parsed->ip_dst[3]<<0;  //-Q0-预处理得到包头+偏移，指针指向数据包内IP地址起始位置，此处读取四个字节
    ip_them = parsed->ip_src[0]<<24 | parsed->ip_src[1]<<16
            | parsed->ip_src[2]<< 8 | parsed->ip_src[3]<<0;
    //-Q0-关于IP地址处理（以192.168.1.1为例）：
        //-Q2-ICMP-因为handle的是收到的数据包，因此IP地址解析对应的变量"源和目的"是反着的。
        // (192.168.1.1)ipv4 -> (0xC0A80101)hex
        //      0xC0 << 24 = 3221225472
        //      0xA8 << 16 = 11010048
        //      0x01 << 8  = 256
        //      0x01 << 0  = 1
        // ip_me = IP的十进制表示（3232235777）
    //-Q0-对于32位都是这样处理的，例如序列号。
    seqno_me = px[parsed->transport_offset+4]<<24
                | px[parsed->transport_offset+5]<<16
                | px[parsed->transport_offset+6]<<8
                | px[parsed->transport_offset+7]<<0;
    //-Q2-ICMP-按层级解析ICMP回应报文，抓包观察ICMP协议动作或参考 RFC 792
    switch (type) {  //-Q2-ICMP-由于`对方源端口号随机`，因此将Type值保存在`接收报文源端口号`内。
    case 0: /* ICMP echo 回应 主机存活 */
        //-Q2-ICMP-因为Type=0,Code=0,不存在其他情况表示主机存活，因此不需要进入Code判断。
        cookie = (unsigned)syn_cookie(ip_them, Templ_ICMP_echo, ip_me, 0, entropy);
        if ((cookie & 0xFFFFFFFF) != seqno_me)
            return; /* 非预期回应 */

        if (dedup_is_duplicate(echo_reply_dedup, ip_them, 0, ip_me, 0))
            break;

        //if (syn_hash(ip_them, Templ_ICMP_echo) != seqno_me)
        //    return; /* not my response */

        /*
         * 报告主机“打开”或“存在”
         */
        output_report_status(
                            out,
                            timestamp,
                            PortStatus_Open,
                            ip_them,
                            1, /* ip proto */
                            0,
                            0,
                            parsed->ip_ttl,
                            parsed->mac_src);
        break;
    case 3: /* 目标不可达 */
        switch (code) {
        case 0: /* 网络不可达 */
            /* 将接收到许多网络不可达信息，包括从配置错误的网络中 */
            break;
        case 1: /* 主机不可达 */
            /* 路由不存在 */
            break;
        case 2: /* 协议不可达 */
            /* 不支持SCTP协议，主机存在 */
            break;
        case 3: /* 端口不可达 */
            if (length - parsed->transport_offset > 8) {    //-Q0-L4偏移，是除去L3协议头的偏移
                unsigned ip_me2, ip_them2, port_me2, port_them2;
                unsigned ip_proto;
                int err;

                err = parse_port_unreachable(
                    px + parsed->transport_offset + 8,
                    length - parsed->transport_offset + 8,
                    &ip_me2, &ip_them2, &port_me2, &port_them2,
                    &ip_proto);

                if (err)
                    return;

                if (!matches_me(out, ip_me2, port_me2))
                    return;

                switch (ip_proto) {    //-Q2-ICMP-最后解析IP承载协议类型
                case 6: //-Q2-ICMP-TCP协议
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break;
                case 17: //-Q2-ICMP-UDP协议
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break;
                case 132://-Q2-ICMP-SCTP协议
                    output_report_status(
                                        out,
                                        timestamp,
                                        PortStatus_Closed,
                                        ip_them2,
                                        ip_proto,
                                        port_them2,
                                        0,
                                        parsed->ip_ttl,
                                        parsed->mac_src);
                    break; //-Q2-ICMP-至少我这里测试，ICMP无论是否可达，协议号永远为1。
                }//-Q2-ICMP-所以ICMP不可达，就永远不report咯？毕竟不可达。。。可达才是存活。
            }

        }
        break;  //-Q2-ICMP-港真，PING端口是一种特殊探测行为。PING探测主机是否存活-Pn比较靠谱。
    default:
    ;
    }

}

//-Q0-ICMP协议从运行开始到扫fang描qi
//-Q2-ICMP-从扫描到解包处理，最终得出目标状态反馈的梳理。
// 因为扫描是通过巨大的Mascan结构体进行任务配置，所以Understand是不能够直接将关系画出来的。
// 对于Masscan还算好应付，理清间接调用关系还是能应付，大佬的代码很扁平化，就是过程有点。。。
// 
// main.c      main()                  初始化数据结构并读取参数
// main.c      main_scan()             初始化扫描选项（类型、范围、初始化适配器）
// templ-pkt.c template_packet_init()  初始化数据包模板（包含ICMP扫描）
//-Q0-添加协议时，数据包结果在此处初始化。
//     templ-pkt.c _template_init()        识别协议、填充数据
//     templ-pkt.c icmp_checksum()         计算校验和-第一次
//     ...各种模板初始化过程，相见templ-pkt.c
// main.c      rte_ring_create()       RTE缓冲初始化（数据包缓冲、传输队列）
//-Q1-ICMP-开启收发线程  
//     发送线程中：
//          main.c Ln 397 -- rawsock_send_probe()       &tmpl-pkt被发送                    
//     接收线程中：
//          main.c Ln 704 -- rawsock_recv_packet()      &px是收到的数据包
//          main.c Ln 730 -- preprocess_frame()         从L2开始解析，后续解析L3，存入&prased
//          main.c Ln 802 -- handle_icmp()              解析非TCP协议报文（IP->ICMP）
//-Q0-新协议回应数据包到达，需要preprocess相关方法进行预处理解析（通用方法）得到基本情况。
//     =*=*= 到达 proto-icmp->handle_icmp()  =*=*=  调用对应解析函数，进行目标状态解析，输出结果。
//-Q0-新协议中具体目标状态判断是要单独写,并在接收线程内添加相应的handle函数。
// main.c      等待发送结束，等待接收结束
// ...过程伴随着各种状态输出...

// 原以为Handle是通过查数组，传递函数指针到Main的，实际上对于非TCP协议，这里看到是直接调用的。
// 因为在masscan-app.h中，有一个列出很多协议名称的数组。实际上，只是为了Banners输出时用的。