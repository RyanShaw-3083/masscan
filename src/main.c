// 其实我只想添加一个新的协议探测报文到 MASSCAN 内，甚至类似实现“应用层单包探测”。
//      实际过程中发现masscan不能很好地获取banners以及端口开放情况。
//      也许读完整个代码，我会发现我根本不需要这么做。
//      能解决C10M问题的大佬，写出的东西一定是值得学习的。
//      DPDK也用了类似RTE_RING结构？

/*

    主入口文件

    此文件包含s:

    * main()
    * transmit_thread() - 探测报文发送线程
    * receive_thread() - 回应数据包接收线程

    此处你将了解到数据包收发过程。

    这是整个项目的关键，我试着使此文件相对“扁平化”，以便所有过程都是可见的。
    所以它包含了大量的有很多局部变量的极大的函数。
    
*/
#include "masscan.h"
#include "masscan-version.h"
#include "masscan-status.h"     /* 接收线程中`receive_thread`端口开启或关闭状态获取 */
#include "rand-blackrock.h"     /* BlackRock随机化函数 */
#include "rand-lcg.h"           /* LCG随机化方法 */
#include "templ-pkt.h"          /* 待发送的数据包模板 */
#include "rawsock.h"            /* 多系统平台通用的原始套接字顶层接口*/
#include "logger.h"             /* 支持-v选项调整日志级别 */
#include "main-status.h"        /* printf() 函数进行定期状态更新数据显示 */
#include "main-throttle.h"      /* 速率限制 */
#include "main-dedup.h"         /* 忽略重复的回应报文 */
#include "main-ptrace.h"        /* 迎合nmap中的 --packet-trace 功能 */
#include "proto-arp.h"          /* 回应ARP请求报文 */
#include "proto-banner1.h"      /* 抓取目标系统服务的Banners */
#include "proto-tcp.h"          /* TCP/IP连接表 */
#include "proto-preprocess.h"   /* 快速处理报文 */
#include "proto-icmp.h"         /* 处理ICMP回应 */
#include "proto-udp.h"          /* 处理UDP回应 */
#include "syn-cookie.h"         /* 发送时创建 SYN-cookies*/
#include "output.h"             /* 显示结果信息 */
#include "rte-ring.h"           /* 生产者/消费者模型的环形缓冲队列 */
#include "rawsock-pcapfile.h"   /* 将原始数据包保存为PCAP文件 */
#include "stub-pcap.h"          /* 动态加载libpcap库 */
#include "smack.h"              /* Aho-corasick state-machine pattern-matcher */
#include "pixie-timer.h"        /* 可移植的时间库函数 */
#include "pixie-threads.h"      /* 可移植的线程库函数 */
#include "templ-payloads.h"     /* UDP数据报文 */
#include "proto-snmp.h"         /* 解析SNMP回应 */
#include "proto-ntp.h"          /* 解析NTP回应 */
#include "proto-coap.h"         /* CoAP协议自测 */
#include "templ-port.h"
#include "in-binary.h"          /* 转换二进制数据为 XML/JSON 格式 */
#include "main-globals.h"       /* 程序中所有全局变量 */
#include "proto-zeroaccess.h"
#include "siphash24.h"
#include "proto-x509.h"
#include "crypto-base64.h"      /* base64 编码/解码器 */
#include "pixie-backtrace.h"
#include "proto-sctp.h"
#include "proto-oproto.h"       /* 其他IP层之上的协议 */
#include "vulncheck.h"          /* 检查例如 monlist, poodle, heartblee 的软件漏洞 */
#include "main-readrange.h"
#include "scripting.h"
#include "range-file.h"         /* 从文件读取IP地址范围 */
#include "read-service-probes.h"
#include "misc-rstfilter.h"
#include "util-malloc.h"

#include <assert.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>

#if defined(WIN32)
#include <WinSock.h>
#if defined(_MSC_VER)
#pragma comment(lib, "Ws2_32.lib")
#endif
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

/*
 * 是的，使用全局变量很糟。
 */
unsigned volatile is_tx_done = 0;
unsigned volatile is_rx_done = 0;
time_t global_now;

uint64_t usec_start;


/***************************************************************************
 * 我们为每个网络适配器创建一对发送/接收线程。
 * 这个结构（ThreadPair）包含我们发送给每线程对的参数。
 ***************************************************************************/
struct ThreadPair {
    /** 指向核心配置数据的结构. 注意它带有 'const',
     * 意味着线程无法修改其中数据内容. */
    const struct Masscan *masscan;

    /** 线程对使用适配器，通常线程对有自己的适配器参数。尤其是使用 PF_RING
     * 聚合模式. */
    struct Adapter *adapter;

    /**
     * 线程对使用一个 "数据包缓冲" 和一个 "发送队列" 去相互发送数据。
     * 那是因为当进行 Banner 检查时，接收线程需要去响应从目标接收到
     * SYN-ACKs的数据包。然而， 接收线程无法发送数据， 所以使用环形
     * 结构按顺序发送数据包到发送线程去发送数据。
     */
    PACKET_QUEUE *packet_buffers;
    PACKET_QUEUE *transmit_queue;

    /**
     * 标识线程对所使用的网卡索引. 这是 "masscan->nic[]" 结构体中数组成员的索引。
     *
     * 注意: 这也是线程ID, 因为我们在每个网卡上，仅绑定一个线程对.
     */
    unsigned nic_index;

    /**
     * 'index' 重要变量的拷贝. 仅为其他线程调用, 用以标识执行进度状态。
     */
    volatile uint64_t my_index;


    /* 这是传输线程与接收线程共用的数据包格式化模板集合数组。*/
    struct TemplateSet tmplset[1];

    /**
     * 当前传输所涉及的IP地址。
     */
    struct Source src;
    unsigned char adapter_mac[6];
    unsigned char router_mac[6];

    unsigned done_transmitting;
    unsigned done_receiving;

    double pt_start;

    struct Throttler throttler[1];

    uint64_t *total_synacks;
    uint64_t *total_tcbs;
    uint64_t *total_syns;

    size_t thread_handle_xmit;
    size_t thread_handle_recv;
};


/***************************************************************************
 * 接收线程不发送数据. 换言之, 发送线程将发送数据放入队列中. 每隔一段时间，传输队列需要
 * 刷新队列内容并将全部内容发送。
 * 这是一个固有的设计问题，试图分批发送而不是单个数据包发送。
 * 它增加了延迟，但提高了性能。
 * 我们不关心延迟。
 ***************************************************************************/
static void
flush_packets(struct Adapter *adapter,
    PACKET_QUEUE *packet_buffers,
    PACKET_QUEUE *transmit_queue,
    uint64_t *packets_sent,
    uint64_t *batchsize)
{
    /*
     * 发送缓冲中的一批数据包。
     */
    for ( ; (*batchsize); (*batchsize)--) {
        int err;
        struct PacketBuffer *p;

        /*
         * 从传输队列中获取下一个数据包. 这个数据包被一个接收队列放置于此, 将包含一个ACK或HTTP请求。
         */
        err = rte_ring_sc_dequeue(transmit_queue, (void**)&p);  //数据包入队。
        if (err) {
            break; /* 队列空, 没有等待发送的数据 */
        }


        /*
         * 实际发送数据的过程。
         */
        rawsock_send_packet(adapter, p->px, (unsigned)p->length, 1);

        /*
         * 现在我们发完了这一个数据包, 将它放在传输线程可以重用的缓冲区的空闲列表中。
         */
        for (err=1; err; ) {
            err = rte_ring_sp_enqueue(packet_buffers, p);  //数据包存入缓冲。
            if (err) {
                LOG(0, "transmit queue full (should be impossible)\n");
                pixie_usleep(10000);
            }
        }


        /*
         * 记录已发送的数据包用于阀值计数.
         */
        (*packets_sent)++;
    }

}


/***************************************************************************
 * 我们支持IP地址与端口号组合的区间列表. 以下函数用于转换区间信息到可用变量.
 ***************************************************************************/
static void
get_sources(const struct Masscan *masscan,
            unsigned nic_index,
            unsigned *src_ip,
            unsigned *src_ip_mask,
            unsigned *src_port,
            unsigned *src_port_mask)
{
    const struct Source *src = &masscan->nic[nic_index].src;

    *src_ip = src->ip.first;
    *src_ip_mask = src->ip.last - src->ip.first;

    *src_port = src->port.first;
    *src_port_mask = src->port.last - src->port.first;
}

/***************************************************************************
 * 这个线程以最快的速度吐出包
 *
 *      全部令人激动的事情发生在这里!!!!
 *      90% 的时间片占用在这个函数内.
 *
 ***************************************************************************/
static void
transmit_thread(void *v) /*可视作 scanning_thread() */
{
    struct ThreadPair *parms = (struct ThreadPair *)v;
    uint64_t i;
    uint64_t start;
    uint64_t end;
    const struct Masscan *masscan = parms->masscan;
    uint64_t retries = masscan->retries;
    uint64_t rate = masscan->max_rate;
    unsigned r = (unsigned)retries + 1;
    uint64_t range;
    struct BlackRock blackrock;
    uint64_t count_ips = rangelist_count(&masscan->targets);
    struct Throttler *throttler = parms->throttler;
    struct TemplateSet pkt_template = templ_copy(parms->tmplset);
    struct Adapter *adapter = parms->adapter;
    uint64_t packets_sent = 0;
    unsigned increment = (masscan->shard.of-1) + masscan->nic_count;
    unsigned src_ip;
    unsigned src_ip_mask;
    unsigned src_port;
    unsigned src_port_mask;
    uint64_t seed = masscan->seed;
    uint64_t repeats = 0; /* --infinite repeats */
    uint64_t *status_syn_count;
    uint64_t entropy = masscan->seed;

    LOG(1, "THREAD: xmit: starting thread #%u\n", parms->nic_index);  
    // 一个线程对使用绑定一个NIC，线程ID即为NIC在全部网卡信息数组中的索引号。

    /* 使用指针将该变量导出至线程外，以便状态计数可获取到当前SYN的发送状态 */
    status_syn_count = MALLOC(sizeof(uint64_t));
    *status_syn_count = 0;
    parms->total_syns = status_syn_count;


    /* 通常，我们只有一个发送源地址. 特殊情况下可能有多个. */
    get_sources(masscan, parms->nic_index,
                &src_ip, &src_ip_mask,
                &src_port, &src_port_mask);


    /* "THROTTLER" 限制我们的最大发送速率, 通过选项
     * --max-rate 进行参数配置 */
    throttler_start(throttler, masscan->max_rate/masscan->nic_count);

infinite:
    
    /* 以Range变量来初始随机化（blackrock）过程, 简单来说即为目标IP地址数量乘以待扫描的端口数量 */
    range = rangelist_count(&masscan->targets)
            * rangelist_count(&masscan->ports);
    blackrock_init(&blackrock, range, seed, masscan->blackrock_rounds);

    /* 计算扫描的“开始”和“结束”。这样做的一个原因是
     * 支持—shard（切分），这样多台机器就可以协同工作进行同样的扫描。
     * 这样做的另一个原因是，当存在重试（--retried）选项时，我们可以稍微扩充扫描结束计数（bleed a little bit...）
     * 另一个这里要做的是处理多个网络适配器，本质上与切分的逻辑相同。 */
    start = masscan->resume.index + (masscan->shard.one-1) + parms->nic_index;
    end = range;
    if (masscan->resume.count && end > start + masscan->resume.count)
        end = start + masscan->resume.count;
    end += retries * rate;


    /* -----------------
     * 主循环开始
     * -----------------*/
    LOG(3, "THREAD: xmit: starting main loop: [%llu..%llu]\n", start, end);
    for (i=start; i<end; ) {
        uint64_t batch_size;

        /*
         * 一次循环处理多个包。 这是因为逐个包处理所发生的开销，导致发送上限在 1000万 pps（包每秒）, 
         * 所以我们通过批量发送的方式减小每数据包开销. 最低速率时, 每次批量大小仅为1. (--max-rate)
         */
        batch_size = throttler_next_batch(throttler, packets_sent);  
        // 逐个发送无法突破C10M，所以批量发送，降低单个包的处理开销。

        /*
         * 从另一个线程发送数据包, 当配置了 --banners 选项. 将导致相比SYN发送有更高的优先级. 
         * 如果获取banner信息导致无法发送SYN数据包,
         * 之后 "batch_size" 将降低至0, 并且无法继续发送SYN数据包.
         */
        flush_packets(adapter, parms->packet_buffers, parms->transmit_queue,
                        &packets_sent, &batch_size);


        /*
         * 传输一组数据包。任何慢于每秒100,000个包时，“batch_size”都可能是1
         */
        while (batch_size && i < end) {
            uint64_t xXx;
            unsigned ip_them;
            unsigned port_them;
            unsigned ip_me;
            unsigned port_me;
            uint64_t cookie;


            /*
             * 随机化的目标:
             *  这是有点棘手的选择一个随机的IP和端口号，以便扫描。
             *  我们将索引i从[0..range]单调递增。然后我们将该索引
             *  (随机transmog)洗牌到相同范围内的其他一些惟一的/1到1的数字中。
             *  这样我们访问所有的目标，但顺序是随机的。
             *  然后，一旦我们打乱了索引，我们就“选择”索引引用的IP地址和端口。
             */
            xXx = (i + (r--) * rate);
            if (rate > range)
                xXx %= range;
            else
                while (xXx >= range)
                    xXx -= range;
            xXx = blackrock_shuffle(&blackrock,  xXx);
            ip_them = rangelist_pick(&masscan->targets, xXx % count_ips);
            port_them = rangelist_pick(&masscan->ports, xXx / count_ips);

            /*
             * SYN-COOKIE 逻辑
             *  根据源 IP/port 得出 SYN-Cookie
             */
            if (src_ip_mask > 1 || src_port_mask > 1) {
                uint64_t ck = syn_cookie((unsigned)(i+repeats),
                                        (unsigned)((i+repeats)>>32),
                                        (unsigned)xXx, (unsigned)(xXx>>32),
                                        entropy);
                port_me = src_port + (ck & src_port_mask);
                ip_me = src_ip + ((ck>>16) & src_ip_mask);
            } else {
                ip_me = src_ip;
                port_me = src_port;
            }
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy);

            /*
             * 发送探测报文
             *  这就是整个程序的要点，但是这里没有什么令人兴奋的事情发生。
             *  需要注意的是，这可能是一个绕过内核的“原始”传输，这意味着我们可以每秒调用这个函数数百万次。
             */
            rawsock_send_probe(
                    adapter,
                    ip_them, port_them,
                    ip_me, port_me,
                    (unsigned)cookie,
                    !batch_size, /* 便于发送最后一批数据包时清空队列 */
                    &pkt_template
                    );
            batch_size--;
            packets_sent++;
            (*status_syn_count)++;

            /*
             * 在范围内按顺序递增
             *  是的，我知道这是一个微不足道的“i++”，但它是一个核心功能
             *  在值域内线性递增的方程组，但由此产生一个打乱的目标序列(如
             *  上述)。因为这是线性递增的我们可以做很多创造性的事情，比如做聪明的事情
             *  重新传输和分片。
             */
            if (r == 0) {
                i += increment; /* <------ 默认按1累加, 累加值在使用切分/多网卡时会更大 */
                r = (unsigned)retries + 1;
            }

        } /* 一组数据包发送结束 */


        /* 保存当前进度位置, 如果用户按了
         * <ctrl-c> 直接退出 */
        parms->my_index = i;

        /* 如果用户按了 <ctrl-c>, 我们需要退出程序. 但当用户使用 --resume 希望继续
        *  之前的扫描。因此我们将进度信息保存在文件中 */
        if (is_tx_done) {
            break;
        }
    }

    /*
     * --infinite
     *  进行负载测试，重新执行一次。
     */
    if (masscan->is_infinite && !is_tx_done) {
        seed++;
        repeats++;
        goto infinite;
    }

    /*
     * 清理掉全部未传输的数据包. 高速的机制如 Windows
     * "sendq" 和 Linux 的 "PF_RING"，数据包入队及传送同时进行,
     * 所以会有很多数据包入队但是没被发送.
     * 此处为了保证全部数据包确实被发送出去.
     */
    rawsock_flush(adapter);

    /*
     * 等待接收线程确认发送已经完成，回应数据接收完毕。
     */
    LOG(1, "THREAD: xmit done, waiting for receive thread to realize this\n");

    /*
     * 全部发送已经完成，但是回应数据包的接收存在一定的延迟. 
     * 至此需要等待一段时间，让回应数据到达. 此时按下 <ctrl-c> 多次将直接退出这一等待过程.
     */
    while (!is_rx_done) {
        unsigned k;
        uint64_t batch_size;

        for (k=0; k<1000; k++) {
            
            /*
             * 根据用户定义的最大发送速率（--max-rate），重新配置发送阀值（每批次发送数据包个数）。
             */
            batch_size = throttler_next_batch(throttler, packets_sent);


            /* 从接收线程中发送数据包 */
            flush_packets(  adapter,
                            parms->packet_buffers,
                            parms->transmit_queue,
                            &packets_sent,
                            &batch_size);

            /* 确认数据包确实被传送，而不仅仅是入队等待发送 */
            rawsock_flush(adapter);

            pixie_usleep(100);  // 每次阻塞100微秒，最多阻塞1000次
        }
    }

    /* 发送完成，线程将停止 */
    parms->done_transmitting = 1;
    LOG(1, "THREAD: xmit: stopping thread #%u\n", parms->nic_index);
}
/////////// 2019-09-02 1:05 PM ////////////////
// 发送线程的顶层细节整理完了。
//     为什么是“接收线程”填充发送队列？
//////////////////////////////////////////////
/***************************************************************************
 ***************************************************************************/
static unsigned
is_nic_port(const struct Masscan *masscan, unsigned ip)  // 接收线程中，判断IP是不是自己网卡的IP。
{
    unsigned i;
    for (i=0; i<masscan->nic_count; i++)
        if (is_my_port(&masscan->nic[i].src, ip))
            return 1;
    return 0;
}

/***************************************************************************
 *
 * 异步接收线程
 *
 * 发送与接收跑在两个独立的线程内. 这里没有记录已发送的信息. 取而代之的是, 使用
 * "SYN-cookie" 在已发送的数据包内, 据此接收线程中匹配已发送的数据包.
 ***************************************************************************/
static void
receive_thread(void *v)
{
    struct ThreadPair *parms = (struct ThreadPair *)v;
    const struct Masscan *masscan = parms->masscan;
    struct Adapter *adapter = parms->adapter;
    int data_link = rawsock_datalink(adapter);
    struct Output *out;
    struct DedupTable *dedup;
    struct PcapFile *pcapfile = NULL;
    struct TCP_ConnectionTable *tcpcon = 0;
    uint64_t *status_synack_count;
    uint64_t *status_tcb_count;
    uint64_t entropy = masscan->seed;
    struct ResetFilter *rf;
    
    /* 减少 RST 回应, 参见 rstfilter_is_filter() */
    rf = rstfilter_create(entropy, 16384);

    /* 一些状态描述 */
    status_synack_count = MALLOC(sizeof(uint64_t));
    *status_synack_count = 0;
    parms->total_synacks = status_synack_count;

    status_tcb_count = MALLOC(sizeof(uint64_t));
    *status_tcb_count = 0;
    parms->total_tcbs = status_tcb_count;

    LOG(1, "THREAD: recv: starting thread #%u\n", parms->nic_index);
    
    /* 为该线程锁定一个CPU. 
     * 发送线程占用奇数核心, 接收线程在偶数核心 */
    if (pixie_cpu_get_count() > 1) {
        unsigned cpu_count = pixie_cpu_get_count();
        unsigned cpu = parms->nic_index * 2 + 1;
        while (cpu >= cpu_count) {
            cpu -= cpu_count;
            cpu++;
        }
        //TODO: 保证可移植性
        //pixie_cpu_set_affinity(cpu);
    }

    /*
     * 如果配置（--pcap）打开pcap文件保存原始数据包。 这让我们可以调试扫描，同时看到人们发送来的奇怪回应。
     * 注意我们不记录接发送报文，只保存接收数据.
     */
    if (masscan->pcap_filename[0]) {
        pcapfile = pcapfile_openwrite(masscan->pcap_filename, 1);
    }

    /*
     * 开启输出. 这里是使用 --output-format 以及 --output-filename 会被触发的函数。
     */
    out = output_create(masscan, parms->nic_index);

    /*
     * 创建重复数据删除表。所以当有人给我们发送多个响应时，我们只记录第一个。
     */
    dedup = dedup_create();

    /*
     * 创建一个TCP连接表，以便在执行 --banners 选项时与活动连接进行交互
     */
    if (masscan->is_banners) {
        struct TcpCfgPayloads *pay;

        /*
         * 创建TCP连接表
         */
        tcpcon = tcpcon_create_table(
            (size_t)((masscan->max_rate/5) / masscan->nic_count),
            parms->transmit_queue,
            parms->packet_buffers,
            &parms->tmplset->pkts[Proto_TCP],
            output_report_banner,
            out,
            masscan->tcb.timeout,
            masscan->seed
            );
        
        /*
         * 初始化TCP脚本
         */
        scripting_init_tcp(tcpcon, masscan->scripting.L);
        
        
        /*
         * 手工配置一些标志位
         */
        tcpcon_set_banner_flags(tcpcon,
                masscan->is_capture_cert,
                masscan->is_capture_html,
                masscan->is_capture_heartbleed,
				masscan->is_capture_ticketbleed);
        if (masscan->http_user_agent_length)    // 读取配置，查找对应协议，进行参数配置
            tcpcon_set_parameter(   tcpcon,
                                    "http-user-agent",
                                    masscan->http_user_agent_length,
                                    masscan->http_user_agent);
        if (masscan->is_hello_smbv1)
            tcpcon_set_parameter(   tcpcon,
                                 "hello",
                                 1,
                                 "smbv1");
        if (masscan->is_hello_ssl)
            tcpcon_set_parameter(   tcpcon,
                                 "hello",
                                 1,
                                 "ssl");
        if (masscan->is_heartbleed)
            tcpcon_set_parameter(   tcpcon,
                                 "heartbleed",
                                 1,
                                 "1");
        if (masscan->is_ticketbleed)
            tcpcon_set_parameter(   tcpcon,
                                 "ticketbleed",
                                 1,
                                 "1");
        if (masscan->is_poodle_sslv3)
            tcpcon_set_parameter(   tcpcon,
                                 "sslv3",
                                 1,
                                 "1");
        if (masscan->tcp_connection_timeout) {
            char foo[64];
            sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "timeout",
                                 strlen(foo),
                                 foo);
        }
        if (masscan->tcp_hello_timeout) {
            char foo[64];
            sprintf_s(foo, sizeof(foo), "%u", masscan->tcp_connection_timeout);
            tcpcon_set_parameter(   tcpcon,
                                 "hello-timeout",
                                 strlen(foo),
                                 foo);
        }
        
        for (pay = masscan->payloads.tcp; pay; pay = pay->next) {
            char name[64];
            sprintf_s(name, sizeof(name), "hello-string[%u]", pay->port);
            tcpcon_set_parameter(   tcpcon, 
                                    name, 
                                    strlen(pay->payload_base64), 
                                    pay->payload_base64);
        }

    }

    /*
     * 离线模式下，我们不需要任何的接收线程，所以仅仅等待发送线程执行完毕，然后结束。
     */
    if (masscan->is_offline) {
        while (!is_rx_done)
            pixie_usleep(10000);
        parms->done_receiving = 1;
        goto end;
    }

    /*
     *接收数据包. 我们在这里获取响应信息并将执行状态打印在屏幕上.
     */
    LOG(1, "THREAD: recv: starting main loop\n");
    while (!is_rx_done) {
        int status;
        unsigned length;
        unsigned secs;
        unsigned usecs;
        const unsigned char *px;
        int err;
        unsigned x;
        struct PreprocessedInfo parsed;
        unsigned ip_me;
        unsigned port_me;
        unsigned ip_them;
        unsigned port_them;
        unsigned seqno_me;
        unsigned seqno_them;
        unsigned cookie;
        
        /*
         * 接收
         *
         * 一个无聊的过程，目的为了接收数据包。
         */
        err = rawsock_recv_packet(
                    adapter,
                    &length,
                    &secs,
                    &usecs,
                    &px);
        if (err != 0) {
            if (tcpcon)
                tcpcon_timeouts(tcpcon, (unsigned)time(0), 0);
            continue;
        }
        

        /*
         * 以数据包内时间戳为基准的TCP超时事件. 例如一个TCP连接已经打开了10秒，我们将它关闭. (--banners)
         */
        if (tcpcon) {
            tcpcon_timeouts(tcpcon, secs, usecs);
        }

        if (length > 1514)
            continue;

        /*
         * "预处理" 回应数据包. 这意味着遍历并找出TCP/IP头的位置以及一些字段的位置，比如IP地址和端口号。
         */
        x = preprocess_frame(px, length, data_link, &parsed);
        if (!x)
            continue; /* 跳过错误数据包 */
        ip_me = parsed.ip_dst[0]<<24 | parsed.ip_dst[1]<<16
            | parsed.ip_dst[2]<< 8 | parsed.ip_dst[3]<<0;
        ip_them = parsed.ip_src[0]<<24 | parsed.ip_src[1]<<16
            | parsed.ip_src[2]<< 8 | parsed.ip_src[3]<<0;
        port_me = parsed.port_dst;
        port_them = parsed.port_src;
        seqno_them = TCP_SEQNO(px, parsed.transport_offset);
        seqno_me = TCP_ACKNO(px, parsed.transport_offset);
        

        switch (parsed.ip_protocol) {
        case 132: /* 收到SCTP */
            cookie = syn_cookie(ip_them, port_them | (Proto_SCTP<<16), ip_me, port_me, entropy) & 0xFFFFFFFF;
            break;  // SCTP —— 流控制传输协议，继承TCP与UDP优点的一个协议。
        default:
            cookie = syn_cookie(ip_them, port_them, ip_me, port_me, entropy) & 0xFFFFFFFF;
        }

        /* 验证: 收到数据内的IP字段值，是否为本机公网IP */
        if (!is_my_ip(&parms->src, ip_me))
            continue;

        /*
         * 处理非TCP协议
         */
        switch (parsed.found) {
            case FOUND_ARP:    // ARP协议处理
                LOGip(2, ip_them, 0, "-> ARP [%u] \n", px[parsed.found_offset]);
                switch (px[parsed.found_offset + 6]<<8 | px[parsed.found_offset+7]) {
                case 1: /* 收到ARP请求报文 */
                    /** 
                     * 这个函数发送 ARP "reply" 到请求解析我方IP的目标主机（即使是我们实现的用户层TCP/IP协议栈）.
                     * 自从我们完全绕过了内核协议栈, 我们不得不自己处理ARP, 否则路由器将失去到本地的路由
                     */
                    arp_response(   ip_me,
                                    parms->adapter_mac,
                                    px, length,
                                    parms->packet_buffers,
                                    parms->transmit_queue);
                    break;
                case 2: /* 收到ARP回应 */
                    /* 此处为适应 "arp scan" 模式, 仅仅进行对目标的ARP扫描而不是端口扫描时 */

                    /* 如果没有进行ARP扫描，则忽略收到的ARP回应报文 */
                    if (!masscan->scan_type.arp)
                        break;

                    /* 收到的数据不在我们配置的IP范围内，忽略该报文 */
                    if (!rangelist_is_contains(&masscan->targets, ip_them))
                        break;

                    /* 忽略重复报文 */
                    if (dedup_is_duplicate(dedup, ip_them, 0, ip_me, 0))
                        continue;

                    /* ...一切如预期，处理并上报该ARP回应。 */
                    handle_arp(out, secs, px, length, &parsed);
                    break;
                }
                continue;
            case FOUND_UDP:  // 收到UDP报文
            case FOUND_DNS:  // 收到DNS报文
                if (!is_nic_port(masscan, port_me))
                    continue;
                if (parms->masscan->nmap.packet_trace)
                    packet_trace(stdout, parms->pt_start, px, length, 0);
                handle_udp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_ICMP:  // 收到ICMP报文
                handle_icmp(out, secs, px, length, &parsed, entropy);
                continue;
            case FOUND_SCTP:  //收到SCTP报文
                handle_sctp(out, secs, px, length, cookie, &parsed, entropy);
                break;
            case FOUND_OPROTO: /* 其他IP协议 */
                handle_oproto(out, secs, px, length, &parsed, entropy);
                break;
            case FOUND_TCP:
                /* 收到未知的TCP协议 */
                break;  // 这是个坑？这就是不好好抓banners的理由？！
            default:
                continue;
        }


        /* 验证: 是不是自身的端口号 */
        if (!is_my_port(&parms->src, port_me))
            continue;
        if (parms->masscan->nmap.packet_trace)
            packet_trace(stdout, parms->pt_start, px, length, 0);

        /* 保存原始数据包到 --pcap 指定的文件 */
        if (pcapfile) {
            pcapfile_writeframe(
                pcapfile,
                px,
                length,
                length,
                secs,
                usecs);
        }

        { // 为了调试方便建立的独立块，记录IP信息。
            char buf[64];
            LOGip(5, ip_them, port_them, "-> TCP ackno=0x%08x flags=0x%02x(%s)\n",
                seqno_me,
                TCP_FLAGS(px, parsed.transport_offset),
                reason_string(TCP_FLAGS(px, parsed.transport_offset), buf, sizeof(buf)));
        }

        /* 如果配置了 --banners 选项，捕获banners信息, 创建新的 "TCP 控制块 (TCB)" */
        if (tcpcon) {  //TCP连接控制
            // TCP_IS_{Flag}标识接收到的TCP状态
            // TCP_WAHT_{STATUS}标识当前TCP状态，并作为参数传递给TCP状态处理函数。
            struct TCP_Control_Block *tcb;

            /* 当前连接是否已经有TCB? */
            tcb = tcpcon_lookup_tcb(tcpcon,
                            ip_me, ip_them,
                            port_me, port_them);
            // 收到的TCP flag为SYN+ACK （TCP握手完成了一半，枚举值0x01），检查SYN cookie判断该数据包是否为预期。
            if (TCP_IS_SYNACK(px, parsed.transport_offset)) {
                if (cookie != seqno_me - 1) {
                    LOG(2, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n",
                        (ip_them>>24)&0xff, (ip_them>>16)&0xff, (ip_them>>8)&0xff, (ip_them>>0)&0xff,
                        seqno_me-1, cookie);
                    continue;
                }

                if (tcb == NULL) {
                    tcb = tcpcon_create_tcb(tcpcon,
                                    ip_me, ip_them,
                                    port_me, port_them,
                                    seqno_me, seqno_them+1,
                                    parsed.ip_ttl);
                    (*status_tcb_count)++;
                }

                tcpcon_handle(tcpcon, tcb, TCP_WHAT_SYNACK,
                    0, 0, secs, usecs, seqno_them+1);

            } else if (tcb) {
                /* 首先，如果收到ACK，先处理ACK（握手完成后） */
                if (TCP_IS_ACK(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_ACK,
                        0, seqno_me, secs, usecs, seqno_them);
                }

                /* 其次，如果收到了带有数据的包，处理数据 */
                if (parsed.app_length) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_DATA,
                        px + parsed.app_offset, parsed.app_length,
                        secs, usecs, seqno_them);
                }

                /* 如果收到FIN，处理连接关闭请求. 注意，ACK+FIN+Payload可以一起收到 */
                if (TCP_IS_FIN(px, parsed.transport_offset)
                    && !TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_FIN,
                        0, parsed.app_length, secs, usecs, seqno_them);
                }

                /* 如果收到RST, 我们将关闭该连接 */
                if (TCP_IS_RST(px, parsed.transport_offset)) {
                    tcpcon_handle(tcpcon, tcb, TCP_WHAT_RST,
                        0, 0, secs, usecs, seqno_them);
                }
            } else if (TCP_IS_FIN(px, parsed.transport_offset)) {
                /*
                 * 没有TCB!
                 *  当我们已经发送了FIN，并删除了连接时会出现。
                 *  但我们没有收到数据包.
                 */
                if (TCP_IS_RST(px, parsed.transport_offset))
                    ; /* 如果我们自己的TCP RST置位，则忽略。 */
                else {
                    int is_suppress;
                    // 抑制RST
                    is_suppress = rstfilter_is_filter(rf, ip_me, port_me, ip_them, port_them);
                    if (!is_suppress)
                        tcpcon_send_RST(
                            tcpcon,
                            ip_me, ip_them,
                            port_me, port_them,
                            seqno_them, seqno_me);
                }
            }

        }

        if (TCP_IS_SYNACK(px, parsed.transport_offset)
            || TCP_IS_RST(px, parsed.transport_offset)) { // 对应TCP状态可判断端口开或关，参见《网络扫描原理》

            /* 判断端口状态 */
            status = PortStatus_Unknown;
            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                status = PortStatus_Open;
            if (TCP_IS_RST(px, parsed.transport_offset)) {
                status = PortStatus_Closed;
            }

            /* 验证: syn-cookies是否为预期 */
            if (cookie != seqno_me - 1) {
                LOG(5, "%u.%u.%u.%u - bad cookie: ackno=0x%08x expected=0x%08x\n",
                    (ip_them>>24)&0xff, (ip_them>>16)&0xff,
                    (ip_them>>8)&0xff, (ip_them>>0)&0xff,
                    seqno_me-1, cookie);
                continue;
            }

            /* 验证: 忽略重复包 */
            if (dedup_is_duplicate(dedup, ip_them, port_them, ip_me, port_me))
                continue;

            /* 状态统计，SYN+ACK 接收数量 */
            if (TCP_IS_SYNACK(px, parsed.transport_offset))
                (*status_synack_count)++;

            /*
             * 这里输出结果
             */
            output_report_status(
                        out,
                        global_now,
                        status,
                        ip_them,
                        6, /* 指定IP协议承载tcp协议 */
                        port_them,
                        px[parsed.transport_offset + 13], /* TCP标志位 */
                        parsed.ip_ttl,
                        parsed.mac_src
                        );
            

            /*
             * 发送RST，这样就不会让另一端挂起(只有在我们才不会获取Banners的完全无状态模式下)
             */
            if (tcpcon == NULL && !masscan->is_noreset)
                tcp_send_RST(
                    &parms->tmplset->pkts[Proto_TCP],
                    parms->packet_buffers,
                    parms->transmit_queue,
                    ip_them, ip_me,
                    port_them, port_me,
                    0, seqno_me);

        }
    }


    LOG(1, "THREAD: recv: stopping thread #%u\n", parms->nic_index);
    
    /*
     * 回收&清理
     */
end:
    if (tcpcon)
        tcpcon_destroy_table(tcpcon);
    dedup_destroy(dedup);
    output_destroy(out);
    if (pcapfile)
        pcapfile_close(pcapfile);

    for (;;) {
        void *p;
        int err;
        err = rte_ring_sc_dequeue(parms->packet_buffers, (void**)&p);
        if (err == 0)
            free(p);
        else
            break;
    }

    /* 接收线程结束 */
    parms->done_receiving = 1;
}


/***************************************************************************
 * 我们捕获<ctrl+c>，这样我们就不是立即退出，而是在循环中等待几秒钟，等待任何延迟的响应。
 * 但是，用户可以按第二次退出等待。
 ***************************************************************************/
static void control_c_handler(int x)
{
    static unsigned control_c_pressed = 0;
    static unsigned control_c_pressed_again = 0;
    if (control_c_pressed == 0) {
        fprintf(stderr,
                "waiting several seconds to exit..."
                "                                            \n"
                );
        fflush(stderr);
        control_c_pressed = 1+x;
        is_tx_done = control_c_pressed;
    } else {
        if (is_rx_done) {
            fprintf(stderr, "\nERROR: threads not exiting %d\n", is_rx_done);
            if (is_rx_done++ > 1)
                exit(1);
        } else {
            control_c_pressed_again = 1;
            is_rx_done = control_c_pressed_again;
        }
    }

}



/***************************************************************************
 * 被 main() 调用，初始化扫描.
 * 启动收发线程并等待执行完成。
 ***************************************************************************/
static int
main_scan(struct Masscan *masscan)
{
    struct ThreadPair parms_array[8];
    uint64_t count_ips;
    uint64_t count_ports;
    uint64_t range;
    unsigned index;
    time_t now = time(0);
    struct Status status;
    uint64_t min_index = UINT64_MAX;
    struct MassVulnCheck *vulncheck = NULL;

    memset(parms_array, 0, sizeof(parms_array));

    /*
     * 漏洞验证初始化
     */
    if (masscan->vuln_name) {
        unsigned i;
		unsigned is_error;
        vulncheck = vulncheck_lookup(masscan->vuln_name);
        
        /* 没有指定端口号，使用默认端口 */
        is_error = 0;
        if (rangelist_count(&masscan->ports) == 0)
            rangelist_parse_ports(&masscan->ports, vulncheck->ports, &is_error, 0);
        
        /* 手动模式：指定端口号时修改端口号 */
        for (i=0; i<masscan->ports.count; i++) {
            struct Range *r = &masscan->ports.list[i];
            r->begin = (r->begin&0xFFFF) | Templ_VulnCheck;
            r->end = (r->end & 0xFFFF) | Templ_VulnCheck;
        }
    }
    
    /*
     * 计算任务大小
     */
    count_ips = rangelist_count(&masscan->targets);
    if (count_ips == 0) {
        LOG(0, "FAIL: target IP address list empty\n");
        LOG(0, " [hint] try something like \"--range 10.0.0.0/8\"\n");
        LOG(0, " [hint] try something like \"--range 192.168.0.100-192.168.0.200\"\n");
        return 1;
    }
    count_ports = rangelist_count(&masscan->ports);
    if (count_ports == 0) {
        LOG(0, "FAIL: no ports were specified\n");
        LOG(0, " [hint] try something like \"-p80,8000-9000\"\n");
        LOG(0, " [hint] try something like \"--ports 0-65535\"\n");
        return 1;
    }
    range = count_ips * count_ports + (uint64_t)(masscan->retries * masscan->max_rate);

    /*
     * 执行ARP扫描时禁止进行端口扫描
     */
    if (rangelist_is_contains(&masscan->ports, Templ_ARP)) {
        if (masscan->ports.count != 1) {
            LOG(0, "FAIL: cannot arpscan and portscan at the same time\n");
            return 1;
        }
    }

    /*
     * 如果IP范围太大，要求用户指定排除列表。
     */
    if (count_ips > 1000000000ULL && rangelist_count(&masscan->exclude_ip) == 0) {
        LOG(0, "FAIL: range too big, need confirmation\n");
        LOG(0, " [hint] to prevent acccidents, at least one --exclude must be specified\n");
        LOG(0, " [hint] use \"--exclude 255.255.255.255\" as a simple confirmation\n");
        exit(1);
    }  // （范围大于10亿时触发）全球IP数量43亿（2018），所以分布式扫描是必要的。

    /*
     * 仅保留nmap udp报文中的端口号信息. 在高速率模式下有更快的查找速度.
     */
    payloads_udp_trim(masscan->payloads.udp, &masscan->ports);
    payloads_oproto_trim(masscan->payloads.oproto, &masscan->ports);

    /* 优化目标选择，所以这是一个快速的二进制搜索
     * 遍历大内存表。当我们浏览整个互联网时
     * 我们的排除列表将把原始的0.0.0.0/0范围分割成
     * 数百个子程序。这允许我们更快地获取（统计）地址（数量）。*/
    rangelist_optimize(&masscan->targets);
    rangelist_optimize(&masscan->ports);

#ifdef __AFL_HAVE_MANUAL_CONTROL
  __AFL_INIT();
#endif

    /*
     * 为每个适配器开启扫描线程（对）。
     */
    for (index=0; index<masscan->nic_count; index++) {
        struct ThreadPair *parms = &parms_array[index];
        int err;

        parms->masscan = masscan;
        parms->nic_index = index;
        parms->my_index = masscan->resume.index;
        parms->done_transmitting = 0;
        parms->done_receiving = 0;

        /* 需要 --packet-trace 选项，便于我们知道什么时候开始的扫描 */
        parms->pt_start = 1.0 * pixie_gettime() / 1000000.0;


        /*
         * 打开适配器，读取扫描配置（初始化适配器）
         */
        err = masscan_initialize_adapter(
                            masscan,
                            index,
                            parms->adapter_mac,
                            parms->router_mac
                            );
        if (err != 0)
            exit(1);
        parms->adapter = masscan->nic[index].adapter;
        if (masscan->nic[index].src.ip.range == 0) {
            LOG(0, "FAIL: failed to detect IP of interface\n");
            LOG(0, " [hint] did you spell the name correctly?\n");
            LOG(0, " [hint] if it has no IP address, "
                    "manually set with \"--adapter-ip 192.168.100.5\"\n");
            exit(1);
        }


        /*
        * 初始化TCP包模板。事情是这样的：
        * 我们解析一个现有的TCP包，并使用它作为模板
        * 扫描。然后，我们用附加的功能调整模板，
        * 例如IP地址等
        */
        parms->tmplset->vulncheck = vulncheck;
        template_packet_init(
                    parms->tmplset,
                    parms->adapter_mac,
                    parms->router_mac,
                    masscan->payloads.udp,
                    masscan->payloads.oproto,
                    rawsock_datalink(masscan->nic[index].adapter),
                    masscan->seed);

        /*
         * 为每一个发送的数据包设定源IP
         */
        if (masscan->nic[index].src.port.range == 0) {
            unsigned port = 40000 + now % 20000;
            masscan->nic[index].src.port.first = port;
            masscan->nic[index].src.port.last = port;
            masscan->nic[index].src.port.range = 1;
        }

        parms->src = masscan->nic[index].src;


        /*
         * 设定数据包TTL.
         */
        if (masscan->nmap.ttl)
            template_set_ttl(parms->tmplset, masscan->nmap.ttl);

        if (masscan->nic[0].is_vlan)
            template_set_vlan(parms->tmplset, masscan->nic[0].vlan_id);


        /*
         * 设置 <ctrl-c> 的回调（进入暂停状态，保存扫描进度）
         */
        signal(SIGINT, control_c_handler);


        /*
         * 分配数据包缓存
         */
#define BUFFER_COUNT 16384
        parms->packet_buffers = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
        parms->transmit_queue = rte_ring_create(BUFFER_COUNT, RING_F_SP_ENQ|RING_F_SC_DEQ);
        {
            unsigned i;
            for (i=0; i<BUFFER_COUNT-1; i++) {
                struct PacketBuffer *p;

                p = MALLOC(sizeof(*p));
                err = rte_ring_sp_enqueue(parms->packet_buffers, p);
                if (err) {
                    /* I dunno why but I can't queue all 256 packets, just 255 */
                    LOG(0, "packet_buffers: enqueue: error %d\n", err);
                }
            }
        }


        /*
         * 开始扫描线程.
         * 这是程序开始以高速率吐出数据包的地方。
         */
        parms->thread_handle_xmit = pixie_begin_thread(transmit_thread, 0, parms);


        /*
         * 启动匹配的接收线程。发送和接收线程成对出现。
         */
        parms->thread_handle_recv = pixie_begin_thread(receive_thread, 0, parms);

    }

    /*
     * 状态输出
     */
    {
        char buffer[80];
        struct tm x;

        now = time(0);
        gmtime_s(&x, &now);
        strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S GMT", &x);
        LOG(0, "\nStarting masscan " MASSCAN_VERSION " (http://bit.ly/14GZzcT) at %s\n", buffer);

        if (count_ports == 1 && \
            masscan->ports.list->begin == Templ_ICMP_echo && \
            masscan->ports.list->end == Templ_ICMP_echo)
            { /* 仅仅 ICMP 适用 */
                LOG(0, " -- forced options: -sn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating ICMP Echo Scan\n");
                LOG(0, "Scanning %u hosts\n",(unsigned)count_ips);
             }
        else /* 可以仅用于UDP扫描 或混合了 UDP/TCP/ICMP 的扫描 */
            {
                LOG(0, " -- forced options: -sS -Pn -n --randomize-hosts -v --send-eth\n");
                LOG(0, "Initiating SYN Stealth Scan\n");
                LOG(0, "Scanning %u hosts [%u port%s/host]\n",
                    (unsigned)count_ips, (unsigned)count_ports, (count_ports==1)?"":"s");
            }
    }

    /*
     * 等待 <ctrl-c> 被用户按下或扫描结束
     */
    LOG(1, "THREAD: status: starting thread\n");
    status_start(&status);
    status.is_infinite = masscan->is_infinite;
    while (!is_tx_done && masscan->output.is_status_updates) {
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* 找出所有线程中的最小线程ID */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }

        if (min_index >= range && !masscan->is_infinite) {
            /* 上述条件明确了扫描的结束状态 */
            is_tx_done = 1;
        }

        /*
         * 更新统计信息输出,单位 包/秒.
         */
        if (masscan->output.is_status_updates)
            status_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns,
                0);

        /* 大概阻塞一秒 */
        pixie_mssleep(750);
    }

    /*
     * 如果没扫完，保存扫描状态。
     */
    if (min_index < count_ips * count_ports) {
        masscan->resume.index = min_index;

        /* 保存当前状态到配置文件 "paused.conf" 以便后续继续本次扫描 */
        masscan_save_state(masscan);
    }



    /*
     * 等待所有线程退出
     */
    now = time(0);
    for (;;) {
        unsigned transmit_count = 0;
        unsigned receive_count = 0;
        unsigned i;
        double rate = 0;
        uint64_t total_tcbs = 0;
        uint64_t total_synacks = 0;
        uint64_t total_syns = 0;


        /* 找出所有线程中的最小线程ID */
        min_index = UINT64_MAX;
        for (i=0; i<masscan->nic_count; i++) {
            struct ThreadPair *parms = &parms_array[i];

            if (min_index > parms->my_index)
                min_index = parms->my_index;

            rate += parms->throttler->current_rate;

            if (parms->total_tcbs)
                total_tcbs += *parms->total_tcbs;
            if (parms->total_synacks)
                total_synacks += *parms->total_synacks;
            if (parms->total_syns)
                total_syns += *parms->total_syns;
        }



        if (time(0) - now >= masscan->wait) {    // 不用继续等待，接收线程任务完成
            is_rx_done = 1;
        }

        if (masscan->output.is_status_updates) {  // 阻塞等待状态更新
            status_print(&status, min_index, range, rate,
                total_tcbs, total_synacks, total_syns,
                masscan->wait - (time(0) - now));

            for (i=0; i<masscan->nic_count; i++) {
                struct ThreadPair *parms = &parms_array[i];

                transmit_count += parms->done_transmitting;
                receive_count += parms->done_receiving;

            }

            pixie_mssleep(250);

            if (transmit_count < masscan->nic_count)
                continue;
            is_tx_done = 1;
            is_rx_done = 1;
            if (receive_count < masscan->nic_count)
                continue;

        } else {
            /* [AFL-fuzz]
             * 等待无状态输出的线程结束，但允许我们直接退出。
             */
            for (i=0; i<masscan->nic_count; i++) {
                struct ThreadPair *parms = &parms_array[i];

                pixie_thread_join(parms->thread_handle_xmit);
                parms->thread_handle_xmit = 0;
                pixie_thread_join(parms->thread_handle_recv);
                parms->thread_handle_recv = 0;
            }
            is_tx_done = 1;
            is_rx_done = 1;
        }

        break;
    }

    LOG(1, "THREAD: status: stopping thread\n");

    /*
     * 清理
     */
    status_finish(&status);

    if (!masscan->output.is_status_updates) {
        uint64_t usec_now = pixie_gettime();

        printf("%u milliseconds ellapsed\n", (unsigned)((usec_now - usec_start)/1000));
    }
    return 0;
}



// 解析命令行参数，配置扫描任务。
/***************************************************************************
 ***************************************************************************/
int main(int argc, char *argv[])
{
    struct Masscan masscan[1];
    unsigned i;
    
    usec_start = pixie_gettime();
#if defined(WIN32)
    {WSADATA x; WSAStartup(0x101, &x);}
#endif

    global_now = time(0);

    /* 程序崩溃时，系统报告（记录）错误信息 */
    {
        int is_backtrace = 1;
        for (i=1; i<(unsigned)argc; i++) {
            if (strcmp(argv[i], "--nobacktrace") == 0)
                is_backtrace = 0;
        }
        if (is_backtrace)
            pixie_backtrace_init(argv[0]);
    }
    
    /*
     * 初始化非零配置变量
     */
    memset(masscan, 0, sizeof(*masscan));
    masscan->blackrock_rounds = 4;
    masscan->output.is_show_open = 1; /* 默认: 以syn-ack为端口开，rst为关闭 */
    masscan->output.is_status_updates = 1; /* 默认: 显示状态更新 */
    masscan->seed = get_entropy(); /* 随机化的熵值 */
    masscan->wait = 10; /* 发送完成后等待剩余线程结束的时间 */
    masscan->max_rate = 100.0; /* 最大速率 = 百/数据包/秒（每秒几百数据包） */
    masscan->nic_count = 1;
    masscan->shard.one = 1;
    masscan->shard.of = 1;
    masscan->min_packet_size = 60;
    masscan->payloads.udp = payloads_udp_create();
    masscan->payloads.oproto = payloads_oproto_create();
    strcpy_s(   masscan->output.rotate.directory,
                sizeof(masscan->output.rotate.directory),
                ".");
    masscan->is_capture_cert = 1;

    /*
     * 预处理命令行
     */
    if (masscan_conf_contains("--readscan", argc, argv)) {
        masscan->is_readscan = 1;
    }

    /*
     * 在非windows系统上，从文件中读取默认值，文件在/etc目录。
     * 多数这些缺省值将包含一些内容例如输出目录、最大包速率等等。
     * 重要的是，主要的"——excludefile"可能放在这里，
     * 这样黑名单范围将不会被扫描，即使用户犯错误。
     */
#if !defined(WIN32)
    if (!masscan->is_readscan) {
        if (access("/etc/masscan/masscan.conf", 0) == 0) {
            masscan_read_config_file(masscan, "/etc/masscan/masscan.conf");
        }
    }
#endif

    /*
     * 从命令行读取配置。我们正在寻找选项或IPv4地址范围列表。
     */
    masscan_command_line(masscan, argc, argv);
    
    /*
     * 加载数据库文件，如“nmap-payloads”和“nmap-service-probe”
     */
    masscan_load_database_files(masscan);

    /*
     * 如果需要，加载脚本引擎并运行那些指定脚本。
     */
    if (masscan->is_scripting)
        scripting_init(masscan);

    /* 我们需要做一个单独的“原始套接字”初始化步骤。此处适应
     * Windows 环境及 PF_RING 驱动 */
    if (pcap_init() != 0)
        LOG(2, "libpcap: failed to load\n");
    rawsock_init();

    /* 初始化协议匹配数据结构 */
    snmp_init();
    x509_init();


    /*
     * 大规模扫描时配置并应用排除列表。
     */
    {
        uint64_t range = rangelist_count(&masscan->targets) * rangelist_count(&masscan->ports);
        uint64_t range2;
        rangelist_exclude(&masscan->targets, &masscan->exclude_ip);
        rangelist_exclude(&masscan->ports, &masscan->exclude_port);
        //rangelist_remove_range2(&masscan->targets, range_parse_ipv4("224.0.0.0/4", 0, 0));

        range2 = rangelist_count(&masscan->targets) * rangelist_count(&masscan->ports);

        if (range != 0 && range2 == 0) {
            LOG(0, "FAIL: no ranges left to scan\n");
            LOG(0, "   ...all ranges overlapped something in an excludefile range\n");
            exit(1);
        }

        if (range2 != range && masscan->resume.index) {
            LOG(0, "FAIL: Attempted to add additional 'exclude' ranges after scan start.\n");
            LOG(0, "   ...This messes things up the scan randomization, so you have to restart scan\n");
            exit(1);
        }
    }



    /*
     * 从配置文件中读取扫描行为。
     */
    switch (masscan->op) {
    case Operation_Default:
        /* 输出帮助信息 */
        masscan_usage();
        break;

    case Operation_Scan:
        /*
         * 默认执行动作
         */
        return main_scan(masscan);

    case Operation_ListScan:
        /* 随机化待扫描目标IP列表 */
        main_listscan(masscan);
        return 0;

    case Operation_List_Adapters:
        /* 列出我们在扫描过程中可能用到的适配器（网卡） */
        rawsock_list_adapters();
        break;

    case Operation_DebugIF:
        for (i=0; i<masscan->nic_count; i++)
            rawsock_selftest_if(masscan->nic[i].ifname);
        return 0;

    case Operation_ReadRange:
        main_readrange(masscan);
        return 0;

    case Operation_ReadScan:
        {
            unsigned start;
            unsigned stop;

            /* 继续扫描任务，读取第一个状态文件 */
            for (start=1; start<(unsigned)argc; start++) {
                if (memcmp(argv[start], "--readscan", 10) == 0) {
                    start++;
                    break;
                }
            }

            /* 找到最后一个文件 */
            for (stop=start+1; stop<(unsigned)argc && argv[stop][0] != '-'; stop++)
                ;

            /*
             * 读取二进制文件并输出状态信息
             */
            read_binary_scanfile(masscan, start, stop, argv);

        }
        break;

    case Operation_Benchmark:
        printf("=== benchmarking (%u-bits) ===\n\n", (unsigned)sizeof(void*)*8);
        blackrock_benchmark(masscan->blackrock_rounds);
        blackrock2_benchmark(masscan->blackrock_rounds);
        smack_benchmark();
        exit(1);
        break;

    case Operation_Selftest:
        /*
         * 进行自测过程
         */
        {
            int x = 0;
            x += proto_coap_selftest();
            x += smack_selftest();
            x += sctp_selftest();
            x += base64_selftest();
            x += banner1_selftest();
            x += output_selftest();
            x += siphash24_selftest();
            x += ntp_selftest();
            x += snmp_selftest();
            x += payloads_udp_selftest();
            x += blackrock_selftest();
            x += rawsock_selftest();
            x += lcg_selftest();
            x += template_selftest();
            x += ranges_selftest();
            x += rangefile_selftest();
            x += pixie_time_selftest();
            x += rte_ring_selftest();
            x += mainconf_selftest();
            x += zeroaccess_selftest();
            x += nmapserviceprobes_selftest();
            x += rstfilter_selftest();


            if (x != 0) {
                /* 任何一个自测失败返回错误信息 */
                fprintf(stderr, "regression test: failed :( \n");
                return 1;
            } else {
                fprintf(stderr, "regression test: success!\n");
                return 0;
            }
        }
        break;
    }


    return 0;
}


