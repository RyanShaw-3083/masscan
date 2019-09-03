#ifndef MASSCAN_H
#define MASSCAN_H
#include "string_s.h"
#include "main-src.h"
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>

#include "ranges.h"
#include "ranges6.h"
#include "packet-queue.h"

struct Adapter;
struct TemplateSet;
struct Banner1;

/**
 * 这是masscan将要执行的“操作”，几乎总是这样
 * “扫描”网络。然而，还有一些较小的操作要做
 * 相反，像运行一个“自测”，或“调试”，或其他东西而不是扫描。
 * 我们解析命令行，以便找出正确操作
 */
enum Operation {
    Operation_Default = 0,          /* 未定义，打印帮助 */
    Operation_List_Adapters = 1,    /* --listif */                      // 列出网卡列表
    Operation_Selftest = 2,         /* --selftest or --regress */       // 自测或回归测试
    Operation_Scan = 3,         /* 这是你期待的 */                        // 开始扫描
    Operation_DebugIF = 4,          /* --debug if */                    // 接口调试
    Operation_ListScan = 5,         /* -sL */                           // Nmap参数格式，顺序扫描
    Operation_ReadScan = 6,         /* --readscan <binary-output> */    // 读取二进制文件获取扫描信息
    Operation_ReadRange = 7,        /* --readrange */                   // 读取IP范围信息
    Operation_Benchmark = 8,        /* --benchmark */                   // 评估扫描性能
};

/**
 * 输出的格式。如果没有指定任何内容，则默认值将指定
 * 为“——interactive”，这意味着我们将实时打印结果出来到命令行。
 * 只能指定一种输出格式，除此之外“——interactive”可以与其他选项一起指定。
 */
enum OutputFormat {
    Output_Default      = 0x0000,
    Output_Interactive  = 0x0001,   /* --interactive, (交互模式，打印到命令行) */
    Output_List         = 0x0002,
    Output_Binary       = 0x0004,   /* -oB, "binary", 基本格式（二进制格式） */
    Output_XML          = 0x0008,   /* -oX, "xml" */
    Output_JSON         = 0x0010,   /* -oJ, "json" */
    Output_NDJSON       = 0x0011,   /* -oD, "ndjson" */
    Output_Nmap         = 0x0020,
    Output_ScriptKiddie = 0x0040,
    Output_Grepable     = 0x0080,   /* -oG, "grepable" */
    Output_Redis        = 0x0100, 
    Output_Unicornscan  = 0x0200,   /* -oU, "unicornscan" */
    Output_None         = 0x0400,
    Output_Certs        = 0x0800,
    Output_All          = 0xFFBF,   /* not supported */  //不支持的输出格式
};


/**
 * 保存TCP“hello”有效负载列表，使用“——hello-file”指定或“——hello-string”选项
 */
struct TcpCfgPayloads
{
    /** “hello”数据的base64格式。这要么是base64字符串
     * 在cmdline/cfgfile中指定“——hello-string”，或
     * 文件的内容指定为“——hello-file”，我们已经转换为base64。
     * */
    char *payload_base64;
    
    /** hello所属的TCP端口 */
    unsigned port;
    
    /** 这些配置选项存储为链表 */
    struct TcpCfgPayloads *next;
};




/**
 * 这是主MASSCAN配置结构。它是在启动时创建的
 * 读取命令行并解析配置文件。
 * 
 * 一旦开始读取，这个结构就不会改变。传输和接收线程只有一个指向这个结构的“const”指针。
 */
struct Masscan
{
    /**
     * 这个程序正在做什么，通常是“Operation_Scan”，但是
     * 也可以是其他东西，比如“Operation_SelfTest”
     */
    enum Operation op;
    
    struct {
        unsigned tcp:1;
        unsigned udp:1;     /* -sU */
        unsigned sctp:1;
        unsigned ping:1;    /* --ping, ICMP 探测 */
        unsigned arp:1;     /* --arp, 本地 ARP 扫描 */
        unsigned oproto:1;  /* -sO */
    } scan_type;
    
    /**
     * 配置扫描类型之后，添加这些端口
     */
    unsigned top_ports;
    
    /**
     * 将参数回送到的临时文件，用于将配置保存到文件中
     */
    FILE *echo;
    unsigned echo_all;

    /**
     * 我们将使用一个或多个网络适配器进行扫描。
     * 每个适配器应该有一组单独的IP源地址，PF_RING dnaX:Y适配器除外。
     */
    struct {
        char ifname[256];
        struct Adapter *adapter;
        struct Source src;
        unsigned char my_mac[6];
        unsigned char router_mac[6];
        unsigned router_ip;
        int link_type; /* 根据 libpcap 定义的 */
        unsigned char my_mac_count; /*是否有MAC地址? */
        unsigned vlan_id;
        unsigned is_vlan:1;
    } nic[8];
    unsigned nic_count;

    /**
     * 扫描中包含的IPv4地址的目标范围。
     * 用户可以在这里指定任何内容，我们将解决所有重叠
     * 诸如此类，并对目标范围进行排序。
     */
    struct RangeList targets;
    struct Range6List targets_ipv6;

    /**
     * 我们正在扫描的端口。用户可以指定重复端口
     * 和重叠的范围，但我们会去复制他们，扫描端口只有一次。
     * 注意:TCP端口存储0-64k，而UDP端口存储在
     * 范围64k-128k，因此，允许我们同时扫描两者。
     */
    struct RangeList ports;
    
    /**
     * 只输出这些类型的Banners
     */
    struct RangeList banner_types;

    /**
     * 要从扫描中排除IPv4地址/范围。
     * 这需要优先于任何“包含”语句。
     * 事情是这样的:
     *  之后所有配置已读取，然后应用排除/黑名单在目标/白名单的顶部，只留下一个目标/白名单。
     *  因此，在扫描期间，我们只选择目标/白名单和不要查阅排除/黑名单。
     */
    struct RangeList exclude_ip;
    struct RangeList exclude_port;
    struct Range6List exclude_ipv6;


    /**
     * 最大速率，单位为包每秒(—速率参数)。这可以每秒数据包的一小部分，或高达30000000.0
     * (或实际上更多，但我只测试了3000万个应用程序)。
     */
    double max_rate;

    /**
     * 重试次数(—重试或—max-重试参数)。重试间隔几秒钟。
     */
    unsigned retries;

    
    unsigned is_pfring:1;       /* --pfring */
    unsigned is_sendq:1;        /* --sendq */
    unsigned is_banners:1;      /* --banners */
    unsigned is_offline:1;      /* --offline */
    unsigned is_noreset:1;      /* --noreset, 不发送 RST */
    unsigned is_gmt:1;          /* --gmt, 所有时间按 GMT 时区 */
    unsigned is_capture_cert:1; /* --capture cert */
    unsigned is_capture_html:1; /* --capture html */
    unsigned is_capture_heartbleed:1; /* --capture heartbleed */
    unsigned is_capture_ticketbleed:1; /* --capture ticket （ticketbleed） */
    unsigned is_test_csv:1;     /* (临时测试使用) */
    unsigned is_infinite:1;     /* -infinite */
    unsigned is_readscan:1;     /* --readscan, Operation_Readscan */
    unsigned is_heartbleed:1;   /* --heartbleed, 漏洞扫描 */
    unsigned is_ticketbleed:1;  /* --ticketbleed, 漏洞扫描 */
    unsigned is_poodle_sslv3:1; /* --vuln poodle, 漏洞扫描 */
    unsigned is_hello_ssl:1;    /* --ssl, 发SSL HELLO到被扫描端口 */
    unsigned is_hello_smbv1:1;  /* --smbv1,发SMBv1 hello,不是v1/v2 hello（非兼容模式） */
    unsigned is_scripting:1;    /* 是否需要脚本 */
        
    /**
     * 永远等待响应，而不是默认的10秒
     */
    unsigned wait;

    /**
     * --resume
     * 此结构包含暂停扫描的选项(通过退出程序)，稍后重新启动。
     */
    struct {
        /** --resume-index */
        uint64_t index;
        
        /** --resume-count */
        uint64_t count;
        
        /** 派生 --resume-index 从目标的 ip:port */
        struct {
            unsigned ip;
            unsigned port;
        } target;
    } resume;

    /**
     * --shard n/m
     * 这是用来分配扫描跨多个“分配”。每一个
     * 扫描中的碎片必须知道碎片的总数，而且还必须知道
     * 知道哪些碎片是它的身份。因此，碎片1/5扫描
     * 与2/5的范围不同。这些数从1开始，所以是
     * 1/3(三分之一)、2/3和3/3(但不是0/3)。
     */
    struct {
        unsigned one;
        unsigned of;
    } shard;

    /**
     * 我们当前使用的包模板集。
     * 我们存储一个二进制模板用于TCP、UDP、SCTP、ICMP等。
     * 所有使用该协议的扫描,然后使用基本模板。
     * IP和TCP选项可以是添加到基本模板的，因此不影响任何其他系统的组件。
     */
    struct TemplateSet *pkt_template;

    /**
     * 可重复配置的随机化种子。
     */
    uint64_t seed;
    
    /**
     * 此块配置我们为输出文件所做的操作
     */
    struct OutputStuff {
        
        /**
         * --output-format
         * 例如 "xml", "binary", "json", "ndjson", "grepable"等等.
         */
        enum OutputFormat format;
        
        /**
         * --output-filename
         * 存放扫描结果的文件的名称。
         * 注意:文件名“-”表示我们应该将文件发送到标准输出而不是一个文件。
         */
        char filename[256];
        
        /**
         * XML输出的一个特性，我们可以在其中插入一个可选的
         * 将样式表放入文件中，以便在web浏览器上更好地呈现
         */
        char stylesheet[256];

        /**
         * --append
         * 我们应该附加到输出文件中，而不是覆盖它。
         */
        unsigned is_append:1;
        
        /**
         * --open
         * --open-only
         * --show open
         * 是否显示打开的端口
         */
        unsigned is_show_open:1;
        
        /**
         * --show closed
         * 是否显示关闭的端口 (i.e. RSTs)
         */
        unsigned is_show_closed:1;
        
        /**
         * --show host
         * 是否显示主机消息而不是关闭的端口
         */
        unsigned is_show_host:1;
        
        /**
         * 打印端口是打开的原因，这对我们来说是多余的
         */
        unsigned is_reason:1;
    
        /**
         * --interactive
         * 打印到命令行，同时写入输出文件。
         * 如果输出格式已经是“交互式的”(默认)，
         * 但仅当默认输出格式为其他格式时，且用户还需要交互性。
         */
        unsigned is_interactive:1;
        
        /**
        * 打印状态更新
        */
        unsigned is_status_updates:1;

        struct {
            /**
             * 按多少偏移分割输出。
             */
            unsigned timeout;
            
            /**
             * 我们时间分割时，按GMT时区，因此需要配置时区偏移。
             */
            unsigned offset;
            
            /**
             * 除了按时间分割，我们可以按文件大小分割 
             */
            uint64_t filesize;
            
            /**
             * 存放自动分割文件的路径
             */
            char directory[256];
        } rotate;
    } output;

    struct {
        unsigned data_length; /* 随机化数据长度 */
        unsigned ttl; /* 最初的 IP TTL 值 */
        unsigned badsum; /* 错误的 TCP/UDP/SCTP 校验和 */

        unsigned packet_trace:1; /* 打印数据包信息 */
        
        char datadir[256];
    } nmap;

    char pcap_filename[256];

    struct {
        unsigned timeout;
    } tcb;

    struct {
        char *pcap_payloads_filename;
        char *nmap_payloads_filename;
        char *nmap_service_probes_filename;
    
        struct PayloadsUDP *udp;
        struct PayloadsUDP *oproto;
        struct TcpCfgPayloads *tcp;
        struct NmapServiceProbeList *probes;
    } payloads;
    
    unsigned char *http_user_agent;
    unsigned http_user_agent_length;
    unsigned tcp_connection_timeout;
    
    /** HELLO发送前的预期等待时间，对于一些协议如FTP或VNC，发送等待应更长些 */
    unsigned tcp_hello_timeout;

    struct {
        const char *header_name;
        unsigned char *header_value;
        unsigned header_value_length;
    } http_headers[16];

    char *bpf_filter;

    struct {
        unsigned ip;
        unsigned port;
    } redis;



    /**
     * --min-packet
     */
    unsigned min_packet_size;

    /**
     * BlackRock随机轮数
     * --blackrock-rounds
     */
    unsigned blackrock_rounds;
    
    /**
     * --script <name>
     */
    struct {
        /* 脚本名称 */
        char *name;
        
        /* 脚本解释器 */
        struct lua_State *L;
    } scripting;

    
    /**
     * --vuln <name>
     * 要检查漏洞的名称，比如“poodle”
     */
    const char *vuln_name;

};


int mainconf_selftest(void);
void masscan_read_config_file(struct Masscan *masscan, const char *filename);
void masscan_command_line(struct Masscan *masscan, int argc, char *argv[]);
void masscan_usage(void);
void masscan_save_state(struct Masscan *masscan);
void main_listscan(struct Masscan *masscan);

/**
 * 加载数据库, 例如:
 *  - nmap-payloads
 *  - nmap-service-probes
 *  - pcap-payloads
 */
void masscan_load_database_files(struct Masscan *masscan);

/**
 * 预先扫描命令行，寻找可能影响前面的选项处理方式的选项。这是一个有点拼凑，真的.
 */
int masscan_conf_contains(const char *x, int argc, char **argv);

/**
 *读取选项集合 <name=value> 键值对.
 */
void
masscan_set_parameter(struct Masscan *masscan,
                      const char *name, const char *value);



int
masscan_initialize_adapter(
    struct Masscan *masscan,
    unsigned index,
    unsigned char *adapter_mac,
    unsigned char *router_mac);

#endif
