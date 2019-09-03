#include "output.h"
#include "masscan.h"
#include "masscan-version.h"
#include "masscan-status.h"
#include "out-tcp-services.h"
#include "templ-port.h"
#include "string_s.h"


/****************************************************************************
 ****************************************************************************/
static unsigned
count_type(const struct RangeList *ports, int start_type, int end_type)
{
    unsigned min_port = start_type;
    unsigned max_port = end_type;
    unsigned i;
    unsigned result = 0;

    for (i=0; i<ports->count; ports++) {
        struct Range r = ports->list[i];
        if (r.begin > max_port)
            continue;
        if (r.end < min_port)
            continue;

        if (r.begin < min_port)
            r.begin = min_port;
        if (r.end > max_port)
            r.end = max_port;


        result += r.end - r.begin + 1;
    }

    return result;
}

/****************************************************************************
 ****************************************************************************/
static void
print_port_list(const struct RangeList *ports, int type, FILE *fp)
{
    unsigned min_port = type;
    unsigned max_port = type + 65535;
    unsigned i;

    for (i=0; i<ports->count; ports++) {
        struct Range r = ports->list[i];
        if (r.begin > max_port)
            continue;
        if (r.end < min_port)
            continue;

        if (r.begin < min_port)
            r.begin = min_port;
        if (r.end > max_port)
            r.end = max_port;

        fprintf(fp, "%u-%u%s", r.begin, r.end, (i+1<ports->count)?",":"");
    }
}

extern const char *debug_recv_status;

/****************************************************************************
 * 这个函数并不能真正“打开”文件。相反，这个函数的目的是通过打印头信息来初始化文件。
 ****************************************************************************/
static void
grepable_out_open(struct Output *out, FILE *fp)
{
    char timestamp[64];
    struct tm tm;
    unsigned count;

    
    gmtime_s(&tm, &out->when_scan_started);

    //Tue Jan 21 20:23:22 2014
    //%a %b %d %H:%M:%S %Y
    strftime(timestamp, sizeof(timestamp), "%c", &tm);

    fprintf(fp, "# Masscan " MASSCAN_VERSION " scan initiated %s\n", 
                timestamp);

    count = count_type(&out->masscan->ports, Templ_TCP, Templ_TCP_last);
    fprintf(fp, "# Ports scanned: TCP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_TCP, fp);

    count = count_type(&out->masscan->ports, Templ_UDP, Templ_UDP_last);
    fprintf(fp, ") UDP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_UDP, fp);
    
    
    count = count_type(&out->masscan->ports, Templ_SCTP, Templ_SCTP_last);
    fprintf(fp, ") SCTP(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_SCTP, fp);

    count = count_type(&out->masscan->ports, Templ_Oproto_first, Templ_Oproto_last);
    fprintf(fp, ") PROTOCOLS(%u;", count);
    if (count)
        print_port_list(&out->masscan->ports, Templ_Oproto_first, fp);
    
    fprintf(fp, ")\n");
}

/****************************************************************************
 * 这个函数并没有真正“关闭”文件。相反，它的目的是将跟踪信息打印到文件中。
 * 这只是需要在末尾添加内容的XML文件所关心的问题。
 ****************************************************************************/
static void
grepable_out_close(struct Output *out, FILE *fp)
{
    time_t now = time(0);
    char timestamp[64];
    struct tm tm;

    UNUSEDPARM(out);

    gmtime_s(&tm, &now);

    //Tue Jan 21 20:23:22 2014
    //%a %b %d %H:%M:%S %Y
    strftime(timestamp, sizeof(timestamp), "%c", &tm);

    fprintf(fp, "# Masscan done at %s\n", 
                timestamp);
}

/****************************************************************************
 * 打印端口的状态，端口几乎总是“打开”或“关闭”。
 ****************************************************************************/
static void
grepable_out_status(struct Output *out, FILE *fp, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    const char *service;
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(reason);
    UNUSEDPARM(ttl);

    if (ip_proto == 6)
        service = tcp_service_name(port);
    else if (ip_proto == 17)
        service = udp_service_name(port);
    else
        service = oproto_service_name(ip_proto);
    
    fprintf(fp, "Timestamp: %lu", timestamp);

    fprintf(fp, "\tHost: %u.%u.%u.%u ()",
                    (unsigned char)(ip>>24),
                    (unsigned char)(ip>>16),
                    (unsigned char)(ip>> 8),
                    (unsigned char)(ip>> 0)
                    );
    fprintf(fp, "\tPorts: %u/%s/%s/%s/%s/%s/%s\n",
                port,
                status_string(status),      //"open", "closed"
                name_from_ip_proto(ip_proto),  //"tcp", "udp", "sctp"
                "", //owner
                service, //service
                "", //SunRPC info
                "" //Version info
                );
}

/****************************************************************************
 * 为端口打印“banner”信息。这是在有为端口定义的协议，我们做一些交互来找出
 * 关于哪个协议在端口上运行的更多信息，它的版本，及其他有用资料。
 ****************************************************************************/
static void
grepable_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, unsigned ttl,
        const unsigned char *px, unsigned length)
{
    char banner_buffer[4096];

    UNUSEDPARM(ttl);
    UNUSEDPARM(timestamp);
    UNUSEDPARM(out);
    UNUSEDPARM(ip_proto);
    
    fprintf(fp, "Host: %u.%u.%u.%u ()",
                    (unsigned char)(ip>>24),
                    (unsigned char)(ip>>16),
                    (unsigned char)(ip>> 8),
                    (unsigned char)(ip>> 0)
                    );
    fprintf(fp, "\tPort: %u", port);

    fprintf(fp, "\tService: %s", masscan_app_to_string(proto));

    normalize_string(px, length, banner_buffer, sizeof(banner_buffer));

    fprintf(fp, "\tBanner: %s\n", banner_buffer);

}



/****************************************************************************
 * 这是向系统其余部分公开的唯一结构。一切
 * 文件中的else被定义为“静态”或“私有”。
 ****************************************************************************/
const struct OutputType grepable_output = {
    "grepable",
    0,
    grepable_out_open,
    grepable_out_close,
    grepable_out_status,
    grepable_out_banner
};
