#include "output.h"
#include "masscan-app.h"
#include "masscan-status.h"
#include "string_s.h"

//-Q6-XML-输出文本文件格式-xml

/****************************************************************************
 ****************************************************************************/
static void
xml_out_open(struct Output *out, FILE *fp)  //-Q6-才看到FP是参数，这操作会不会阻塞线程？如果我硬盘卡死的话。
{
    //const struct Masscan *masscan = out->masscan;

    fprintf(fp, "<?xml version=\"1.0\"?>\r\n");
    fprintf(fp, "<!-- masscan v1.0 scan -->\r\n");
    if (out->xml.stylesheet && out->xml.stylesheet[0]) {
        fprintf(fp, "<?xml-stylesheet href=\"%s\" type=\"text/xsl\"?>\r\n",
            out->xml.stylesheet);
    }
    fprintf(fp, "<nmaprun scanner=\"%s\" start=\"%u\" version=\"%s\"  xmloutputversion=\"%s\">\r\n",
        "masscan",
        (unsigned)time(0),
        "1.0-BETA",
        "1.03" /* xml output version I copied from their site */
        );
    fprintf(fp, "<scaninfo type=\"%s\" protocol=\"%s\" />\r\n",
        "syn", "tcp" );
}//-Q6-XML-开始扫描之后，为输出xml格式的文件添加xml文件头。


/****************************************************************************
 ****************************************************************************/
static void
xml_out_close(struct Output *out, FILE *fp)
{
    char buffer[256];
    time_t now = time(0);
    struct tm tm;

    if (out->is_gmt)
        gmtime_s(&tm, &now);
    else
        localtime_s(&tm, &now);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);

    fprintf(fp,
             "<runstats>\r\n"
              "<finished time=\"%u\" timestr=\"%s\" elapsed=\"%u\" />\r\n"
              "<hosts up=\"%" PRIu64 "\" down=\"%" PRIu64 "\" total=\"%" PRIu64 "\" />\r\n"
             "</runstats>\r\n"
            "</nmaprun>\r\n",
            (unsigned)now,                    /* time */
            buffer,                 /* timestr */
            (unsigned)(now - out->rotate.last), /* elapsed */
            out->counts.tcp.open,
            out->counts.tcp.closed,
            out->counts.tcp.open + out->counts.tcp.closed
            );

}//-Q6-XML-结束扫描时，对xml添加文件尾。

/****************************************************************************
 ****************************************************************************/
static void
xml_out_status(struct Output *out, FILE *fp, time_t timestamp, int status,
               unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl)
{
    char reason_buffer[128];
    UNUSEDPARM(out);
    fprintf(fp, "<host endtime=\"%u\">"
                    "<address addr=\"%u.%u.%u.%u\" addrtype=\"ipv4\"/>"
                    "<ports>"
                    "<port protocol=\"%s\" portid=\"%u\">"
                    "<state state=\"%s\" reason=\"%s\" reason_ttl=\"%u\"/>"
                    "</port>"
                    "</ports>"
                "</host>"
                "\r\n",
        (unsigned)timestamp,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        name_from_ip_proto(ip_proto),
        port,
        status_string(status),
        reason_string(reason, reason_buffer, sizeof(reason_buffer)),
        ttl
        );
}//-Q6-XML-按既定格式，存储对应数据内容。

/****************************************************************************
 ****************************************************************************/
static void
xml_out_banner(struct Output *out, FILE *fp, time_t timestamp,
        unsigned ip, unsigned ip_proto, unsigned port,
        enum ApplicationProtocol proto, 
        unsigned ttl,
        const unsigned char *px, unsigned length)
{
    char banner_buffer[4096];
    const char *reason;

    switch (proto) {
    case 6: reason = "syn-ack"; break;
    default: reason = "response"; break;
    }

    UNUSEDPARM(out);

    fprintf(fp, "<host endtime=\"%u\">"
                    "<address addr=\"%u.%u.%u.%u\" addrtype=\"ipv4\"/>"
                    "<ports>"
                    "<port protocol=\"%s\" portid=\"%u\">"
                      "<state state=\"open\" reason=\"%s\" reason_ttl=\"%u\" />"
                      "<service name=\"%s\" banner=\"%s\"></service>"
                    "</port>"
                    "</ports>"
                "</host>"
                "\r\n",
        (unsigned)timestamp,
        (ip>>24)&0xFF,
        (ip>>16)&0xFF,
        (ip>> 8)&0xFF,
        (ip>> 0)&0xFF,
        name_from_ip_proto(ip_proto),
        port,
        reason, ttl,
        masscan_app_to_string(proto),
        normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
        );
}//-Q6-XML-存储Banner的模板行及内容读取过程

/****************************************************************************
 ****************************************************************************/
const struct OutputType xml_output = {
    "xml",
    0,
    xml_out_open,
    xml_out_close,
    xml_out_status,
    xml_out_banner
}; //-Q6-XML-注册输出插件（对应头文件定义）

