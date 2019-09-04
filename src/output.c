/*
    output logging/reporting
    
    脚本/版本控制在其后
    这是格式化输出文件的文件——也就是说，我们报告是从这里生成的。

    PLUGINS

    各种类型的输出(XML、二进制、Redis等)都写得很模糊
    作为“插件”，这意味着作为一个结构与函数指针。在
    将来，应该可以将插件编写为DDLs/共享对象
    并在运行时加载它们，但现在，它们只是硬编码。

    ROTATE

    文件可以“分段”。这是通过在文件前面加上
    创建文件的日期/时间。

    该设计的一个关键特性是防止文件丢失其中一段。
    因此，这些文件在仍然打开时将被重命名。
    如果重命名函数失败，则文件将保留在原处
    打开用于写入，并继续附加到文件中。

    因此，您可以启动程序日志记录到“——rotate-dir ./foobar”
    然后注意到错误信息说分段不起作用，然后创建“foobar”目录，此时分段功能正常——只是第一个分段的文件将包含几个区间段的数据。
*/

/* Linux需要64位的偏移量 */
#define _FILE_OFFSET_BITS 64

#include "output.h"
#include "masscan.h"
#include "masscan-status.h"
#include "string_s.h"
#include "logger.h"
#include "proto-banner1.h"
#include "masscan-app.h"
#include "main-globals.h"
#include "pixie-file.h"
#include "pixie-sockets.h"
#include "util-malloc.h"

#include <limits.h>
#include <ctype.h>
#include <string.h>


/*****************************************************************************
 *****************************************************************************/
static int64_t ftell_x(FILE *fp)
{
#if defined(WIN32) && defined(__GNUC__)
    return ftello64(fp);
#elif defined(WIN32) && defined(_MSC_VER)
    return _ftelli64(fp);
#else
    return ftello(fp);
#endif
}

/*****************************************************************************
 * “status”变量包含打开/关闭信息和
 * 协议信息。这将它拆分成两个值。
 *****************************************************************************/
const char *
name_from_ip_proto(unsigned ip_proto)
{
    switch (ip_proto) {
        case 0: return "arp";
        case 1: return "icmp";
        case 6: return "tcp";
        case 17: return "udp";
        case 132: return "sctp";
        default: return "err";
    }
}


/*****************************************************************************
 * 实际的“status”变量根据底层协议。这个函数创建一个粗略的“open” “关闭”
 * 基于窄变量的字符串。
 *****************************************************************************/
const char *
status_string(enum PortStatus status)
{
    switch (status) {
        case PortStatus_Open: return "open";
        case PortStatus_Closed: return "closed";
        case PortStatus_Arp: return "up";
        default: return "unknown";
    }
}


/*****************************************************************************
 * 将TCP标志转换为nmap样式的“reason”字符串
 *****************************************************************************/
const char *
reason_string(int x, char *buffer, size_t sizeof_buffer)
{
    sprintf_s(buffer, sizeof_buffer, "%s%s%s%s%s%s%s%s",
        (x&0x01)?"fin-":"",
        (x&0x02)?"syn-":"",
        (x&0x04)?"rst-":"",
        (x&0x08)?"psh-":"",
        (x&0x10)?"ack-":"",
        (x&0x20)?"urg-":"",
        (x&0x40)?"ece-":"",
        (x&0x80)?"cwr-":""
        );
    if (buffer[0] == '\0')
        return "none";
    else
        buffer[strlen(buffer)-1] = '\0';
    return buffer;
}


/*****************************************************************************
 * 从横幅中删除不好的字符，特别是新行和HTML
 * 控制代码。
 *****************************************************************************/
const char *
normalize_string(const unsigned char *px, size_t length,
                 char *buf, size_t buf_len)
{
    size_t i=0;
    size_t offset = 0;


    for (i=0; i<length; i++) {
        unsigned char c = px[i];

        if (isprint(c) && c != '<' && c != '>' && c != '&' && c != '\\' && c != '\"' && c != '\'') {
            if (offset + 2 < buf_len)
                buf[offset++] = px[i];
        } else {
            if (offset + 5 < buf_len) {
                buf[offset++] = '\\';
                buf[offset++] = 'x';
                buf[offset++] = "0123456789abcdef"[px[i]>>4];
                buf[offset++] = "0123456789abcdef"[px[i]&0xF];
            }
        }
    }

    buf[offset] = '\0';

    return buf;
}


/*****************************************************************************
 * PORTABILITY: WINDOWS
 *
 * Windows POSIX函数在没有“share-delete”标志的情况下打开文件，
 * 意味着它们不能在打开时重命名。因此，我们需要
 * 建立我们自己的开放标志。
 *****************************************************************************/
static FILE *
open_rotate(struct Output *out, const char *filename)
{
    FILE *fp = 0;
    unsigned is_append = out->is_append;
    int x;

    /*
     * KLUDGE: do something special for redis
     */
    if (out->format == Output_Redis) {
        ptrdiff_t fd = out->redis.fd;
        if (fd < 1) {
            struct sockaddr_in sin = {0};
            fd = (ptrdiff_t)socket(AF_INET, SOCK_STREAM, 0);
            if (fd == -1) {
                LOG(0, "redis: socket() failed to create socket\n");
                exit(1);
            }
            sin.sin_addr.s_addr = htonl(out->redis.ip);
            sin.sin_port = htons((unsigned short)out->redis.port);
            sin.sin_family = AF_INET;
            x = connect((SOCKET)fd, (struct sockaddr*)&sin, sizeof(sin));
            if (x != 0) {
                LOG(0, "redis: connect() failed\n");
                perror("connect");
            }
            out->redis.fd = fd;
        }
        out->funcs->open(out, (FILE*)fd);

        return (FILE*)fd;
    }

    /* 特殊处理带‘-’的文件名 */
    if (filename[0] == '-' && filename[1] == '\0')
        fp = stdout;

    /* 打开一个“共享”文件。在Windows上，默认情况下文件不能重命名。当它们打开时，我们需要一个特殊的函数来处理 */
    if (fp == 0) {
        x = pixie_fopen_shareable(&fp, filename, is_append);
        if (x != 0 || fp == NULL) {
            fprintf(stderr, "out: could not open file for %s\n",
                    is_append?"appending":"writing");
            perror(filename);
            is_tx_done = 1;
            return NULL;
        }
    }

    /*
     * 将文件标记为新打开的。这样，在向它写入任何数据之前，我们首先必须编写文件头
     */
    out->is_virgin_file = 1;

    return fp;
}


/*****************************************************************************
 * 将剩余的数据写入文件并关闭它。这个函数是
 * 名为“rotate”，但它实际上并不旋转，这个名称只是反映了如何在分割过程中使用.
 *****************************************************************************/
static void
close_rotate(struct Output *out, FILE *fp)
{
    if (out == NULL)
        return;
    if (fp == NULL)
        return;

    /*
     * 写入格式定义的尾部 </xml>
     */
    if (!out->is_virgin_file)
        out->funcs->close(out, fp);

    memset(&out->counts, 0, sizeof(out->counts));

    /* Redis 手工处理 */
    if (out->format == Output_Redis)
        return;

    fflush(fp);
    fclose(fp);
}


/*****************************************************************************
 * 返回下一次分割发生的时间。分割是与周期对齐，这意味着
 * 如果每小时旋转一次，就完成了每小时准时，比如9点整。换句话说,一段“每小时”并不意味着“每60分钟”，但是准一个小时”。
 * 由于该项目将在一段时间内启动，这意味着第一次分割将在不到一个完整周期内发生。
 *****************************************************************************/
static time_t
next_rotate_time(time_t last_rotate, unsigned period, unsigned offset)
{
    time_t next;

    next = last_rotate - (last_rotate % period) + period + offset;

    return next;
}


#if 0
/*****************************************************************************
 *****************************************************************************/
static int
ends_with(const char *filename, const char *extension)
{
    if (filename == NULL || extension == NULL)
        return 0;
    if (strlen(filename) + 1 < strlen(extension))
        return 0;
    if (memcmp(filename + strlen(filename) - strlen(extension),
                extension, strlen(extension)) != 0)
        return 0;
    if (filename[strlen(filename) - strlen(extension) - 1] != '.')
        return 0;

    return 1;
}
#endif

/*****************************************************************************
 * strdup():编译器不喜欢strdup()，所以我在这里只编写自己的代码。我也许应该找到更好的解决方案。
 *****************************************************************************/
static char *
duplicate_string(const char *str)
{
    size_t length;
    char *result;

    /* 找出字符串的长度。在这种情况下，我们允许空字符串长度为零 */
    if (str == NULL)
        length = 0;
    else
        length = strlen(str);

    /* 为字符串分配内存 */
    result = MALLOC(length + 1);
    

    /* 拷贝字符串 */
    if (str)
        memcpy(result, str, length+1);
    result[length] = '\0';

    return result;
}

/*****************************************************************************
 * 在文件扩展名之前添加索引变量。例如,
 * 如果原始文件名是“foo”。，下标为1，则
 * 新文件名变成“foo.01.bar”。将索引放在
 * 扩展名，它保留文件类型。通过在索引前加上一个0，
 * 它允许多达100个文件，同时仍然能够轻松地排序文件。
 *****************************************************************************/
static char *
indexed_filename(const char *filename, unsigned index)
{
    size_t len = strlen(filename);
    size_t ext;
    char *new_filename;
    size_t new_length = strlen(filename) + 32;

    /* 查找扩展名 */
    ext = len;
    while (ext) {
        ext--;
        if (filename[ext] == '.')
            break;
        if (filename[ext] == '/' || filename[ext] == '\\') {
            /* 未找到，当前扩展名为文件名尾 */
            ext = len;
            break;
        }
    }
    if (ext == 0 && len > 0 && filename[0] != '.')
        ext = len;

    /* 分配内存 */
    new_filename = MALLOC(new_length);
    

    /* 格式化新文件名 */
    sprintf_s(new_filename, new_length, "%.*s.%02u%s",
              (unsigned)ext, filename,
              index,
              filename+ext);

    return new_filename;

}

/*****************************************************************************
 * 创建一个“输出”结构。如果正在编写文件，则创建，以便立即捕获创建文件的任何错误，而不是等到扫描可能失败的时候.
 *****************************************************************************/
struct Output *
output_create(const struct Masscan *masscan, unsigned thread_index)
{
    struct Output *out;
    unsigned i;

    /* allocate/initialize memory */
    out = CALLOC(1, sizeof(*out));
    out->masscan = masscan;
    out->when_scan_started = time(0);
    out->is_virgin_file = 1;

    /*
     * 从“masscan”结构复制配置信息。
     */
    out->rotate.period = masscan->output.rotate.timeout;
    out->rotate.offset = masscan->output.rotate.offset;
    out->rotate.filesize = masscan->output.rotate.filesize;
    out->redis.port = masscan->redis.port;
    out->redis.ip = masscan->redis.ip;
    out->is_banner = masscan->is_banners;
    out->is_gmt = masscan->is_gmt;
    out->is_interactive = masscan->output.is_interactive;
    out->is_show_open = masscan->output.is_show_open;
    out->is_show_closed = masscan->output.is_show_closed;
    out->is_show_host = masscan->output.is_show_host;
    out->is_append = masscan->output.is_append;
    out->xml.stylesheet = duplicate_string(masscan->output.stylesheet);
    out->rotate.directory = duplicate_string(masscan->output.rotate.directory);
    if (masscan->nic_count <= 1)
        out->filename = duplicate_string(masscan->output.filename);
    else
        out->filename = indexed_filename(masscan->output.filename, thread_index);

    for (i=0; i<8; i++) {
        out->src[i] = masscan->nic[i].src;
    }

    /*
     * 连接适当的输出模块。
     * TODO:支持多个输出模块
     */
    out->format = masscan->output.format;
    switch (out->format) {
    case Output_List:
        out->funcs = &text_output;
        break;
    case Output_Unicornscan:
        out->funcs = &unicornscan_output;
        break;
    case Output_XML:
        out->funcs = &xml_output;
        break;
    case Output_JSON:
        out->funcs = &json_output;
        break;
    case Output_NDJSON:
        out->funcs = &ndjson_output;
        break;
    case Output_Certs:
        out->funcs = &certs_output;
        break;
    case Output_Binary:
        out->funcs = &binary_output;
        break;
    case Output_Grepable:
        out->funcs = &grepable_output;
        break;
    case Output_Redis:
        out->funcs = &redis_output;
        break;
    case Output_None:
        out->funcs = &null_output;
        break;
    default:
        out->funcs = &null_output;
        break;
    }

    /*
     * 打开所需的输出文件。我们现在在扫描开始时做这个。
     * 因此，我们可以立即通知用户错误，而不是在长时间的扫描过程中等待，并让它失败。
     */
    if (masscan->output.filename[0] && out->funcs != &null_output) {
        FILE *fp;

        fp = open_rotate(out, masscan->output.filename);
        if (fp == NULL) {
            perror(masscan->output.filename);
            exit(1);
        }

        out->fp = fp;
        out->rotate.last = time(0);
    }

    /*
     * 设置下一次分割的时间。如果我们不分割文件，那么
     * 这个时间将在未来被设置为“无穷大”。
     * TODO:这段代码不兼容Y2036。
     */
    if (masscan->output.rotate.timeout == 0) {
        /* TODO:如何找到max time_t值?*/
        out->rotate.next = (time_t)LONG_MAX;
    } else {
        if (out->rotate.offset > 1) {
            out->rotate.next = next_rotate_time(
                                    out->rotate.last-out->rotate.period,
                                    out->rotate.period, out->rotate.offset);
        } else {
            out->rotate.next = next_rotate_time(
                                    out->rotate.last,
                                    out->rotate.period, out->rotate.offset);
        }
    }



    return out;
}


/*****************************************************************************
 * 分割文件，将其从本地目录移动到远程目录
 * 并更改名称以包含时间戳。这是在处理文件时完成的
 * 仍然打开:我们先移动文件并重命名它，然后关闭它。
 *****************************************************************************/
static FILE *
output_do_rotate(struct Output *out, int is_closing)
{
    const char *dir = out->rotate.directory;
    const char *filename = out->filename;
    char *new_filename;
    size_t new_filename_size;
    struct tm tm;
    int err;

    /* 文件不存在直接跳过 */
    if (out == NULL || out->fp == NULL)
        return NULL;

    /* 确认缓冲写入文件 */
    fflush(out->fp);

    /* 从文件名删除根路径前缀，只需要文件名 */
    while (strchr(filename, '/') || strchr(filename, '\\')) {
        filename = strchr(filename, '/');
        if (*filename == '/')
            filename++;
        filename = strchr(filename, '\\');
        if (*filename == '\\')
            filename++;
    }

    /* 为新文件名分配内存 */
    new_filename_size =     strlen(dir)
                            + strlen("/")
                            + strlen(filename)
                            + strlen("1308201101-")
                            + strlen(filename)
                            + 1  /* - */
                            + 1; /* nul */
    new_filename = MALLOC(new_filename_size);

    /* 获取文件的适当时间戳 */
    if (out->is_gmt) {
        err = gmtime_s(&tm, &out->rotate.last);
    } else {
        err = localtime_s(&tm, &out->rotate.last);
    }
    if (err != 0) {
        free(new_filename);
        perror("gmtime(): file rotation ended");
        return out->fp;
    }


    /* 寻找一个与现有名称不冲突的名称。如果所需的文件已经存在，则增加文件名。这种事永远不应该发生。 */
    err = 0;
again:
    if (out->rotate.filesize) {
        size_t x_off=0, x_len=0;
        if (strrchr(filename, '.')) {
            x_off = strrchr(filename, '.') - filename;
            x_len = strlen(filename + x_off);
        } else {
            x_off = strlen(filename);
            x_len = 0;
        }
        sprintf_s(new_filename, new_filename_size,
                      "%s/%.*s-%05u%.*s",
                dir,
                (unsigned)x_off, filename,
                out->rotate.filecount++,
                (unsigned)x_len, filename + x_off
                );
    } else {
        sprintf_s(new_filename, new_filename_size,
                  "%s/%02u%02u%02u-%02u%02u%02u" "-%s",
            dir,
            tm.tm_year % 100,
            tm.tm_mon+1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            filename);
        if (access(new_filename, 0) == 0) {
            tm.tm_sec++;
            if (err++ == 0)
                goto again;
        }
    }
    filename = out->filename;

    /*
     * Move the file
     */
    err = rename(filename, new_filename);
    if (err) {
        LOG(0, "rename(\"%s\", \"%s\"): failed\n", filename, new_filename);
        perror("rename()");
        free(new_filename);
        return out->fp;
    }

    /*
     * 设置下一个分割时间，即当前时间加上周期长度
     */
    out->rotate.bytes_written = 0;

    if (out->rotate.period) {
        out->rotate.next = next_rotate_time(time(0),
                                        out->rotate.period, out->rotate.offset);
    }

    LOG(1, "rotated: %s\n", new_filename);
    free(new_filename);

    /*
     * 创建新文件
     */
    if (is_closing)
        out->fp = NULL; /* 程序正在退出，不创建新文件 */
    else {
        FILE *fp;

        fp = open_rotate(out, filename);
        if (fp == NULL) {
            LOG(0, "rotate: %s: failed: %s\n", filename, strerror_x(errno));
        } else {
            close_rotate(out, out->fp);
            out->fp = fp;
            out->rotate.last = time(0);
            LOG(1, "rotate: started new file: %s\n", filename);
        }
    }
    return out->fp;
}

/***************************************************************************
 ***************************************************************************/
static int
is_rotate_time(const struct Output *out, time_t now, FILE *fp)
{
    if (out->is_virgin_file)
        return 0;
    if (now >= out->rotate.next)
        return 1;
    if (out->rotate.filesize != 0 &&
        ftell_x(fp) >= (int64_t)out->rotate.filesize)
        return 1;
    return 0;
}

/***************************************************************************
 * 返回匹配MAC地址前三个字节的vendor/OUI字符串。
 * TODO:这应该从文件中读取
 ***************************************************************************/
static const char *
oui_from_mac(const unsigned char mac[6])
{
    unsigned oui = mac[0]<<16 | mac[1]<<8 | mac[2];
    switch (oui) {
    case 0x0001c0: return "Compulab";
    case 0x000732: return "Aaeon";
    case 0x000c29: return "VMware";
    case 0x001075: return "Seagate";
    case 0x001132: return "Synology";
    case 0x022618: return "Asus";
    case 0x0022b0: return "D-Link";
    case 0x00236c: return "Apple";
    case 0x0016CB: return "Apple";
    case 0x001e06: return "Odroid";
    case 0x001ff3: return "Apple";
    case 0x002590: return "Supermicro";
    case 0x08cc68: return "Cisco";
    case 0x0C9D92: return "Asus";
    case 0x244CE3: return "Amazon";
    case 0x2c27d7: return "HP";
    case 0x3497f6: return "Asus";
    case 0x38f73d: return "Amazon";
    case 0x404a03: return "Zyxel";
    case 0x4C9EFF: return "Zyxel";
    case 0x5855CA: return "Apple";
    case 0x60a44c: return "Asus";
    case 0x6c72e7: return "Apple";
    case 0x9003b7: return "Parrot";
    case 0x94dbc9: return "Azurewave";
    case 0xacbc32: return "Apple";
    case 0xb827eb: return "Raspberry Pi";
    case 0xc05627: return "Belkin";
    case 0xc0c1c0: return "Cisco-Linksys";
    case 0xDCA4CA: return "Apple";
    case 0xe4956e: return "[random]";
    default: return "";
    }
}

/***************************************************************************
 * 只报告“打开”或“关闭”，几乎没有其他信息。
 * 当响应返回时，这将直接从receive线程调用。
 ***************************************************************************/
void
output_report_status(struct Output *out, time_t timestamp, int status,
        unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl,
        const unsigned char mac[6])
{
    FILE *fp = out->fp;
    time_t now = time(0);

    global_now = now;

    /* 如果定义 "--open"/"--open-only" 参数，则不报告关闭端口 */
    if (!out->is_show_closed && status == PortStatus_Closed)
        return;
    if (!out->is_show_open && status == PortStatus_Open)
        return;

    /* 如果配置 "--interactive" 模式, 打印获取到的Banners信息 */
    if (out->is_interactive || out->format == 0 || out->format == Output_Interactive) {
        unsigned count;

        switch (ip_proto) {
        case 0: /* ARP */
            count = fprintf(stdout, "Discovered %s port %u/%s on %u.%u.%u.%u (%02x:%02x:%02x:%02x:%02x:%02x) %s",
                        status_string(status),
                        port,
                        name_from_ip_proto(ip_proto),
                        (ip>>24)&0xFF,
                        (ip>>16)&0xFF,
                        (ip>> 8)&0xFF,
                        (ip>> 0)&0xFF,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        oui_from_mac(mac)
                        );
            break;
        default:
            count = fprintf(stdout, "Discovered %s port %u/%s on %u.%u.%u.%u",
                        status_string(status),
                        port,
                        name_from_ip_proto(ip_proto),
                        (ip>>24)&0xFF,
                        (ip>>16)&0xFF,
                        (ip>> 8)&0xFF,
                        (ip>> 0)&0xFF
                        );
        }

        /* 因为这一行可能会覆盖“%done”状态行，所以在后面打印一些空格来完全覆盖这一行 */
        if (count < 80)
            fprintf(stdout, "%.*s", (int)(79-count),
                    "                                          "
                    "                                          ");

        fprintf(stdout, "\n");
        fflush(stdout);

    }


    if (fp == NULL)
        return;

    /* 分割，如果超过了时间限制。
     * 在写输出时，只要有输出要写到文件，就会内联地分割日志文件，而不是在时间间隔时在单独的线程中。
     * 因此，如果结果来得很慢，分割就不会发生在精确的边界上 */
    if (is_rotate_time(out, now, fp)) {
        fp = output_do_rotate(out, 0);
        if (fp == NULL)
            return;
    }


    /* 保留一些统计数据，以便用户可以监视有多少内容被发现。 */
    switch (status) {
        case PortStatus_Open:
            switch (ip_proto) {
            case 1:
                out->counts.icmp.echo++;
                break;
            case 6:
                out->counts.tcp.open++;
                break;
            case 17:
                out->counts.udp.open++;
                break;
            case 132:
                out->counts.sctp.open++;
                break;
            default:
                out->counts.oproto.open++;
                break;
            }
            if (!out->is_show_open)
                return;
            break;
        case PortStatus_Closed:
            switch (ip_proto) {
            case 6:
                out->counts.tcp.closed++;
                break;
            case 17:
                out->counts.udp.closed++;
                break;
            case 132:
                out->counts.sctp.closed++;
                break;
            }
            if (!out->is_show_closed)
                return;
            break;
        case PortStatus_Arp:
            out->counts.arp.open++;
            break;
        default:
            LOG(0, "unknown status type: %u\n", status);
            return;
    }

    /*
     * 新文件写入文件头内容
     */
    if (out->is_virgin_file) {
        out->funcs->open(out, fp);
        out->is_virgin_file = 0;
    }

    /*
     * 无论什么格式，开始实际输出
     */
    out->funcs->status(out, fp, timestamp, status, ip, ip_proto, port, reason, ttl);
}


/***************************************************************************
 ***************************************************************************/
void
output_report_banner(struct Output *out, time_t now,
                unsigned ip, unsigned ip_proto, unsigned port,
                unsigned proto, 
                unsigned ttl, 
                const unsigned char *px, unsigned length)
{
    FILE *fp = out->fp;

    /* 如果我们不做横幅，那就什么都不要做。这是因为当做UDP扫描时，我们仍然会得到横幅信息解码响应包，即使用户不感兴趣 */
    if (!out->is_banner)
        return;

    /* 如果配置 "--interactive" 模式, 打印获取到的Banners信息 */
    if (out->is_interactive || out->format == 0 || out->format == Output_Interactive) {
        unsigned count;
        char banner_buffer[4096];

        count = fprintf(stdout, "Banner on port %u/%s on %u.%u.%u.%u: [%s] %s",
            port,
            name_from_ip_proto(ip_proto),
            (ip>>24)&0xFF,
            (ip>>16)&0xFF,
            (ip>> 8)&0xFF,
            (ip>> 0)&0xFF,
            masscan_app_to_string(proto),
            normalize_string(px, length, banner_buffer, sizeof(banner_buffer))
            );

        /* 打印空行防覆盖 */
        if (count < 80)
            fprintf(stdout, "%.*s", (int)(79-count),
                    "                                          "
                    "                                          ");

        fprintf(stdout, "\n");
    }

    /* 文件不存在跳过 */
    if (fp == NULL)
        return;

    /* 分割，如果超过了时间限制。
     * 在写输出时，只要有输出要写到文件，就会内联地分割日志文件，而不是在时间间隔时在单独的线程中。
     * 因此，如果结果来得很慢，分割就不会发生在精确的边界上 */
    if (is_rotate_time(out, now, fp)) {
        fp = output_do_rotate(out, 0);
        if (fp == NULL)
            return;
    }

    /*
     * 新文件写入文件头
     */
    if (out->is_virgin_file) {
        out->funcs->open(out, fp);
        out->is_virgin_file = 0;
    }

    /*
     * 开始输出
     */
    out->funcs->banner(out, fp, now, ip, ip_proto, port, proto, ttl, px, length);

}


/***************************************************************************
 * 每次退出或关闭时调用
 ***************************************************************************/
void
output_destroy(struct Output *out)
{
    if (out == NULL)
        return;

    /* 分割文件，进行最后一次分割 */
    if (out->rotate.period || out->rotate.filesize) {
        LOG(1, "doing finale rotate\n");
        output_do_rotate(out, 1);
    }

    /* 如果不分割文件，则只需关闭此文件。请记住，有些文件会在关闭文件之前编写关闭信息 */
    if (out->fp)
        close_rotate(out, out->fp);



    free(out->xml.stylesheet);
    free(out->rotate.directory);
    free(out->filename);

    free(out);
}


/*****************************************************************************
 * 输出模块单元测试
 *****************************************************************************/
int
output_selftest(void)
{
    char *f;

    f = indexed_filename("foo.bar", 1);
    if (strcmp(f, "foo.01.bar") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    f = indexed_filename("foo.b/ar", 2);
    if (strcmp(f, "foo.b/ar.02") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    f = indexed_filename(".foobar", 3);
    if (strcmp(f, ".03.foobar") != 0) {
        fprintf(stderr, "output: failed selftest\n");
        return 1;
    }
    free(f);

    return 0;
}

