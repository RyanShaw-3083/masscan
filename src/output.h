#ifndef OUTPUT_H
#define OUTPUT_H
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include "main-src.h"
#include "unusedparm.h"
#include "masscan-app.h"

struct Masscan;
struct Output;
enum ApplicationProtocol;
enum PortStatus;

/**
 * Output 插件
 *
 * 编写输出的各种方法本质上都是插件。随着新方法
 * 创建后，我们只需填充函数指针的结构。
 * TODO:这需要一个可加载的DLL，但与此同时，它只是
 * 内部结构。
 */
struct OutputType {
    const char *file_extension;
    void *(*create)(struct Output *out);
    void (*open)(struct Output *out, FILE *fp);
    void (*close)(struct Output *out, FILE *fp);
    void (*status)(struct Output *out, FILE *fp,
                   time_t timestamp, int status,
                   unsigned ip, unsigned ip_proto, unsigned port, 
                   unsigned reason, unsigned ttl);
    void (*banner)(struct Output *out, FILE *fp,
                   time_t timestamp, unsigned ip, unsigned ip_proto,
                   unsigned port, enum ApplicationProtocol proto,
                   unsigned ttl,
                   const unsigned char *px, unsigned length);
};

/**
 * Masscan为每个线程建立输出模块
 */
struct Output
{
    const struct Masscan *masscan;
    char *filename;
    struct Source src[8];
    FILE *fp;
    const struct OutputType *funcs;
    unsigned format;

    /**
     * 扫描开始时的时间戳。这保存在输出文件中。因为这就是nmap所做的，很多工具都会解析它。
     */
    time_t when_scan_started;

    /**
     * 是否已经开始写入文件。在真正开始编写之前，我们一直在延迟文件头的编写
     */
    unsigned is_virgin_file:1;
    
    /**
     * json输出使用它来测试是否看到了第一条记录，以便确定是否需要在记录前加上逗号
     */
    unsigned is_first_record_seen:1;

    struct {
        time_t next;
        time_t last;
        unsigned period;
        unsigned offset;
        uint64_t filesize;
        uint64_t bytes_written;
        unsigned filecount; /* 分割文件大小 */
        char *directory;
    } rotate;

    unsigned is_banner:1;
    unsigned is_gmt:1; /* --gmt */
    unsigned is_interactive:1; /* 直接输出命令行 */
    unsigned is_show_open:1; /* 显示开放的目标端口 (default) */
    unsigned is_show_closed:1; /* 显示关闭的目标端口 */
    unsigned is_show_host:1; /* 显示主机状态，例如 up/down */
    unsigned is_append:1; /* 追加模式 */
    struct {
        struct {
            uint64_t open;
            uint64_t closed;
            uint64_t banner;
        } tcp;  //-Q6-所以如RawSocket是不会记录为可打印的二进制数据的
        struct {
            uint64_t open;
            uint64_t closed;
        } udp;
        struct {
            uint64_t open;
            uint64_t closed;
        } sctp;
        struct {
            uint64_t echo;
            uint64_t timestamp;
        } icmp;
        struct {
            uint64_t open;
        } arp;
        struct {
            uint64_t open;
            uint64_t closed;
        } oproto;
    } counts;

    struct {
        unsigned ip;
        unsigned port;
        ptrdiff_t fd;
        uint64_t outstanding;
        unsigned state;
    } redis;
    struct {
        char *stylesheet;
    } xml;
};

const char *name_from_ip_proto(unsigned ip_proto);
const char *status_string(enum PortStatus x);
const char *reason_string(int x, char *buffer, size_t sizeof_buffer);
const char *normalize_string(const unsigned char *px, size_t length,
                             char *buf, size_t buf_len);


extern const struct OutputType text_output;
extern const struct OutputType unicornscan_output;
extern const struct OutputType xml_output;
extern const struct OutputType json_output;
extern const struct OutputType ndjson_output;
extern const struct OutputType certs_output;
extern const struct OutputType binary_output;
extern const struct OutputType null_output;
extern const struct OutputType redis_output;
extern const struct OutputType grepable_output;
//-Q6-新输出插件要在此处需要声明，便于外部调用。
/**
 * 创建一个“output”对象。这是由接收线程按顺序调用的
 * 向任何一方发送“状态”信息(打开/关闭端口)和“Banners”
 * 到命令行或特定格式的文件，如XML或Redis
 * @param masscan
 *      主配置数据结构.
 * @param thread_index
 *      一个以上接收线程以线程索引号区分
 * @return
 *      最终必须由output_destroy()销毁的输出对象。
 */
struct Output *
output_create(const struct Masscan *masscan, unsigned thread_index);

void output_destroy(struct Output *output);

void output_report_status(struct Output *output, time_t timestamp,
    int status, unsigned ip, unsigned ip_proto, unsigned port, unsigned reason, unsigned ttl,
    const unsigned char mac[6]);


typedef void (*OUTPUT_REPORT_BANNER)(
                struct Output *output, time_t timestamp,
                unsigned ip, unsigned ip_proto, unsigned port,
                unsigned proto, unsigned ttl,
                const unsigned char *px, unsigned length);

void output_report_banner(
                struct Output *output,
                time_t timestamp,
                unsigned ip, unsigned ip_proto, unsigned port,
                unsigned proto,
                unsigned ttl,
                const unsigned char *px, unsigned length);

/**
 * 单元测试
 * @return
 *      0 on success, or positive integer on failure
 */
int
output_selftest(void);




#endif
