#ifndef PROTO_BANNER1_H
#define PROTO_BANNER1_H
#include <stdint.h>

#include <stdio.h>
#include "masscan-app.h"
#include "proto-banout.h"
#include "proto-x509.h"
#include "proto-spnego.h"

struct InteractiveData;
struct Banner1;
struct ProtocolState;

typedef void (*BannerParser)(
              const struct Banner1 *banner1,
              void *banner1_private,
              struct ProtocolState *stream_state,
              const unsigned char *px, size_t length,
              struct BannerOutput *banout,
              struct InteractiveData *more);
struct Banner1
{
    struct lua_State *L;
    struct SMACK *smack;
    struct SMACK *http_fields;
    struct SMACK *html_fields;
    struct SMACK *memcached_responses;
    struct SMACK *memcached_stats;
    //-Q3-SM-由于不同协议在应用层上存在不同的状态交互模式，因此需要初始化多个SMACK结构

    unsigned is_capture_html:1;
    unsigned is_capture_cert:1;
    unsigned is_capture_heartbleed:1;
    unsigned is_capture_ticketbleed:1;
    unsigned is_heartbleed:1;
    unsigned is_ticketbleed:1;
    unsigned is_poodle_sslv3:1;

    struct {
        struct ProtocolParserStream *tcp[65536];
    } payloads;  //-Q3-SM-Payloads包含待解析（抓取）banners
    
    BannerParser parser[PROTO_end_of_list];
};

struct BannerBase64
{
    unsigned state:2;
    unsigned temp:24;
};

struct SSL_SERVER_HELLO {
    unsigned state;
    unsigned remaining;
    unsigned timestamp;
    unsigned short cipher_suite;
    unsigned short ext_tag;
    unsigned short ext_remaining;
    unsigned char compression_method;
    unsigned char version_major;
    unsigned char version_minor;
};
struct SSL_SERVER_CERT {
    unsigned state;
    unsigned remaining;
    struct {
        unsigned remaining;
    } sub;
    struct CertDecode x509;
};
struct SSL_SERVER_ALERT {
    unsigned char level;
    unsigned char description;
};

struct SSLRECORD {
    unsigned char type;
    unsigned char version_major;
    unsigned char version_minor;

    struct {
        unsigned state;
        unsigned char type;
        unsigned remaining;
    } handshake;

    union {
        struct {
            /* 所有结构体应该以状态进度变量为起始 */
            unsigned state;
        } all;
        struct SSL_SERVER_HELLO server_hello;
        struct SSL_SERVER_CERT server_cert;
        struct SSL_SERVER_ALERT server_alert;
    } x;

};

struct PIXEL_FORMAT {
    unsigned short red_max;
    unsigned short green_max;
    unsigned short blue_max;
    unsigned char red_shift;
    unsigned char green_shift;
    unsigned char blue_shift;
    unsigned char bits_per_pixel;
    unsigned char depth;
    unsigned big_endian_flag:1;
    unsigned true_colour_flag:1;
};
struct VNCSTUFF {
    unsigned sectype;
    unsigned char version;
    unsigned char len;
    
    unsigned short width;
    unsigned short height;
    
    struct PIXEL_FORMAT pixel;    
};

struct FTPSTUFF {  
    unsigned code; //-Q5-FTP-交互状态码
    unsigned is_last:1;
};


struct SMTPSTUFF {
    unsigned code;
    unsigned is_last:1;
};

struct POP3STUFF {
    unsigned code;
    unsigned is_last:1;
};

struct MEMCACHEDSTUFF {
    unsigned match;
};

struct Smb72_Negotiate {
    uint16_t DialectIndex;
    uint16_t SecurityMode;
    uint64_t SystemTime;
    uint32_t SessionKey;
    uint32_t Capabilities;
    uint16_t ServerTimeZone;
    uint8_t  ChallengeLength;
    uint8_t  ChallengeOffset;
};

struct Smb73_Setup {
    uint16_t BlobLength;
    uint16_t BlobOffset;
};

struct SMBSTUFF {
    unsigned nbt_state;
    unsigned char nbt_type;
    unsigned char nbt_flags;
    unsigned is_printed_ver:1;
    unsigned is_printed_guid:1;
    unsigned is_printed_time:1;
    unsigned nbt_length;
    unsigned nbt_err;
    
    union {
        struct {
            unsigned char   command;
            unsigned        status;
            unsigned char   flags1;
            unsigned short  flags2;
            unsigned        pid;
            unsigned char   signature[8];
            unsigned short  tid;
            unsigned short  uid;
            unsigned short  mid;
            unsigned short  param_length;
            unsigned short  param_offset;
            unsigned short  byte_count;
            unsigned short  byte_offset;
            unsigned short  byte_state;
            unsigned short  unicode_char;
        } smb1;
        struct {
            unsigned seqno;
            unsigned short header_length;
            unsigned short offset;
            unsigned short state;
            unsigned short opcode;
            unsigned short struct_length;
            unsigned is_dynamic:1;
            unsigned char flags;
            unsigned ntstatus;
            unsigned number;
            unsigned short blob_offset;
            unsigned short blob_length;
        } smb2;
    } hdr;
    union {
        struct Smb72_Negotiate negotiate;
        struct Smb73_Setup setup;
        struct {
            uint64_t current_time;
            uint64_t boot_time;
        } negotiate2;
    } parms;
    struct SpnegoDecode spnego;
};

struct RDPSTUFF {
    unsigned short tpkt_length;
    struct {
        unsigned state;
        unsigned short dstref;
        unsigned short srcref;
        unsigned char len;
        unsigned char type;
        unsigned char flags;
    } cotp;
    struct {
        unsigned state;
        unsigned result;
        unsigned char type;
        unsigned char flags;
        unsigned char len;
    } cc;
};

struct ProtocolState { //-Q5-协议交互状态描述
    unsigned state; //-Q4-HTTP-SM-Banner1_state()来自TCB定义（读取位置state）。
    unsigned remaining;
    unsigned short port;
    unsigned short app_proto;
    unsigned is_sent_sslhello:1;
    struct BannerBase64 base64;

    union {
        struct SSLRECORD ssl;
        struct VNCSTUFF vnc;
        struct FTPSTUFF ftp;
        struct SMTPSTUFF smtp;
        struct POP3STUFF pop3;
        struct MEMCACHEDSTUFF memcached;
        struct SMBSTUFF smb;
        struct RDPSTUFF rdp;
    } sub; //-Q5-协议细节，交互状态标识
};

enum {
    CTRL_SMALL_WINDOW = 1,
};

/**
 * 各种TCP流协议的注册结构比如HTTP、SSL和SSH
 */
struct ProtocolParserStream {
    const char *name;  //-Q5-协议名称
    unsigned port;  //-Q5-端口
    const void *hello;  //-Q5-交互数据包（Hello包）
    size_t hello_length;  //-Q5-Hello数据长度
    unsigned ctrl_flags;  //-Q5-控制位
    int (*selftest)(void);  //-Q5-单元测试回调
    void *(*init)(struct Banner1 *b);  //-Q5-Banner获取回调
    void (*parse)(  //-Q5-协议解析
        const struct Banner1 *banner1,  //-Q5-Banners  
        void *banner1_private,  
        struct ProtocolState *stream_state,  //-Q5-交互状态
    const unsigned char *px, size_t length,  //-Q5-数据包及长度
        struct BannerOutput *banout,    //-Q5-Banners输出回调
        struct InteractiveData *more);  //-Q5-交互模式的更多数据
    void (*cleanup)(struct ProtocolState *stream_state);  //-Q5-协议处理对象销毁
    void (*transmit_hello)(const struct Banner1 *banner1, struct InteractiveData *more);  //-Q5-发送Hello交互
    
    /* 当为一个端口注册多个项时。当一个连接关闭时，将打开下一个连接。*/
    struct ProtocolParserStream *next;
    
    /*NOTE: “next”参数应该是这个结构中的最后一个参数，
     *因为我们在编译时静态初始化其余成员，然后在运行时使用最后一个参数链接结构 *///-Q0-初始化Payload时 Ln 40 每个节点是顺序的。
};


/**
 * 匹配TCP连接开始时的数据的模式。这将提示该连接可能是什么协议。
 */
struct Patterns {
    
    /** 一个字符串，如“SSH-”或“220”，匹配一个Banners */
    const char *pattern;
    
    /** 该字符串的长度，因为它可能是包含nul字符的二进制文件 */
    unsigned pattern_length;
    
    /** 任意分配给此模式的整数，应该是可能匹配我们正在寻找的协议ID */
    unsigned id;
    
    /**
     * 这个字符串是否只匹配开始('锚定')或者输入的任何地方。
     * 几乎所有的模式都是固定的。
     */
    unsigned is_anchored;
    
    /**
     * 几个模式匹配器的模式匹配器的一些额外标志.
     */
    unsigned extra;
};

struct Banner1 *
banner1_create(void);


void
banner1_destroy(struct Banner1 *b);

unsigned
banner1_parse(
        const struct Banner1 *banner1,
        struct ProtocolState *pstate,
        const unsigned char *px, size_t length,
        struct BannerOutput *banout,
        struct InteractiveData *more);



/**
 * 通过阅读测试banner协议解析系统在捕获文件中
 */
void banner1_test(const char *filename);

int banner1_selftest(void);

#endif
