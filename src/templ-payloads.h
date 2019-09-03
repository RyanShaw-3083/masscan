#ifndef TEMPL_PAYLOADS_H
#define TEMPL_PAYLOADS_H
#include <stdio.h>
#include <stdint.h>
struct RangeList;

/**
 * 模块回归测试
 * @return
 *      0 on 成功, or 负数失败.
 */
int
payloads_udp_selftest(void);

/**
 * 创建这个模块。必须在退出时与“destroy()”函数匹配
 */
struct PayloadsUDP *
payloads_udp_create(void);

struct PayloadsUDP *
payloads_oproto_create(void);

/**
 * 释放使用匹配调用创建的对象的资源’payloads_create ()”
 */
void
payloads_udp_destroy(struct PayloadsUDP *payloads);

void
payloads_oproto_destroy(struct PayloadsUDP *payloads);

/**
 * 从“nmap-payload”格式的文件中读取payload。
 *调用者是负责打开/关闭文件，但应传递文件名，以便我们可以打印有用的错误信息。
 */
void
payloads_udp_readfile(FILE *fp, const char *filename,
                   struct PayloadsUDP *payloads);

/**
 * 从libpcap格式的文件读取有效负载。
 */
void
payloads_read_pcap(const char *filename, struct PayloadsUDP *payloads, struct PayloadsUDP *oproto_payloads);

/**
 * 调用此函数删除扫描中不使用的任何有效负载。这使得生成包时查找更快。
 */
void
payloads_udp_trim(struct PayloadsUDP *payloads, const struct RangeList *ports);

void
payloads_oproto_trim(struct PayloadsUDP *payloads, const struct RangeList *ports);


/**
* 端口扫描器为它发送的每个包创建一个“cookie”
* 将是一个64位值，其低阶位将被裁剪以适合任何值尺寸可用。
* 对于TCP，这将成为SYN包的32位seqno。
* 但是对于UDP协议，每个应用层协议都是不同。
* 例如，SNMP可以使用32位事务ID，而DNS只能使用16位事务ID。
 */
typedef unsigned (*SET_COOKIE)(unsigned char *px, size_t length,
                               uint64_t seqno);


/**
 * 给定UDP端口号，返回与之关联的有效负载使用那个端口号。
 * @param payloads
 *      Payload表
 * @param port
 *      接收端口号
 * @param px
 *      收到数据包数据.
 * @param length
 *      数据包长度.
 * @param source_port
 *      下一次发包端口.
 * @param xsum
 *      返回的部分校验和的有效载荷字节，使其不需要为每个包重新计算。
 * @param set_cookie
 *      返回的函数，该函数（set-cookie）将在每次传输的数据包调用
 */
int
payloads_udp_lookup(
                const struct PayloadsUDP *payloads,
                unsigned port,
                const unsigned char **px,
                unsigned *length,
                unsigned *source_port,
                uint64_t *xsum,
                SET_COOKIE *set_cookie);

int
payloads_oproto_lookup(
                    const struct PayloadsUDP *payloads,
                    unsigned port,
                    const unsigned char **px,
                    unsigned *length,
                    unsigned *source_port,
                    uint64_t *xsum,
                    SET_COOKIE *set_cookie);



#endif
