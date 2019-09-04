#ifndef PROTO_INTERACTIVE_H
#define PROTO_INTERACTIVE_H
#include <stdio.h>

struct InteractiveData {
    const void *m_payload;
    unsigned m_length;
    unsigned is_payload_dynamic:1;
    unsigned is_closing:1;
};
enum {
    TCPTRAN_DYNAMIC = 0x0001,
};

/**
 * 处理发送线程TCP数据报
 */
void
tcp_transmit(struct InteractiveData *more, const void *data, size_t length, unsigned flags);

/**
 * TCP连接关闭处理
 */
void
tcp_close(struct InteractiveData *more);

/**
 * 分配发送数据缓冲.
 */
unsigned char *
tcp_transmit_alloc(struct InteractiveData *more, size_t length);

#endif
