#include "main-src.h" // 本地地址判断实现

int is_myself(const struct Source *src, unsigned ip, unsigned port)
{
    return is_my_ip(src, ip) && is_my_port(src, port);
}

int is_my_ip(const struct Source *src, unsigned ip)
{
    return src->ip.first <= ip && ip <= src->ip.last;    // 检查结构体第一个和最后一个地址，参见main-src.h
}

int is_my_port(const struct Source *src, unsigned port)
{
    return src->port.first <= port && port <= src->port.last;
}
