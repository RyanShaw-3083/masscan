/*

    过滤重复回应

    MASSCAN是一个异步扫描器. 因此，没有简单的方法将探针与响应关联起来。
    因此，我们必须忍受这样的事实有时我们得到重复的响应，产生重复的记录。
    我们可以用一个表来模拟这个过程，这个表可以记住最近的回答。临时的重复
    数据仍然会发送出去，但问题会小一些。
*/
#include "main-dedup.h"
#include "util-malloc.h"
#include <stdlib.h>
#include <string.h>

#define DEDUP_ENTRIES 65536 /* 更激进的重复数据删除 */

struct DedupEntry
{
    unsigned ip_them;
    unsigned port_them;
    unsigned ip_me;
    unsigned port_me;
};
struct DedupTable
{
    struct DedupEntry entries[DEDUP_ENTRIES][4];
};

/***************************************************************************
 ***************************************************************************/
struct DedupTable *
dedup_create(void)
{
    struct DedupTable *result;

    result = CALLOC(1, sizeof(*result));

    return result;
}

/***************************************************************************
 ***************************************************************************/
void
dedup_destroy(struct DedupTable *table)
{
    if (table)
        free(table);
}

/***************************************************************************
 ***************************************************************************/
unsigned
dedup_is_duplicate(struct DedupTable *dedup,
                   unsigned ip_them, unsigned port_them,
                   unsigned ip_me, unsigned port_me)
{
    unsigned hash;
    struct DedupEntry *bucket;
    unsigned i;

    /* THREAT: 可能需要保护这个散列，不过syn-cookies提供了一些保护 */
    hash = (ip_them + port_them) ^ ((ip_me) + (ip_them>>16)) ^ (ip_them>>24) ^ port_me;
    hash &= DEDUP_ENTRIES-1;

    /* 在缓冲桶中搜索 */
    bucket = dedup->entries[hash];

    for (i = 0; i < 4; i++) {
        if (bucket[i].ip_them == ip_them && bucket[i].port_them == port_them
            && bucket[i].ip_me == ip_me && bucket[i].port_me == port_me) {
            /* 移动到列表末尾，这样常量重复就会被忽略 */
            if (i > 0) {
                bucket[i].ip_them ^= bucket[0].ip_them;
                bucket[i].port_them ^= bucket[0].port_them;
                bucket[i].ip_me ^= bucket[0].ip_me;
                bucket[i].port_me ^= bucket[0].port_me;

                bucket[0].ip_them ^= bucket[i].ip_them;
                bucket[0].port_them ^= bucket[i].port_them;
                bucket[0].ip_me ^= bucket[i].ip_me;
                bucket[0].port_me ^= bucket[i].port_me;

                bucket[i].ip_them ^= bucket[0].ip_them;
                bucket[i].port_them ^= bucket[0].port_them;
                bucket[i].ip_me ^= bucket[0].ip_me;
                bucket[i].port_me ^= bucket[0].port_me;
            }
            return 1;
        }
    }

    /* 我们没有找到它，所以把它添加到我们的列表中。这将把这个bucket中的旧条目从列表中删除 */
    memmove(bucket, bucket+1, 3*sizeof(*bucket));
    bucket[0].ip_them = ip_them;
    bucket[0].port_them = port_them;
    bucket[0].ip_me = ip_me;
    bucket[0].port_me = port_me;

    return 0;
}
