/*

    速率限制/节流器:阻止我们传输太快。

    我们可以每秒发送数百万个数据包。这将大多数网络阻塞。因此，我们需要节流或限速当我们发送速率过快时。

    由于我们以每秒1000万的速度发送数据包，所以我们计算需要以一种轻量级的方式进行。
    也就是说我们无法为每一个包的限速操作进行系统调用。

    注意:要注意的一个复杂问题是时钟之间的差异时间和流逝的时间，它们是变化的。
    
    我们必须避免一个问题，例如：

    有人把电脑挂了几天，然后把它唤醒，
    此时，系统尝试发送100万个包/秒，并不是预期中的1000包/秒。
*/
#include "main-throttle.h"
#include "pixie-timer.h"
#include "logger.h"
#include <string.h>
#include <stdio.h>


/***************************************************************************
 ***************************************************************************/
void
throttler_start(struct Throttler *throttler, double max_rate)
{
    unsigned i;

    memset(throttler, 0, sizeof(*throttler));

    throttler->max_rate = max_rate;

    for (i=0; i<sizeof(throttler->buckets)/sizeof(throttler->buckets[0]); i++) {
        throttler->buckets[i].timestamp = pixie_gettime();
        throttler->buckets[i].packet_count = 0;
    }

    throttler->batch_size = 1;

    LOG(1, "maxrate = %0.2f\n", throttler->max_rate);
}


/***************************************************************************
 * 返回下一批可发送数据包的数量. 因此，我们不是试图单独控制每个包，
 * 因为每个包的成本很高，而是一次控制一堆包。
 * 通常，这个函数会返回1，只有在高速率下才会返回较大的数
 * 
 * 注意: 最小的返回值为 1. 当返回值更小时，将暂停并等待系统可以继续发送数据包
 * 
 ***************************************************************************/
uint64_t
throttler_next_batch(struct Throttler *throttler, uint64_t packet_count)
{
    uint64_t timestamp;
    uint64_t index;
    uint64_t old_timestamp;
    uint64_t old_packet_count;
    double current_rate;
    double max_rate = throttler->max_rate;

again:

    /* 注意: 该值通过获取Linux上的 CLOCK_MONOTONIC_RAW 变量, 当系统挂起时，时间戳不会变 */
    timestamp = pixie_gettime();

    /*
     * 记录最后的 256 桶（理想状态下）, 取平均值.
     */
    index = (throttler->index) & 0xFF;
    throttler->buckets[index].timestamp = timestamp;
    throttler->buckets[index].packet_count = packet_count;

    index = (++throttler->index) & 0xFF;
    old_timestamp = throttler->buckets[index].timestamp;
    old_packet_count = throttler->buckets[index].packet_count;

    /*
     * 两个数据包时间戳差值（延迟）超过1s时, 需要重置限流状态（batch_size）以降低速率.
     */
    if (timestamp - old_timestamp > 1000000) {
        //throttler_start(throttler, throttler->max_rate);
        throttler->batch_size = 1;  // 重置，以最小速率运行
        goto again;    // 为什么这样写255次循环？貌似因为并不是严格取256次。
    }

    /*
     * 计算最近一次速率.
     * NOTE: 这里不是自开始以来计算的速率, 仅是最近的速率.
     * 因此系统挂起后，不会生成突发流量导致网络崩溃.
     */
    current_rate = 1.0*(packet_count - old_packet_count)/((timestamp - old_timestamp)/1000000.0);


    /*
     * 如果发送过快，将暂停并随后重试发送。
     */
    if (current_rate > max_rate) {
        double waittime;

        /* 根据发送速率，计算暂停时间 */
        waittime = (current_rate - max_rate) / throttler->max_rate;

        /* 过高速率出现时，不必完全等待整个暂停时间。
         * 更小的时间间隔，将保证接近阀值的尽可能大的发送速率。
         * */
        waittime *= 0.1;

        /* 这是在系统严重故障的情况下。这应该不会实际发生，除非有bug。
         * 真的，我应该做一个'assert()'判断，而不是失败和修复错误，
         * 强制调整时间间隔，而不是默默的继续，只是我太懒了 
         * */
        if (waittime > 0.1)
            waittime = 0.1;

        /* 既然我们已经超速了，就应该减速调整每批发送数据包数量。
         * 我们不会只做一点点,避免矫枉过正一样。我们想要向正确的方向逐渐收敛。
         * 注意，由于这种情况每秒发生成白上千次，收敛速度非常快，即使是0.1%的调整 */
        throttler->batch_size *= 0.999;

        /* 暂停一小会儿（阻塞线程不到一秒） */
        pixie_usleep((uint64_t)(waittime * 1000000.0));

        /* 这里有两种选择。我们要么马上返回，或者我们可以再循环一次。
         * 现在，代码循环更多次以支持非常慢的速率，如0.5包每秒。
         * 没有人会想要运行这样慢的扫描,当然，但是这对测试很有用 
         * */
        //return (uint64_t)throttler->batch_size;
        goto again;  // 限速需要持续执行，动态调整。
    }

    /*
     * 计算符合预期发送速率的可发送数据包数.
     *
     * NOTE: 通常只返回 1 (one). 
     * 高速状态时 (超过 100,000 packets/second) 将返回更大数值
     */
    throttler->batch_size *= 1.005;
    if (throttler->batch_size > 10000)
        throttler->batch_size = 10000;
    throttler->current_rate = current_rate;

    throttler->test_timestamp = timestamp;
    throttler->test_packet_count = packet_count;
    return (uint64_t)throttler->batch_size;
}
