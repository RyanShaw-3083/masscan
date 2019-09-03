/*
    每秒将状态信息打印在命令行

    状态信息涉及:
    - 每秒发送数据包速率
    - 完成百分比
    - 距离完成的剩余时间
    - 'tcbs'TCP连接控制块数量/TCP活动连接数量

*/
#include "main-status.h"
#include "pixie-timer.h"
#include "unusedparm.h"
#include "main-globals.h"
#include "string_s.h"
#include <stdio.h>



/***************************************************************************
 * 每秒打印状态信息到命令行. 
 * 每次检查数据包时间戳，决定是否要输出状态信息.
 ***************************************************************************/
void
status_print(
    struct Status *status,
    uint64_t count,
    uint64_t max_count,
    double x,
    uint64_t total_tcbs,
    uint64_t total_synacks,
    uint64_t total_syns,
    uint64_t exiting)
{
    double elapsed_time;
    double rate;
    double now;
    double percent_done;
    double time_remaining;
    uint64_t current_tcbs = 0;
    uint64_t current_synacks = 0;
    uint64_t current_syns = 0;
    double tcb_rate = 0.0;
    double synack_rate = 0.0;
    double syn_rate = 0.0;


    /*
     * ####  FUGGLY TIME HACK  ####
     *
     * PF_RING 数据包里没时间戳, 因此无法从收到的数据包内判断时间. 
     * 每个包收到后都取一次时间的实现比较丑. 因此我们创建一个全局变量，每秒更新时间值，
     * 无论这样是否方便.这是目前最方便的实现方式.
     */
    global_now = time(0);


    /* 获取时间. 注意: 在Linux上我们读取 CLOCK_MONOTONIC_RAW 而不是通常的时间戳. */
    now = (double)pixie_gettime();

    /* 计算时间消耗了多少秒, float类型数值。
     * 时间戳是微秒，因此需要除100万。
     */
    elapsed_time = (now - status->last.clock)/1000000.0;
    if (elapsed_time == 0)
        return;

    /* 计算 "packets-per-second" （每秒发送速率）, 计算方法仅仅是:
     *
     *  速率 = packets_sent（已发送数据包格式） / elapsed_time（消耗时间）;
     */
    rate = (count - status->last.count)*1.0/elapsed_time;

    /*
     * 取8此速率均值，平滑速率变化曲线。
     */
     status->last_rates[status->last_count++ & 0x7] = rate;
     rate =     status->last_rates[0]
                + status->last_rates[1]
                + status->last_rates[2]
                + status->last_rates[3]
                + status->last_rates[4]
                + status->last_rates[5]
                + status->last_rates[6]
                + status->last_rates[7]
                ;
    rate /= 8;
    /*if (rate == 0)
        return;*/

    /*
     * 计算 "percent-done" （完成百分比）, 简单来说即为已发送数据包个数/全部待发送数据包个数.
     */
    percent_done = (double)(count*100.0/max_count);


    /*
     * 计算剩余扫描时间
     */
    time_remaining  = (1.0 - percent_done/100.0) * (max_count / rate);

    /*
     * 其他统计数据获取
     */
    if (total_tcbs) {
        current_tcbs = total_tcbs - status->total_tcbs;
        status->total_tcbs = total_tcbs;
        tcb_rate = (1.0*current_tcbs)/elapsed_time;
    }
    if (total_synacks) {
        current_synacks = total_synacks - status->total_synacks;
        status->total_synacks = total_synacks;
        synack_rate = (1.0*current_synacks)/elapsed_time;
    }
    if (total_syns) {
        current_syns = total_syns - status->total_syns;
        status->total_syns = total_syns;
        syn_rate = (1.0*current_syns)/elapsed_time;
    }


    /*
     * 消息重定向到 <stderr> 所以 <stdout> 可以直接重定向到文件
     * (<stdout> 反馈所发现的目标服务系统).
     */
    if (status->is_infinite) {
        fprintf(stderr,
                "rate:%6.2f-kpps, syn/s=%.0f ack/s=%.0f tcb-rate=%.0f, %" PRIu64 "-tcbs,         \r",
                        x/1000.0,
                        syn_rate,
                        synack_rate,
                        tcb_rate,
                        total_tcbs
                        );
    } else {
        if (is_tx_done) {
            
            fprintf(stderr,
                        "rate:%6.2f-kpps, %5.2f%% done, waiting %d-secs, found=%" PRIu64 "       \r",
                        x/1000.0,
                        percent_done,
                        (int)exiting,
                        total_synacks
                       );
            
        } else {
            fprintf(stderr,
                "rate:%6.2f-kpps, %5.2f%% done,%4u:%02u:%02u remaining, found=%" PRIu64 "       \r",
                        x/1000.0,
                        percent_done,
                        (unsigned)(time_remaining/60/60),
                        (unsigned)(time_remaining/60)%60,
                        (unsigned)(time_remaining)%60,
                        total_synacks
                       );
        }
    }
    fflush(stderr);

    /*
     * 该数值每次需要更新
     */
    status->last.clock = now;
    status->last.count = count;
}

/***************************************************************************
 ***************************************************************************/
void
status_finish(struct Status *status)    // 标准错误替代了“标准输出”，这里只是打了一个空行。
{
    UNUSEDPARM(status);
    fprintf(stderr,
"                                                                             \r");
}

/***************************************************************************
 ***************************************************************************/
void
status_start(struct Status *status)    // 开始统计
{
    memset(status, 0, sizeof(*status));
    status->last.clock = clock();
    status->last.time = time(0);
    status->last.count = 0;
    status->timer = 0x1;
}
