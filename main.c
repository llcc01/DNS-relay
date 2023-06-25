#include <stdio.h>
#include <pthread.h>
#include <signal.h>
#include "database.h"
#include "protocol.h"
#include "dns.h"
#include "time.h"
#include "pool.h"
#include "main.h"

SOCKET s;
SOCKET s_upstream;
size_t request_count = 0;

#ifdef THREAD_POOL
pthread_t threads[THREAD_NUM];
#endif

// 监听上游服务器的线程，读取返回的消息并处理
void listen_upstream()
{

    while (1)
    {
        SOCKADDR_IN from_addr;
        dns_message_t msg;

        // 阻塞等待上游服务器的响应
        protocol_recv(s_upstream, &from_addr, &msg);

        if (msg.header.qdcount == 0 && msg.header.ancount == 0 && msg.header.nscount == 0 && msg.header.arcount == 0)
        {
            dns_message_free(&msg);
            continue;
        }

        if (!(msg.header.flags & FLAG_QR) || from_addr.sin_addr.s_addr != inet_addr(DNS_UPSTREAM_SERVER))
        {
            dns_message_free(&msg);
            continue;
        }

        dns_handle_arg_t* arg = malloc(sizeof(dns_handle_arg_t));
        arg->sock_in = from_addr;
        arg->msg = msg;

        dns_handle_r(arg);

        // pthread_t thread_id;
        // pthread_create(&thread_id, NULL, (void* (*)(void*))dns_handle_r, (void*)arg);
        // pthread_detach(thread_id);
    }
}

// 监控线程，打印状态
void monitor()
{
    while (1)
    {
#ifdef THREAD_POOL
        LOG_INFO("transaction_id_base: %d,\trequest_count: %zu,\tpool_id_count: %d", transaction_id_base, request_count, pool_id_count);
#else
        LOG_INFO("transaction_id_base: %d,\trequest_count: %zu", transaction_id_base, request_count);
#endif
        request_count = 0;
        Sleep(1000);
    }
}

int main()
{
    logger_set_level(LOG_LEVEL_INFO);

    LOG_INFO("Hello, from DNS relay!");

#ifndef MULTI_THREAD
    LOG_INFO("Single thread mode");
#elif defined(THREAD_POOL)
    LOG_INFO("Thread pool mode, THREAD_NUM: %d", THREAD_NUM);
#else
    LOG_INFO("Multi thread mode");
#endif

    database_init();
    database_load(FILENAME);

    dns_transaction_id_init();

    protocol_init(&s, DNS_LISTEN_PORT);
    protocol_init(&s_upstream, DNS_UPSTREAM_LISTEN_PORT);

#ifdef THREAD_POOL
    pool_id_init(THREAD_LIMIT);
#endif

    pthread_t listen_upstream_thread;
    pthread_t monitor_thread;
    pthread_create(&listen_upstream_thread, NULL, (void* (*)(void*))listen_upstream, NULL);
    pthread_create(&monitor_thread, NULL, (void* (*)(void*))monitor, NULL);


    while (1)
    {
        // if (transaction_id_counter > 5)
        // {
        //     continue;
        // }

        SOCKADDR_IN from_addr;
        dns_message_t msg;

        // 阻塞等待客户端的请求
        protocol_recv(s, &from_addr, &msg);

        if (msg.header.qdcount == 0 && msg.header.ancount == 0 && msg.header.nscount == 0 && msg.header.arcount == 0)
        {
            dns_message_free(&msg);
            continue;
        }

        if (msg.header.flags & FLAG_QR)
        {
            dns_message_free(&msg);
            continue;
        }

        dns_handle_arg_t* arg = malloc(sizeof(dns_handle_arg_t));
        arg->sock_in = from_addr;
        arg->msg = msg;

        // 使用单线程处理DNS请求，多线程效率较低？

#ifndef MULTI_THREAD
        dns_handle_q(arg);

#elif defined(THREAD_POOL)

        // 线程池
        while (pool_id_is_full())
        {
            Sleep(1);
        }

        uint16_t thread_id = pool_id_get();
        arg->thread_id = thread_id;

        pthread_create(&threads[thread_id], NULL, (void* (*)(void*))dns_handle_q, (void*)arg);
        pthread_detach(threads[thread_id]);

#else
        // 多线程
        pthread_t thread;
        pthread_create(&thread, NULL, (void* (*)(void*))dns_handle_q, (void*)arg);
        pthread_detach(thread);

#endif


        request_count++;
    }


    return 0;
}
