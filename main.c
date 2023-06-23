#include <stdio.h>
#include <pthread.h>
#include "database.h"
#include "protocol.h"
#include "dns.h"
#include "time.h"

SOCKET s;
SOCKET s_upstream;

// 监听上游服务器的线程，读取返回的消息并处理
void listen_upstream()
{

    while (1)
    {
        SOCKADDR_IN from_addr;
        dns_message_t msg;

        // 阻塞等待上游服务器的响应
        protocol_recv(s_upstream, &from_addr, &msg);

        if (!(msg.header.flags & FLAG_QR) || from_addr.sin_addr.s_addr != inet_addr(DNS_UPSTREAM_SERVER))
        {
            dns_message_free(&msg);
            continue;
        }

        dns_handle_arg_t* arg = malloc(sizeof(dns_handle_arg_t));
        arg->sock_in = from_addr;
        arg->msg = msg;

        dns_handle_r(arg);

        // pthread_create(NULL, NULL, (void* (*)(void*))dns_handle_r, (void*)arg);
    }
}

// 监控线程，打印状态
void monitor()
{
    while (1)
    {
        printf("\ntransaction_id_base: %d\n", transaction_id_base);
        Sleep(1000);
    }
}

int main(int, char**) {
    printf("Hello, from DNS relay!\n");

    database_init();
    database_load(FILENAME);

    dns_transaction_id_init();

    // dns_record_t record;
    // database_lookup("test1", &record);
    // dns_record_print(&record);

    protocol_init(&s, 53);
    protocol_init(&s_upstream, DNS_UPSTREAM_LISTEN_PORT);


    // dns_message_t msg;
    // msg.header.id = 0x11cc;
    // dns_header_set_flags(&msg.header, 0, 0, 0);
    // msg.header.qdcount = 1;
    // msg.header.ancount = 0;
    // msg.header.nscount = 0;
    // msg.header.arcount = 0;

    // msg.questions = malloc(sizeof(dns_question_t));
    // char name[256];
    // name_to_qname("www.bupt.edu.cn", name);

    // msg.questions[0].name = malloc(strlen(name) + 1);
    // strcpy(msg.questions[0].name, name);

    // msg.questions[0].type = TYPE_A;
    // msg.questions[0].class = CLASS_IN;

    // msg.answers = NULL;
    // msg.authorities = NULL;
    // msg.additionals = NULL;

    // SOCKADDR_IN sock_in;
    // sock_in.sin_family = AF_INET;
    // sock_in.sin_port = htons(53);
    // sock_in.sin_addr.s_addr = inet_addr("10.3.9.44");
    // protocol_send(&s, &sock_in, &msg);
    // dns_message_free(&msg);

    // SOCKADDR_IN from_addr;
    // protocol_recv(&s, &from_addr, &msg);
    // for (int i = 0; i < msg.header.ancount; i++)
    // {
    //     dns_record_print(&msg.answers[i]);
    // }

    pthread_create(NULL, NULL, (void* (*)(void*))listen_upstream, NULL);
    pthread_create(NULL, NULL, (void* (*)(void*))monitor, NULL);

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

        if (msg.header.flags & FLAG_QR)
        {
            dns_message_free(&msg);
            continue;
        }

        dns_handle_arg_t* arg = malloc(sizeof(dns_handle_arg_t));
        arg->sock_in = from_addr;
        arg->msg = msg;

        // 使用单线程处理DNS请求，多线程效率较低？
        dns_handle_q(arg);

        // pthread_create(NULL, NULL, (void* (*)(void*))dns_handle_q, (void*)arg);
    }


    return 0;
}
