#include "dns.h"
#include <pthread.h>
#include <stdio.h>
#include "main.h"
#include "database.h"
#include "protocol.h"
#include "lookup.h"

uint16_t transaction_id_base = 0;
transaction_arg_t transactions[65536];
pthread_mutex_t transaction_id_mutex;
dns_message_t dns_msg_cache[65536] = { 0 };

// ID锁初始化
void dns_transaction_id_init()
{
    pthread_mutex_init(&transaction_id_mutex, NULL);
}

// id锁销毁
void dns_transaction_id_free()
{
    pthread_mutex_destroy(&transaction_id_mutex);
}

// 获取一个ID
int32_t dns_transaction_id_get()
{
    pthread_mutex_lock(&transaction_id_mutex);
    transaction_id_base++;
    pthread_mutex_unlock(&transaction_id_mutex);
    return transaction_id_base;
}

// 设置会话信息
inline void dns_transaction_set(const transaction_arg_t* arg)
{
    pthread_mutex_lock(&transaction_id_mutex);
    transactions[arg->id] = *arg;
    pthread_mutex_unlock(&transaction_id_mutex);
}

// 获取会话信息
inline transaction_arg_t dns_transaction_get(uint16_t id)
{
    return transactions[id];
}

// 处理DNS请求的线程
void dns_handle_q(dns_handle_arg_t* arg)
{
    SOCKADDR_IN sock_in = arg->sock_in;
    dns_message_t msg = arg->msg;
    free(arg);


    // size_t time_count = 10;
    // LARGE_INTEGER time_arr[time_count];

    // QueryPerformanceCounter(&time_arr[0]);

    uint16_t transaction_id = dns_transaction_id_get();
    uint16_t ori_id = msg.header.id;
    // printf("\ntransaction_id get: %d, ori_id: %d\n", transaction_id, ori_id);

    //
    dns_message_t msg_send;
    dns_message_copy(&msg_send, &msg);

    msg_send.header.flags |= FLAG_QR;

    uint8_t banned = 0;

    // QueryPerformanceCounter(&time_arr[1]);
    // if (msg_send.header.qdcount!= 1)
    // {
    //     // printf("qdcount != 1\n");
    //     PANIC("Error: dns_handle_q: qdcount != 1");
    // }

    // 当有一个本地查询失败时，就不再进行本地查询
    for (int i = 0; i < 1 && msg_send.header.qdcount == 1; i++)
    {
        // banned = 1;
        // break;

        dns_question_t question = msg_send.questions[i];

        // char name[NAME_MAX_SIZE];
        // qname_to_name(question.name, name);
        // printf("question: ");
        // if (question.type == TYPE_A)
        // {
        //     printf("A ");
        // }
        // else if (question.type == TYPE_NS)
        // {
        //     printf("NS ");
        // }
        // else if (question.type == TYPE_PTR)
        // {
        //     printf("PTR ");
        // }
        // else if (question.type == TYPE_CNAME)
        // {
        //     printf("CNAME ");
        // }
        // else if (question.type == TYPE_SOA)
        // {
        //     printf("SOA ");
        // }
        // else if (question.type == TYPE_MX)
        // {
        //     printf("MX ");
        // }
        // else if (question.type == TYPE_TXT)
        // {
        //     printf("TXT ");
        // }
        // else if (question.type == TYPE_AAAA)
        // {
        //     printf("AAAA ");
        // }
        // else if (question.type == TYPE_SRV)
        // {
        //     printf("SRV ");
        // }
        // else if (question.type == TYPE_ANY)
        // {
        //     printf("ANY ");
        // }

        // printf("%s\n", name);

        if (question.type == TYPE_PTR && question.class == CLASS_IN)
        {
            char name[NAME_MAX_SIZE];
            qname_to_name(question.name, name);
            // printf("question PTR: %s\n", name);
            if (strcmp(name, LOCAL_NAME) != 0)
            {
                continue;
            }
            msg_send.header.ancount = 1;
            msg_send.answers = malloc(sizeof(dns_record_t));
            dns_record_copy(msg_send.answers, &local_name_rec);
            break;
        }

        // database_lookup(question.name, msg_send.answers);
        // bst_id_t db_id = database_lookup(&question);
        bst_id_t db_id = database_bst_lookup(&question);
        if (db_id == BST_INVALID_ID)
        {
            break;
        }

        msg_send.header.ancount = 1;
        msg_send.answers = malloc(sizeof(dns_record_t));
        database_get_record(db_id, msg_send.answers);

        if (*(msg_send.answers[0].rdata) == 0)
        {
            // printf("banned\n");
            dns_record_free(&msg_send.answers[0]);
            free(msg_send.answers);
            msg_send.answers = NULL;
            msg_send.header.ancount = 0;
            banned = 1;
            dns_header_set_flags(&(msg_send.header), msg_send.header.flags, 0, RCODE_NAME_ERROR);
            break;
        }

        // dns_record_print(msg_send.answers);

    }

    // QueryPerformanceCounter(&time_arr[2]);

    if (msg_send.header.ancount == 0 && banned == 0)
    {
        // printf("not found in database\n");
        transaction_arg_t arg;
        arg.msg = msg;
        arg.org_id = ori_id;
        arg.id = transaction_id;
        arg.sock_in = sock_in;
        arg.start_time = time(NULL);

        // 若元消息未释放，则释放
        if (!dns_message_is_empty(&transactions[transaction_id].msg))
        {
            dns_message_free(&transactions[transaction_id].msg);
        }

        dns_transaction_set(&arg);

        msg.header.id = transaction_id;
        dns_question_upstream(&msg);
    }
    else
    {
        msg_send.header.id = ori_id;
        protocol_send(s, &sock_in, &msg_send);

        dns_message_free(&msg);
    }
    dns_message_free(&msg_send);

    // QueryPerformanceCounter(&time_arr[3]);


    // for (size_t i = 1; i < time_count; i++)
    // {
    //     printf("%d ", time_arr[i].QuadPart - time_arr[i - 1].QuadPart);
    // }
    // printf("\n");

}

// 处理DNS响应的线程
void dns_handle_r(dns_handle_arg_t* arg)
{
    // printf("dns_handle_r\n");

    // SOCKET* s = arg->s;
    // SOCKADDR_IN sock_in = arg->sock_in;
    dns_message_t upstream_msg = arg->msg;
    free(arg);

    uint16_t transaction_id = upstream_msg.header.id;
    uint16_t ori_id = transactions[transaction_id].org_id;
    SOCKADDR_IN sock_in = transactions[transaction_id].sock_in;
    dns_message_t msg = transactions[transaction_id].msg;

    upstream_msg.header.id = ori_id;
    protocol_send(s, &sock_in, &upstream_msg);

    dns_message_free(&msg);
    dns_message_free(&upstream_msg);
}

// 向上游DNS服务器发送DNS请求
void dns_question_upstream(dns_message_t* msg)
{
    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(53);
    sock_in.sin_addr.s_addr = inet_addr(DNS_UPSTREAM_SERVER);
    protocol_send(s_upstream, &sock_in, msg);
}