#include "dns.h"
#include <pthread.h>
#include <stdio.h>
#include "main.h"

uint16_t transaction_id_counter = 0;
uint16_t transaction_id_base = 0;
uint16_t transaction_id_bucket[65536] = { 0 };
uint8_t transaction_id_state[65536] = { 0 };
pthread_mutex_t transaction_id_mutex;
dns_message_t dns_msg_cache[65536] = { 0 };

void dns_transaction_id_init()
{
    transaction_id_counter = 0;
    for (int i = 0; i < 65536; i++)
    {
        transaction_id_bucket[i] = i;
    }
    pthread_mutex_init(&transaction_id_mutex, NULL);
}

void dns_transaction_id_free()
{
    pthread_mutex_destroy(&transaction_id_mutex);
}

int32_t dns_transaction_id_get()
{
    pthread_mutex_lock(&transaction_id_mutex);
    if (transaction_id_counter == 65536)
    {
        pthread_mutex_unlock(&transaction_id_mutex);
        return -1;
    }
    uint16_t index = transaction_id_base + transaction_id_counter;
    uint16_t id = transaction_id_bucket[index];
    transaction_id_counter++;

    pthread_mutex_unlock(&transaction_id_mutex);
    return id;
}

void dns_transaction_id_put(uint16_t id)
{
    pthread_mutex_lock(&transaction_id_mutex);
    if (transaction_id_counter == 0)
    {
        pthread_mutex_unlock(&transaction_id_mutex);
        return;
    }
    transaction_id_counter--;
    transaction_id_bucket[transaction_id_base] = id;
    transaction_id_base++;
    pthread_mutex_unlock(&transaction_id_mutex);
}

inline void dns_transaction_id_set_state(uint16_t id, uint8_t state)
{
    pthread_mutex_lock(&transaction_id_mutex);
    transaction_id_state[id] = state;
    pthread_mutex_unlock(&transaction_id_mutex);
}

inline uint8_t dns_transaction_id_get_state(uint16_t id)
{
    return transaction_id_state[id];
}

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

    dns_message_t msg_send;
    // msg_send = msg;
    dns_message_copy(&msg_send, &msg);

    msg_send.header.flags |= FLAG_QR;

    uint8_t banned = 0;

    // QueryPerformanceCounter(&time_arr[1]);

    // 当有一个本地查询失败时，就不再进行本地查询
    for (int i = 0; i < msg_send.header.qdcount; i++)
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

        // if (question.type != TYPE_A || question.class != CLASS_IN)
        // {
        //     msg_send.header.ancount = 0;
        //     break;
        // }


        // test
        // msg_send.header.ancount = 0;
        // msg_send.answers = NULL;
        // banned = 1;
        // dns_header_set_flags(&(msg_send.header), msg_send.header.flags, 0, RCODE_NAME_ERROR);
        // break;

        msg_send.header.ancount = 1;
        msg_send.answers = malloc(sizeof(dns_record_t));
        database_lookup(question.name, msg_send.answers);
        if (msg_send.answers[0].type == 0)
        {
            dns_record_free(&msg_send.answers[0]);
            free(msg_send.answers);
            msg_send.header.ancount = 0;
            break;
        }

        if (*(msg_send.answers[0].rdata) == 0)
        {
            // printf("banned\n");
            dns_record_free(&msg_send.answers[0]);
            free(msg_send.answers);
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
        transaction_arg_t* arg = malloc(sizeof(transaction_arg_t));
        arg->msg = msg;
        arg->msg_send = msg_send;
        arg->org_id = ori_id;
        arg->id = transaction_id;
        arg->sock_in = sock_in;
        pthread_create(NULL, NULL, (void* (*)(void*))wait_for_upstream, (void*)arg);
    }
    else
    {
        msg_send.header.id = ori_id;
        protocol_send(s, &sock_in, &msg_send);

        dns_message_free(&msg);
        dns_message_free(&msg_send);

        dns_transaction_id_put(transaction_id);
    }

    // QueryPerformanceCounter(&time_arr[3]);


    // for (size_t i = 1; i < time_count; i++)
    // {
    //     printf("%d ", time_arr[i].QuadPart - time_arr[i - 1].QuadPart);
    // }
    // printf("\n");

}

void wait_for_upstream(transaction_arg_t* arg)
{
    dns_message_t msg = arg->msg;
    dns_message_t msg_send = arg->msg_send;
    uint16_t ori_id = arg->org_id;
    uint16_t transaction_id = arg->id;
    SOCKADDR_IN sock_in = arg->sock_in;
    free(arg);

    dns_transaction_id_set_state(transaction_id, 0);
    msg.header.id = transaction_id;
    dns_question_upstream(&msg);

    size_t count = 0;
    while (dns_transaction_id_get_state(transaction_id) == 0 && count < DNS_UPSTREAM_TIMEOUT)
    {
        Sleep(10);
        count++;
    }
    if (count < DNS_UPSTREAM_TIMEOUT)
    {
        dns_message_t upstream_msg_send;
        upstream_msg_send = dns_msg_cache[transaction_id];
        upstream_msg_send.header.id = ori_id;
        protocol_send(s, &sock_in, &upstream_msg_send);
        dns_message_free(&upstream_msg_send);
    }
    else
    {
        dns_header_set_flags(&(msg_send.header), msg_send.header.flags, 0, RCODE_SERVER_FAILURE);
        msg_send.header.id = ori_id;
        protocol_send(s, &sock_in, &msg_send);
    }

    dns_message_free(&msg);
    dns_message_free(&msg_send);

    dns_transaction_id_put(transaction_id);
}


void dns_handle_r(dns_handle_arg_t* arg)
{
    // SOCKET* s = arg->s;
    // SOCKADDR_IN sock_in = arg->sock_in;
    dns_message_t msg = arg->msg;
    free(arg);

    // printf("dns_handle_r\n");

    dns_msg_cache[msg.header.id] = msg;
    dns_transaction_id_set_state(msg.header.id, 1);
}

void dns_question_upstream(dns_message_t* msg)
{
    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(53);
    sock_in.sin_addr.s_addr = inet_addr(DNS_UPSTREAM_SERVER);
    protocol_send(s_upstream, &sock_in, msg);
}