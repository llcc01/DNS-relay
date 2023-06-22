#include "dns.h"
#include <pthread.h>
#include <stdio.h>

int32_t transaction_id_counter = 0;
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
    uint16_t id = transaction_id_bucket[transaction_id_counter];
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
    transaction_id_bucket[transaction_id_counter] = id;
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
    SOCKET* s = arg->s;
    SOCKADDR_IN sock_in = arg->sock_in;
    dns_message_t msg = arg->msg;
    free(arg);

    if (msg.header.flags & FLAG_QR)
    {
        return;
    }

    dns_message_t msg_send = msg;
    msg_send.header.flags |= FLAG_QR;
    for (int i = 0; i < msg_send.header.qdcount; i++)
    {
        dns_question_t question = msg_send.questions[i];
        if (question.type != TYPE_A || question.class != CLASS_IN)
        {
            continue;
        }

        char name[256];
        qname_to_name(question.name, name);
        printf("question: %s\n", name);
        dns_record_t record;
        database_lookup(question.name, &record);
        if (record.type == 0 || *(record.rdata) == 0)
        {
            continue;
        }
        dns_record_print(&record);

        msg_send.header.ancount = 1;
        msg_send.answers = malloc(sizeof(dns_record_t));
        msg_send.answers[0] = record;

    }


    if (msg_send.header.ancount == 0)
    {
        printf("not found\n");
        dns_header_set_flags(&msg_send.header, msg_send.header.flags, 0, 0x3);

        // dns_transaction_id_set_state(msg_send.header.id, 0);
        // msg.header.id = dns_transaction_id_get();
        // dns_question_upstream(s, &msg);
        // while (dns_transaction_id_get_state(msg.header.id) == 0)
        // {
        //     Sleep(1);
        // }
        // dns_transaction_id_put(msg.header.id);
        // msg_send = dns_msg_cache[msg.header.id];
    }

    protocol_send(s, &sock_in, &msg_send);

    if (msg_send.header.ancount > 0)
    {
        free(msg_send.answers);
    }
    if (msg_send.header.nscount > 0)
    {
        free(msg_send.authorities);
    }
    if (msg_send.header.arcount > 0)
    {
        free(msg_send.additionals);
    }

}


void dns_handle_r(dns_handle_arg_t* arg)
{
    SOCKET* s = arg->s;
    SOCKADDR_IN sock_in = arg->sock_in;
    dns_message_t msg = arg->msg;
    free(arg);

    if (!(msg.header.flags & FLAG_QR) || sock_in.sin_addr.s_addr != inet_addr(DNS_UPSTREAM_SERVER))
    {
        return;
    }

    printf("dns_handle_r\n");

    dns_msg_cache[msg.header.id] = msg;
    dns_transaction_id_set_state(msg.header.id, 1);
}

void dns_question_upstream(SOCKET* s, dns_message_t* msg)
{
    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(53);
    sock_in.sin_addr.s_addr = inet_addr(DNS_UPSTREAM_SERVER);
    protocol_send(s, &sock_in, msg);
}