#include <stdio.h>
#include <pthread.h>
#include "database.h"
#include "protocol.h"
#include "dns.h"

int main(int, char**) {
    printf("Hello, from DNS relay!\n");

    database_init();
    database_load(FILENAME);

    // dns_record_t record;
    // database_lookup("test1", &record);
    // dns_record_print(&record);

    SOCKET s;
    protocol_init(&s, 53);

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

    while (1)
    {
        SOCKADDR_IN from_addr;
        dns_message_t msg;

        protocol_recv(&s, &from_addr, &msg);

        dns_handle_arg_t* arg = malloc(sizeof(dns_handle_arg_t));
        arg->s = &s;
        arg->sock_in = from_addr;
        arg->msg = msg;

        if (msg.header.flags & FLAG_QR)
        {
            pthread_create(NULL, NULL, (void* (*)(void*))dns_handle_r, (void*)arg);
        }
        else
        {
            pthread_create(NULL, NULL, (void* (*)(void*))dns_handle_q, (void*)arg);
        }
    }


    return 0;
}
