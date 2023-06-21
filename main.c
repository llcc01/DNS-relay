#include <stdio.h>
#include "database.h"
#include "protocol.h"

int main(int, char**) {
    printf("Hello, from DNS relay!\n");

    database_init();
    database_load(FILENAME);

    // dns_record_t record;
    // database_lookup("test1", &record);
    // dns_record_print(&record);

    SOCKET s;
    protocol_init(&s);

    dns_message_t msg;
    msg.header.id = 0x11cc;
    dns_header_set_flags(&msg.header, 0, 0, 0);
    msg.header.qdcount = 1;
    msg.header.ancount = 0;
    msg.header.nscount = 0;
    msg.header.arcount = 0;

    msg.questions = malloc(sizeof(dns_question_t));
    char name[256];
    name_to_qname("www.bupt.edu.cn", name);

    msg.questions[0].name = malloc(strlen(name) + 1);
    strcpy(msg.questions[0].name, name);

    msg.questions[0].type = TYPE_A;
    msg.questions[0].class = CLASS_IN;

    msg.answers = NULL;
    msg.authorities = NULL;
    msg.additionals = NULL;

    SOCKADDR_IN sock_in;
    sock_in.sin_family = AF_INET;
    sock_in.sin_port = htons(53);
    sock_in.sin_addr.s_addr = inet_addr("10.3.9.44");
    protocol_send(&s, &sock_in, &msg);
    dns_message_free(&msg);

    SOCKADDR_IN from_addr;
    protocol_recv(&s, &from_addr, &msg);
    for (int i = 0; i < msg.header.ancount; i++)
    {
        dns_record_print(&msg.answers[i]);
    }

    while (1)
    {
        protocol_recv(&s, &from_addr, &msg);
        if (msg.header.flags & FLAG_QR)
        {
            printf("response\n");
            continue;
        }
        for (int i = 0; i < msg.header.qdcount; i++)
        {
            dns_question_t question = msg.questions[i];
            if (question.type != TYPE_A || question.class != CLASS_IN)
            {
                printf("not supported\n");
                dns_header_set_flags(&msg.header, FLAG_QR, 0, 0x3);
                msg.header.ancount = 0;
                protocol_send(&s, &from_addr, &msg);
                continue;
            }
            char name[256];
            qname_to_name(question.name, name);
            printf("question: %s\n", name);
            dns_record_t record;
            database_lookup(question.name, &record);
            if (record.type == 0)
            {
                printf("not found\n");
                dns_header_set_flags(&msg.header, FLAG_QR, 0, 0x3);
                msg.header.ancount = 0;
                protocol_send(&s, &from_addr, &msg);
                continue;
            }
            dns_record_print(&record);
            dns_header_set_flags(&msg.header, FLAG_QR | FLAG_RA | FLAG_RD, 0, 0);
            msg.header.ancount = 1;
            msg.answers = malloc(sizeof(dns_record_t));
            msg.answers[0] = record;
            protocol_send(&s, &from_addr, &msg);
        }
    }


    return 0;
}
