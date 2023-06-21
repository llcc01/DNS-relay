#include <stdio.h>
#include "database.h"
#include "protocol.h"

int main(int, char**) {
    printf("Hello, from DNS relay!\n");

    // database_init();
    // database_load(FILENAME);

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

    protocol_send(&s, inet_addr("10.3.9.44"), &msg);
    dns_message_free(&msg);

    uint32_t from_addr;
    protocol_recv(&s, &from_addr, &msg);
    for (int i = 0; i < msg.header.ancount; i++) {
        dns_record_print(&msg.answers[i]);
    }


    return 0;
}
