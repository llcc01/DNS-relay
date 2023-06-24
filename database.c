#include "database.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "protocol.h"
#include "main.h"
#include "lookup.h"
#include "logger.h"

database_t database;

dns_record_t local_name_rec;

void database_init()
{
    LOG_INFO("database_init");
    database.msgs = NULL;
    database.size = 0;

    char local_name[NAME_MAX_SIZE];
    name_to_qname(LOCAL_NAME, local_name);
    local_name_rec.name = malloc(strlen(local_name) + 1);
    strcpy(local_name_rec.name, local_name);

    local_name_rec.type = TYPE_PTR;
    local_name_rec.class = CLASS_IN;
    local_name_rec.ttl = 120;

    char local_domain[NAME_MAX_SIZE];
    name_to_qname(LOCAL_DOMAIN, local_domain);
    local_name_rec.rdlength = strlen(local_domain) + 1;
    local_name_rec.rdata = malloc(local_name_rec.rdlength);
    memcpy(local_name_rec.rdata, local_domain, local_name_rec.rdlength);
}

void database_add(const dns_message_t* msg)
{
    // add the record to the database
    LOG_DEBUG("database_add %s %d.%d.%d.%d", msg->answers[0].rdata, msg->answers[0].rdata[0], msg->answers[0].rdata[1], msg->answers[0].rdata[2], msg->answers[0].rdata[3]);

    database.msgs = realloc(database.msgs, (database.size + 1) * sizeof(dns_message_t));
    dns_message_copy(&(database.msgs[database.size]), msg);
    database.msgs[database.size].header.id = database.size;

    database.size++;
}

void database_get_record(bst_id_t id, dns_record_t* record)
{
    // get the record from the database
    LOG_DEBUG("database_get_msg");
    if (id >= database.size)
    {
        PANIC("Error: database_get_msg: id >= database.size");
    }
    dns_record_copy(record, &(database.msgs[id].answers[0]));
}

void database_get_msg(bst_id_t id, dns_message_t* msg)
{
    // get the message from the database
    LOG_DEBUG("database_get_msg");
    if (id >= database.size)
    {
        PANIC("Error: database_get_msg: id >= database.size");
    }
    dns_message_copy(msg, &(database.msgs[id]));
}

void database_load(const char* filename)
{
    // load the database from the file
    LOG_DEBUG("database_load");
    FILE* fp = fopen(filename, "r");
    if (fp == NULL) {
        PANIC("Error: cannot open file %s", filename);
    }
    char name[256];
    int ip_addr[4];
    dns_question_t question;
    dns_record_t record;
    dns_message_t msg;
    msg.header.qdcount = 1;
    msg.header.ancount = 1;
    msg.header.nscount = 0;
    msg.header.arcount = 0;
    msg.questions = &question;
    msg.answers = &record;
    while (fscanf(fp, "%d.%d.%d.%d %s", &ip_addr[0], &ip_addr[1], &ip_addr[2], &ip_addr[3], name) != EOF)
    {
        char qname[NAME_MAX_SIZE];
        name_to_qname(name, qname);

        question.name = qname;
        question.type = TYPE_A;
        question.class = CLASS_IN;

        record.name = qname;
        record.type = TYPE_A;
        record.class = CLASS_IN;
        record.ttl = 120;
        record.rdlength = 4;
        record.rdata = malloc(4);
        for (size_t i = 0; i < 4; i++)
        {
            record.rdata[i] = ip_addr[i];
        }

        database_add(&msg);
        // dns_record_print(&record);
    }

    database_to_bst(&database);
}

bst_id_t database_lookup(const dns_question_t* question)
{
    // lookup the record in the database
    LOG_DEBUG("database_lookup");

    for (int i = 0; i < database.size; i++)
    {
        if (question_cmp(question, &(database.msgs[i].questions[0])) == 0)
        {
            return database.msgs[i].header.id;
        }
    }
    
    return BST_INVALID_ID;
}

