#ifndef DNS_H__
#define DNS_H__

#include "protocol.h"

typedef struct {
    SOCKADDR_IN sock_in;
    dns_message_t msg;
} dns_handle_arg_t;

typedef struct {
    SOCKADDR_IN sock_in;
    uint16_t org_id;
    uint16_t id;
    dns_message_t msg;
    dns_message_t msg_send;
} transaction_arg_t;

#define DNS_UPSTREAM_SERVER "10.3.9.4"
#define DNS_UPSTREAM_TIMEOUT 500
#define DNS_UPSTREAM_LISTEN_PORT 12345

extern int32_t transaction_id_counter;

void dns_handle_q(dns_handle_arg_t *arg);
void dns_handle_r(dns_handle_arg_t *arg);

void dns_transaction_id_init();
void dns_transaction_id_free();
int32_t dns_transaction_id_get();
void dns_transaction_id_put(uint16_t id);
void dns_transaction_id_set_state(uint16_t id, uint8_t state);
uint8_t dns_transaction_id_get_state(uint16_t id);

void dns_question_upstream(dns_message_t* msg);
void wait_for_upstream(transaction_arg_t* arg);

#endif