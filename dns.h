#ifndef DNS_H__
#define DNS_H__

#include "protocol.h"

typedef struct {
    SOCKET* s;
    SOCKADDR_IN sock_in;
    dns_message_t msg;
} dns_handle_arg_t;

#define DNS_UPSTREAM_SERVER "10.3.9.44"

void dns_handle_q(dns_handle_arg_t *arg);
void dns_handle_r(dns_handle_arg_t *arg);

void dns_transaction_id_init();
void dns_transaction_id_free();
int32_t dns_transaction_id_get();
void dns_transaction_id_put(uint16_t id);
void dns_transaction_id_set_state(uint16_t id, uint8_t state);
uint8_t dns_transaction_id_get_state(uint16_t id);

void dns_question_upstream(SOCKET* s, dns_message_t* msg);


#endif