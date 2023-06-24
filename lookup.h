#ifndef LOOKUP_H__
#define LOOKUP_H__

#include "database.h"
#include "protocol.h"

typedef struct bst_node {
    dns_question_t* question;
    bst_id_t id;
    struct bst_node* left;
    struct bst_node* right;
} bst_node_t;    //二叉树

int question_cmp(const dns_question_t* q1, const dns_question_t* q2);

bst_node_t* bst_insert(bst_node_t* root, const dns_question_t* question, bst_id_t id);
bst_id_t database_lookup_helper(bst_node_t* root, const dns_question_t* question);
bst_id_t database_bst_lookup(const dns_question_t* question);
void database_to_bst(database_t* db);

#endif