#ifndef LOOKUP_H__
#define LOOKUP_H__

#include "database.h"
#include "protocol.h"

typedef struct bst_node {
  dns_question_t* question;
  db_id_t id;
  struct bst_node* left;
  struct bst_node* right;
} bst_node_t;  //二叉树

int question_cmp(const dns_question_t* q1, const dns_question_t* q2);

bst_node_t* bst_node_find_min(bst_node_t* node);
bst_node_t* bst_insert(bst_node_t* root, const dns_question_t* question,
                       db_id_t id);
bst_node_t* bst_delete(bst_node_t* root, const dns_question_t* question);
db_id_t database_lookup_helper(const bst_node_t* root,
                               const dns_question_t* question);
db_id_t database_bst_lookup(const bst_node_t* root,
                            const dns_question_t* question);
void database_to_bst(const database_t* db);
// bst_node_t* cache_index;//cache二叉树的根节点

extern bst_node_t* static_index;
extern bst_node_t* cache_index;

#endif