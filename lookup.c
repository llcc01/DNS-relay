#include "lookup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "database.h"

bst_node_t* static_index = NULL;  //数据库二叉树的根节点
bst_node_t* cache_index = NULL;   // cache二叉树的根节点

int question_cmp(const dns_question_t* q1, const dns_question_t* q2) {
  int cmp = strcmp(q1->name, q2->name);
  if (cmp != 0) {
    return cmp;
  }
  if (q1->type != q2->type) {
    return q1->type - q2->type;
  }
  return q1->class - q2->class;
}

// 释放二叉树节点数据
void bst_node_free(bst_node_t* node) {
  if (node == NULL) {
    return;
  }
  dns_question_free(node->question);
  free(node->question);
}

bst_node_t* bst_insert(bst_node_t* root, const dns_question_t* question,
                       db_id_t id) {
  if (root == NULL) {
    bst_node_t* node = (bst_node_t*)malloc(sizeof(bst_node_t));
    node->question = malloc(sizeof(dns_question_t));
    dns_question_copy(node->question, question);
    node->id = id;
    node->left = NULL;
    node->right = NULL;
    return node;
  }

  int cmp = question_cmp(root->question, question);

  if (cmp < 0) {
    root->left = bst_insert(root->left, question, id);
  } else if (cmp > 0) {
    root->right = bst_insert(root->right, question, id);
  }

  return root;
}

bst_node_t* bst_delete(bst_node_t* root, const dns_question_t* question) {
  if (root == NULL) {
    return NULL;
  }

  int cmp = question_cmp(root->question, question);

  if (cmp < 0) {
    root->left = bst_delete(root->left, question);
  } else if (cmp > 0) {
    root->right = bst_delete(root->right, question);
  } else {
    if (root->left == NULL) {
      bst_node_t* rightChild = root->right;
      bst_node_free(root);
      free(root);
      return rightChild;
    } else if (root->right == NULL) {
      bst_node_t* leftChild = root->left;
      bst_node_free(root);
      free(root);
      return leftChild;
    }

    bst_node_t* minNode = bst_node_find_min(root->right);
    bst_node_free(root);
    dns_question_copy(root->question, minNode->question);
    root->right = bst_delete(root->right, minNode->question);
  }

  return root;
}

bst_node_t* bst_node_find_min(bst_node_t* node) {
  bst_node_t* current = node;
  while (current && current->left != NULL) {
    current = current->left;
  }
  return current;
}

// 释放二叉树
void bst_free(bst_node_t* root) {
  if (root == NULL) {
    return;
  }

  bst_free(root->left);
  bst_free(root->right);

  bst_node_free(root);
  free(root);
}

void database_to_bst(const database_t* db) {
  for (int i = 0; i < db->size; ++i) {
    static_index = bst_insert(static_index, &(db->msgs[i].questions[0]), i);
  }
}

db_id_t database_lookup_helper(const bst_node_t* root,
                               const dns_question_t* question) {
  if (root == NULL) {
    return DB_INVALID_ID;
  }

  int cmp = question_cmp(root->question, question);
  // char name1[NAME_MAX_SIZE];
  // char name2[NAME_MAX_SIZE];
  // qname_to_name(root->question->name, name1);
  // qname_to_name(question->name, name2);
  // LOG_INFO("database_lookup_helper: %s, %s", name1, name2);

  if (cmp == 0) {
    return root->id;
  } else if (cmp < 0) {
    return database_lookup_helper(root->left, question);
  } else {
    return database_lookup_helper(root->right, question);
  }
}

// 数据库二叉树查找
inline db_id_t database_bst_lookup(const bst_node_t* root,
                                   const dns_question_t* question) {
  return database_lookup_helper(root, question);
}
