#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "database.h"
#include "lookup.h"

bst_node_t* database_bst = NULL; //数据库二叉树的根节点

int question_cmp(const dns_question_t* q1, const dns_question_t* q2)
{
    int cmp = strcmp(q1->name, q2->name);
    if (cmp != 0)
    {
        return cmp;
    }
    if (q1->type != q2->type)
    {
        return q1->type - q2->type;
    }
    return q1->class - q2->class;
}

bst_node_t* bst_insert(bst_node_t* root, const dns_question_t* question, bst_id_t id)
{
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

    if (cmp < 0)
    {
        root->left = bst_insert(root->left, question, id);
    }
    else if (cmp > 0)
    {
        root->right = bst_insert(root->right, question, id);
    }

    return root;
}

void database_to_bst(database_t* db)
{
    for (int i = 0; i < db->size; ++i)
    {
        database_bst = bst_insert(database_bst, &(db->msgs[i].questions[0]), i);
    }
}

bst_id_t database_lookup_helper(bst_node_t* root, const dns_question_t* question)
{
    if (root == NULL)
    {
        return BST_INVALID_ID;
    }

    int cmp = question_cmp(root->question, question);

    if (cmp == 0)
    {
        return root->id;
    }
    else if (cmp < 0)
    {
        return database_lookup_helper(root->left, question);
    }
    else
    {
        return database_lookup_helper(root->right, question);
    }
}

bst_id_t database_bst_lookup(const dns_question_t* question)
{
    return database_lookup_helper(database_bst, question);
}

