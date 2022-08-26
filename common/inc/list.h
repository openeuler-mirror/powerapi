/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: luocaimin
 * Create: 2022-08-26
 * Description: provide list interface
 ******************************************************************************/
#ifndef __LIST_H__
#define __LIST_H__

#include <stddef.h>

struct ListHead {
    struct ListHead* next;
    struct ListHead* prev;
};

static inline void ListInit(struct ListHead* list)
{
    list->next = list;
    list->prev = list;
};

/*
 * Add item before next
 */
static inline void ListAdd(struct ListHead* item, struct ListHead* prev, struct ListHead* next)
{
    next->prev = item;
    item->next = next;
    item->prev = prev;
    prev->next = item;
}

/**
 * Add item before head
 */
static inline void ListAddHead(struct ListHead* item, struct ListHead* head)
{
    ListAdd(item, head, head->next);
}

/**
 * Add item after tail
 */
static inline void ListAddTail(struct ListHead* item, struct ListHead* head)
{
    ListAdd(item, head->prev, head);
}

/*
 * Connect two node
 */
static inline void ConnectItem(struct ListHead* prev, struct ListHead* next)
{
    next->prev = prev;
    prev->next = next;
}

/**
 * Delete item from list
 */
static inline void DelItem(struct ListHead* item)
{
    ConnectItem(item->prev, item->next);
}

static inline void DelAndClearItem(struct ListHead* item)
{
    DelItem(item);
    item->next = NULL;
    item->prev = NULL;
}

/**
 * Replace item
 */
static inline void ReplaceItem(struct ListHead* oldItem, struct ListHead* newItem)
{
    newItem->next = oldItem->next;
    newItem->next->prev = newItem;
    newItem->prev = oldItem->prev;
    newItem->prev->next = newItem;
}

/**
 * IsLastItem - tests whether item is the last item in list head
 */
static inline int IsLastItem(const struct ListHead* item, const struct ListHead* head)
{
    return item->next == head;
}

/**
 * IsFirstItem - tests whether item is the first item in list head
 */
static inline int IsFirstItem(const struct ListHead* item, const struct ListHead* head)
{
    return item->prev == head;
}

/**
 * IsEmptyList - tests whether a list is empty
 */
static inline int IsEmptyList(const struct ListHead* head)
{
    return head->next == head;
}

static inline void JoinList(const struct ListHead* list, struct ListHead* prev, struct ListHead* next)
{
    struct ListHead* first = list->next;
    struct ListHead* last = list->prev;

    first->prev = prev;
    prev->next = first;

    last->next = next;
    next->prev = last;
}

/**
 * SpliceList - join two lists
 */
static inline void SpliceList(const struct ListHead* list, struct ListHead* head)
{
    if (!IsEmptyList(list)) {
        JoinList(list, head, head->next);
    }
}

/**
 * OFFSETOF - calculate member offset
 */
#define OFFSETOF(type, member) ((size_t) &((type*)0)->member)

/**
 * CONTAINER_OF - cast a member of a structure out to the containing structure
 * @ptr: the pointer to the member.
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 *
 */

#define CONTAINER_OF(ptr, type, member) ({ (type*)((char*)(ptr) - OFFSETOF(type, member));})

/**
 * GET_LIST_ITEM - get the struct address by it's' member
 * @ptr: the ListHead pointer.
 * @type: the type of the struct .
 * @member: the name of the ListHead within the struct.
 */
#define GET_LIST_ITEM(ptr, type, member) \
    CONTAINER_OF(ptr, type, member)

/**
 * GET_FIRST_LIST_ITEM - get the first element from a list
 */
#define GET_FIRST_LIST_ITEM(ptr, type, member) \
    GET_LIST_ITEM((ptr)->next, type, member)

/**
 * GET_LAST_ITEM - get the last element from a list
 */
#define GET_LAST_ITEM(ptr, type, member) \
    GET_LIST_ITEM((ptr)->prev, type, member)

/**
 * LIST_NEXT_ITEM - get the next element in list
 * @pos: the type * to cursor
 * @member: the name of the ListHead within the struct.
 */
#define LIST_NEXT_ITEM(pos, member) \
    GET_LIST_ITEM((pos)->member.next, typeof(* (pos)), member)

/**
 * LIST_PREV_ITEM - get the prev element in list
 * @pos: the type * to cursor
 * @member: the name of the ListHead within the struct.
 */
#define LIST_PREV_ITEM(pos, member) \
    GET_LIST_ITEM((pos)->member.prev, typeof(* (pos)), member)

/**
 * LIST_FOR_EACH - iterate over a list
 * @pos: the &struct ListHead to use as a loop cursor.
 * @head: the head for your list.
 */
#define LIST_FOR_EACH(pos, head) \
    for ((pos) = (head)->next; (pos) != (head); (pos) = (pos)->next)

/**
 * LIST_FOR_EACH_PREV - iterate over a list backwards
 * @pos: the &struct ListHead to use as a loop cursor.
 * @head: the head for your list.
 */
#define LIST_FOR_EACH_PREV(pos, head) \
    for ((pos) = (head)->prev; (pos) != (head); (pos) = (pos)->prev)

/**
 * LIST_FOR_EACH_SAFE - remove safe loop
 * @pos: the list_head to use as a loop cursor.
 * @n: the list_head to use as temporary storage
 * @head: the list head
 */
#define LIST_FOR_EACH_SAFE(pos, n, head) \
    for ((pos) = (head)->next, (n) = (pos)->next; (pos) != (head); \
            (pos) = (n), (n) = (pos)->next)

/**
 * FREE_LIST_ITEM - Release the space of linked list elements
 * @pos: the list_head to use as a loop cursor.
 * @n: the list_head to use as temporary storage
 * @head: the list head
 * @type: the type of the container struct this is embedded in.
 * @member: the name of the member within the struct.
 */
#define FREE_LIST_ITEM(pos, n, head, type, member) do { \
    LIST_FOR_EACH_SAFE(pos, n, head) { \
        DelAndClearItem(pos); \
        free((type *)GET_LIST_ITEM(pos, type, member)); \
    } \
}while (0)
#endif
