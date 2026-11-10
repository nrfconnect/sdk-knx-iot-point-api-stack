/*
 * Copyright (c) 2004 Swedish Institute of Computer Science.
 * All rights reserved.
 * Copyright (c) 2026 KNX Association
 *
 * SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
 *
 * This file is part of the Contiki operating system.
 * Author: Adam Dunkels <adam@sics.se>
 */

/**
 * \defgroup list Linked list library
 *
 * The linked list library provides a set of functions for
 * manipulating linked lists.
 *
 * A linked list is made up of elements where the first element \b
 * must be a pointer. This pointer is used by the linked list library
 * to form lists of the elements.
 *
 * Lists are declared with the LIST() macro. The declaration specifies
 * the name of the list that later is used with all list functions.
 *
 * Lists can be manipulated by inserting or removing elements from
 * either sides of the list (list_push(), list_add(), list_pop(),
 * list_chop()). A specified element can also be removed from inside a
 * list with list_remove(). The head and tail of a list can be
 * extracted using list_head() and list_tail(), respectively.
 *
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define OC_LIST_CONCAT2(s1, s2) s1##s2
#define OC_LIST_CONCAT(s1, s2) OC_LIST_CONCAT2(s1, s2)

/**
 * Declare a linked list.
 *
 * This macro declares a linked list with the specified \c type. The
 * type \b must be a structure (\c struct) with its first element
 * being a pointer. This pointer is used by the linked list library to
 * form the linked lists.
 *
 * The list variable is declared as static to make it easy to use in a
 * single C module without unnecessarily exporting the name to other
 * modules.
 *
 * \param name The name of the list.
 */
#define OC_LIST(name)                                                          \
  static void *OC_LIST_CONCAT(name, _list) = NULL;                             \
  static oc_list_t name = (oc_list_t)&OC_LIST_CONCAT(name, _list)

/**
 * Declare a linked list inside a structure declaraction.
 *
 * This macro declares a linked list with the specified \c type. The
 * type \b must be a structure (\c struct) with its first element
 * being a pointer. This pointer is used by the linked list library to
 * form the linked lists.
 *
 * Internally, the list is defined as two items: the list itself and a
 * pointer to the list. The pointer has the name of the parameter to
 * the macro and the name of the list is a concatenation of the name
 * and the suffix "_list". The pointer must point to the list for the
 * list to work. Thus the list must be initialized before using.
 *
 * The list is initialized with the LIST_STRUCT_INIT() macro.
 *
 * \param name The name of the list.
 */
#define OC_LIST_STRUCT(name)                                                   \
  void *OC_LIST_CONCAT(name, _list);                                           \
  oc_list_t name

/**
 * Initialize a linked list that is part of a structure.
 *
 * This macro sets up the internal pointers in a list that has been
 * defined as part of a struct. This macro must be called before using
 * the list.
 *
 * \param struct_ptr A pointer to the struct
 * \param name The name of the list.
 */
#define OC_LIST_STRUCT_INIT(struct_ptr, name)                                  \
  do {                                                                         \
    (struct_ptr)->name = &((struct_ptr)->OC_LIST_CONCAT(name, _list));         \
    (struct_ptr)->OC_LIST_CONCAT(name, _list) = NULL;                          \
    oc_list_init((struct_ptr)->name);                                          \
  } while (0)

/**
 * The linked list type.
 *
 */
typedef void **oc_list_t;

void oc_list_init(oc_list_t list);
void *oc_list_head(oc_list_t list);
void *oc_list_tail(oc_list_t list);
void *oc_list_pop(oc_list_t list);
void oc_list_push(oc_list_t list, void *item);

void *oc_list_chop(oc_list_t list);

void oc_list_add(oc_list_t list, void *item);
void *oc_list_remove(oc_list_t list, void *item);

int oc_list_length(oc_list_t list);

void oc_list_copy(oc_list_t dest, oc_list_t src);

void oc_list_insert(oc_list_t list, void *previtem, void *newitem);

void *oc_list_item_next(void *item);

#ifdef __cplusplus
}
#endif
