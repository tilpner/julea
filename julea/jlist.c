/*
 * Copyright (c) 2010 Michael Kuhn
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 **/

#include <glib.h>

#include "jlist.h"
#include "jlist-internal.h"

/**
 * \defgroup JList List
 * @{
 **/

/**
 * A linked list which allows fast prepend and append operations.
 * Also allows querying the length of the list without iterating over it.
 **/
struct JList
{
	/**
	 * Pointer to the first element.
	 **/
	JListElement* head;
	/**
	 * Pointer to the last element.
	 **/
	JListElement* tail;

	/**
	 * The list's length.
	 **/
	guint length;
};

/**
 * Creates a new list.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \return A new list.
 **/
JList*
j_list_new (void)
{
	JList* list;

	list = g_slice_new(JList);
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;

	return list;
}

/**
 * Frees the memory allocated for the list.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param list A list.
 * \param func A function to free the element data, or NULL.
 **/
void
j_list_free (JList* list, JListFreeFunc func)
{
	JListElement* element;

	g_return_if_fail(list != NULL);

	element = list->head;

	while (element != NULL)
	{
		JListElement* next;

		if (func != NULL)
		{
			func(element->data);
		}

		next = element->next;
		g_slice_free(JListElement, element);
		element = next;
	}

	g_slice_free(JList, list);
}

/**
 * Returns the list's length.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param list A list.
 *
 * \return The list's length.
 **/
guint
j_list_length (JList* list)
{
	g_return_val_if_fail(list != NULL, 0);

	return list->length;
}

void
j_list_append (JList* list, gpointer data)
{
	JListElement* element;

	g_return_if_fail(list != NULL);
	g_return_if_fail(data != NULL);

	element = g_slice_new(JListElement);
	element->next = NULL;
	element->data = data;

	list->length++;

	if (list->tail != NULL)
	{
		list->tail->next = element;
	}

	list->tail = element;

	if (list->head == NULL)
	{
		list->head = list->tail;
	}
}

void
j_list_prepend (JList* list, gpointer data)
{
	JListElement* element;

	g_return_if_fail(list != NULL);
	g_return_if_fail(data != NULL);

	element = g_slice_new(JListElement);
	element->next = list->head;
	element->data = data;

	list->length++;
	list->head = element;

	if (list->tail == NULL)
	{
		list->tail = list->head;
	}
}

/**
 * Returns a specific list element.
 *
 * This has to iterate over the list to find the specified element and, therefore, might be slow.
 * It is primarily intended as a convenience function to get the first or last element.
 *
 * \author Michael Kuhn
 *
 * \param list A list.
 * \param index The list element's index.
 *
 * \return A list element, or NULL.
 **/
gpointer
j_list_get (JList* list, gint index)
{
	gpointer data = NULL;

	g_return_val_if_fail(list != NULL, NULL);
	g_return_val_if_fail(index < (gint)list->length, NULL);
	g_return_val_if_fail(index >= (gint)list->length * -1, NULL);

	if (list->head != NULL && list->tail != NULL)
	{
		JListElement* element;
		guint real_index;
		guint i;

		real_index = ((index < 0) ? list->length : 0) + index;
		element = list->head;

		if (real_index == (list->length - 1))
		{
			return list->tail->data;
		}

		for (i = 0; i < real_index; i++)
		{
			element = element->next;

			if (element == NULL)
			{
				return NULL;
			}
		}

		data = element->data;
	}

	return data;
}

/* Internal */

/**
 * Returns the list's first element.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param list A JList.
 *
 * \return A JListElement.
 **/
JListElement*
j_list_head (JList* list)
{
	g_return_val_if_fail(list != NULL, NULL);

	return list->head;
}

/**
 * @}
 **/
