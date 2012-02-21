/*
 * Copyright (c) 2010-2012 Michael Kuhn
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

#include <joperation.h>
#include <joperation-internal.h>

#include <jbackground-operation-internal.h>
#include <jcache-internal.h>
#include <jcollection-internal.h>
#include <jcommon-internal.h>
#include <jitem-internal.h>
#include <jlist.h>
#include <jlist-iterator.h>
#include <joperation-part-internal.h>
#include <jsemantics.h>
#include <jstore-internal.h>

/**
 * \defgroup JOperation Operation
 *
 * @{
 **/

/**
 * An operation.
 **/
struct JOperation
{
	/**
	 * The list of pending operation parts.
	 **/
	JList* list;

	JSemantics* semantics;

	JBackgroundOperation* background_operation;

	/**
	 * The reference count.
	 **/
	gint ref_count;
};

struct JOperationAsync
{
	JOperation* operation;
	JOperationCompletedFunc func;
	gpointer user_data;
};

struct JOperationCache
{
	JCache* cache;
	JList* list;
};

typedef struct JOperationAsync JOperationAsync;
typedef struct JOperationCache JOperationCache;

static JOperationCache* j_operation_cache = NULL;
static JSemantics* j_operation_default_semantics = NULL;

static
JSemantics*
j_operation_get_default_semantics (void)
{
	if (G_UNLIKELY(j_operation_default_semantics == NULL))
	{
		j_operation_default_semantics = j_semantics_new(J_SEMANTICS_TEMPLATE_DEFAULT);
	}

	return j_operation_default_semantics;
}

static
gpointer
j_operation_background_operation (gpointer data)
{
	gboolean ret;

	JOperationAsync* async = data;

	ret = j_operation_execute(async->operation);

	if (async->func != NULL)
	{
		(*async->func)(async->operation, ret, async->user_data);
	}

	g_slice_free(JOperationAsync, async);

	return NULL;
}

void
j_operation_cache_init (void)
{
	JOperationCache* cache;

	g_return_if_fail(j_operation_cache == NULL);

	cache = g_slice_new(JOperationCache);
	cache->cache = j_cache_new(J_MIB(50));
	cache->list = j_list_new((JListFreeFunc)j_operation_unref);

	g_atomic_pointer_set(&j_operation_cache, cache);
}

void
j_operation_cache_fini (void)
{
	JOperationCache* cache;

	g_return_if_fail(j_operation_cache != NULL);

	j_operation_cache_flush();

	cache = g_atomic_pointer_get(&j_operation_cache);
	g_atomic_pointer_set(&j_operation_cache, NULL);

	j_list_unref(cache->list);
	j_cache_free(cache->cache);

	g_slice_free(JOperationCache, cache);
}

// FIXME
static gboolean j_operation_execute_internal (JOperation*);

gboolean
j_operation_cache_flush (void)
{
	JListIterator* iterator;
	gboolean ret = TRUE;

	iterator = j_list_iterator_new(j_operation_cache->list);

	while (j_list_iterator_next(iterator))
	{
		JOperation* operation = j_list_iterator_get(iterator);

		ret = j_operation_execute_internal(operation) && ret;
	}

	j_list_iterator_free(iterator);

	j_list_delete_all(j_operation_cache->list);
	j_cache_clear(j_operation_cache->cache);

	return ret;
}

static
gboolean
j_operation_cache_test (JOperationPart* part)
{
	gboolean ret = FALSE;

	switch (part->type)
	{
		case J_OPERATION_CREATE_STORE:
		case J_OPERATION_DELETE_STORE:
		case J_OPERATION_STORE_CREATE_COLLECTION:
		case J_OPERATION_STORE_DELETE_COLLECTION:
		case J_OPERATION_COLLECTION_CREATE_ITEM:
		case J_OPERATION_COLLECTION_DELETE_ITEM:
		case J_OPERATION_ITEM_WRITE:
			ret = TRUE;
			break;

		case J_OPERATION_GET_STORE:
		case J_OPERATION_STORE_GET_COLLECTION:
		case J_OPERATION_COLLECTION_GET_ITEM:
		case J_OPERATION_ITEM_GET_STATUS:
		case J_OPERATION_ITEM_READ:
			ret = FALSE;
			break;

		case J_OPERATION_NONE:
		default:
			g_warn_if_reached();
	}

	return ret;
}

static
gboolean
j_operation_cache_add (JOperation* operation)
{
	JListIterator* iterator;
	gboolean can_cache = TRUE;

	iterator = j_list_iterator_new(operation->list);

	while (j_list_iterator_next(iterator))
	{
		JOperationPart* part = j_list_iterator_get(iterator);

		can_cache = j_operation_cache_test(part) && can_cache;

		if (!can_cache)
		{
			break;
		}
	}

	j_list_iterator_free(iterator);

	if (!can_cache)
	{
		return FALSE;
	}

	iterator = j_list_iterator_new(operation->list);

	while (j_list_iterator_next(iterator))
	{
		JOperationPart* part = j_list_iterator_get(iterator);

		if (part->type == J_OPERATION_ITEM_WRITE)
		{
			gpointer data;

			data = j_cache_put(j_operation_cache->cache, part->u.item_write.data, part->u.item_write.length);

			if (data == NULL)
			{
				return FALSE;
			}

			part->u.item_write.data = data;
		}
	}

	j_list_iterator_free(iterator);

	j_list_append(j_operation_cache->list, j_operation_ref(operation));

	return TRUE;
}

/**
 * Creates a new operation.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param semantics A semantics object.
 *
 * \return A new operation. Should be freed with j_operation_unref().
 **/
JOperation*
j_operation_new (JSemantics* semantics)
{
	JOperation* operation;

	operation = g_slice_new(JOperation);
	operation->list = j_list_new((JListFreeFunc)j_operation_part_free);
	operation->background_operation = NULL;
	operation->ref_count = 1;

	if (semantics == NULL)
	{
		semantics = j_operation_get_default_semantics();
	}

	operation->semantics = j_semantics_ref(semantics);

	return operation;
}

/**
 * Increases the operation's reference count.
 *
 * \author Michael Kuhn
 *
 * \param list An operation.
 *
 * \return The operation.
 **/
JOperation*
j_operation_ref (JOperation* operation)
{
	g_return_val_if_fail(operation != NULL, NULL);

	g_atomic_int_inc(&(operation->ref_count));

	return operation;
}

/**
 * Decreases the operation's reference count.
 * When the reference count reaches zero, frees the memory allocated for the operation.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 **/
void
j_operation_unref (JOperation* operation)
{
	g_return_if_fail(operation != NULL);

	if (g_atomic_int_dec_and_test(&(operation->ref_count)))
	{
		j_operation_wait(operation);

		if (operation->semantics != NULL)
		{
			j_semantics_unref(operation->semantics);
		}

		j_list_unref(operation->list);

		g_slice_free(JOperation, operation);
	}
}

/**
 * Executes the operation parts of a given operation type.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param type An operation type.
 * \param list A list of operation parts.
 **/
static
gboolean
j_operation_execute_same (JOperation* operation, JList* list)
{
	JOperationPart* part;
	JOperationType type;
	gboolean ret = TRUE;

	part = j_list_get_first(list);

	if (part == NULL)
	{
		return ret;
	}

	type = part->type;

	switch (type)
	{
		case J_OPERATION_CREATE_STORE:
			ret = j_create_store_internal(operation, list);
			break;
		case J_OPERATION_DELETE_STORE:
			ret = j_delete_store_internal(operation, list);
			break;
		case J_OPERATION_GET_STORE:
			ret = j_get_store_internal(operation, list);
			break;
		case J_OPERATION_STORE_CREATE_COLLECTION:
			ret = j_store_create_collection_internal(operation, list);
			break;
		case J_OPERATION_STORE_DELETE_COLLECTION:
			ret = j_store_delete_collection_internal(operation, list);
			break;
		case J_OPERATION_STORE_GET_COLLECTION:
			ret = j_store_get_collection_internal(operation, list);
			break;
		case J_OPERATION_COLLECTION_CREATE_ITEM:
			ret = j_collection_create_item_internal(operation, list);
			break;
		case J_OPERATION_COLLECTION_DELETE_ITEM:
			ret = j_collection_delete_item_internal(operation, list);
			break;
		case J_OPERATION_COLLECTION_GET_ITEM:
			ret = j_collection_get_item_internal(operation, list);
			break;
		case J_OPERATION_ITEM_GET_STATUS:
			ret = j_item_get_status_internal(operation, list);
			break;
		case J_OPERATION_ITEM_READ:
			ret = j_item_read_internal(operation, list);
			break;
		case J_OPERATION_ITEM_WRITE:
			ret = j_item_write_internal(operation, list);
			break;
		case J_OPERATION_NONE:
		default:
			ret = FALSE;
			g_warn_if_reached();
	}

	j_list_delete_all(list);

	return ret;
}

/**
 * Executes the operation.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 *
 * \return TRUE on success, FALSE if an error occurred.
 **/
static
gboolean
j_operation_execute_internal (JOperation* operation)
{
	JList* same_list;
	JListIterator* iterator;
	JOperationType last_type;
	gpointer last_key;
	gboolean ret = TRUE;

	iterator = j_list_iterator_new(operation->list);
	same_list = j_list_new(NULL);
	last_key = NULL;
	last_type = J_OPERATION_NONE;

	while (j_list_iterator_next(iterator))
	{
		JOperationPart* part = j_list_iterator_get(iterator);

		if ((part->type != last_type || part->key != last_key) && last_type != J_OPERATION_NONE)
		{
			ret = j_operation_execute_same(operation, same_list) && ret;
		}

		last_key = part->key;
		last_type = part->type;
		j_list_append(same_list, part);
	}

	ret = j_operation_execute_same(operation, same_list) && ret;

	j_list_unref(same_list);
	j_list_iterator_free(iterator);

	j_list_delete_all(operation->list);

	return ret;
}

/**
 * Executes the operation.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 *
 * \return TRUE on success, FALSE if an error occurred.
 **/
gboolean
j_operation_execute (JOperation* operation)
{
	g_return_val_if_fail(operation != NULL, FALSE);

	if (j_list_length(operation->list) == 0)
	{
		return FALSE;
	}

	if (j_semantics_get(operation->semantics, J_SEMANTICS_CONSISTENCY) == J_SEMANTICS_CONSISTENCY_EVENTUAL
	    && j_operation_cache_add(operation))
	{
		return TRUE;
	}

	j_operation_cache_flush();

	return j_operation_execute_internal(operation);
}

/**
 * Executes the operation asynchronously.
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 * \param func      A complete function.
 *
 * \return TRUE on success, FALSE if an error occurred.
 **/
void
j_operation_execute_async (JOperation* operation, JOperationCompletedFunc func, gpointer user_data)
{
	JOperationAsync* async;

	g_return_if_fail(operation != NULL);

	async = g_slice_new(JOperationAsync);
	async->operation = operation;
	async->func = func;
	async->user_data = user_data;

	operation->background_operation = j_background_operation_new(j_operation_background_operation, async);
}

void
j_operation_wait (JOperation* operation)
{
	g_return_if_fail(operation != NULL);

	if (operation->background_operation != NULL)
	{
		j_background_operation_wait(operation->background_operation);
		j_background_operation_unref(operation->background_operation);
		operation->background_operation = NULL;
	}
}

/* Internal */

/**
 * Returns an operation's semantics.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 *
 * \return A semantics object.
 **/
JSemantics*
j_operation_get_semantics (JOperation* operation)
{
	JSemantics* ret;

	g_return_val_if_fail(operation != NULL, NULL);

	j_trace_enter(j_trace(), G_STRFUNC);
	ret = operation->semantics;
	j_trace_leave(j_trace(), G_STRFUNC);

	return ret;
}

/**
 * Adds a new part to the operation.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * \endcode
 *
 * \param operation An operation.
 * \param part      An operation part.
 **/
void
j_operation_add (JOperation* operation, JOperationPart* part)
{
	g_return_if_fail(operation != NULL);
	g_return_if_fail(part != NULL);

	j_list_append(operation->list, part);
}

/**
 * @}
 **/
