/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2020 Michael Kuhn
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <julea-config.h>

#include <glib.h>
#include <glib/gstdio.h>
#include <gmodule.h>

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <julea.h>

#include <betree.h>

struct JBackendData
{
	db_t* db;
	obj_store_t* os;
	// FIXME check whether hash tables can stay global
};

typedef struct JBackendData JBackendData;

struct JBackendObject
{
	obj_t* obj;
	// FIXME: this is redundant, obj also stores path
	gchar* path;
	guint ref_count;
};

typedef struct JBackendObject JBackendObject;

static guint jd_num_backends = 0;

static GHashTable* jd_backend_file_cache = NULL;

G_LOCK_DEFINE_STATIC(jd_backend_file_cache);

static void
jd_backend_files_free(gpointer data)
{
	GHashTable* files = data;

	g_hash_table_destroy(files);
}

// FIXME not deleted?
static GPrivate jd_backend_files = G_PRIVATE_INIT(jd_backend_files_free);

static void
backend_file_unref(gpointer data)
{
	JBackendObject* bo = data;

	g_return_if_fail(bo != NULL);

	G_LOCK(jd_backend_file_cache);

	if (g_atomic_int_dec_and_test(&(bo->ref_count)))
	{
		g_hash_table_remove(jd_backend_file_cache, bo->path);

		j_trace_file_begin(bo->path, J_TRACE_FILE_CLOSE);
		betree_object_close(bo->obj, NULL);
		j_trace_file_end(bo->path, J_TRACE_FILE_CLOSE, 0, 0);

		g_free(bo->path);
		g_slice_free(JBackendObject, bo);
	}

	G_UNLOCK(jd_backend_file_cache);
}

static GHashTable*
jd_backend_files_get_thread(void)
{
	GHashTable* files;

	files = g_private_get(&jd_backend_files);

	if (G_UNLIKELY(files == NULL))
	{
		files = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, backend_file_unref);
		g_private_replace(&jd_backend_files, files);
	}

	return files;
}

static JBackendObject*
backend_file_get(GHashTable* files, gchar const* key)
{
	JBackendObject* bo;

	if ((bo = g_hash_table_lookup(files, key)) != NULL)
	{
		goto end;
	}

	G_LOCK(jd_backend_file_cache);

	if ((bo = g_hash_table_lookup(jd_backend_file_cache, key)) != NULL)
	{
		g_atomic_int_inc(&(bo->ref_count));
		g_hash_table_insert(files, bo->path, bo);
		G_UNLOCK(jd_backend_file_cache);
	}

	/* Attention: The caller must call backend_file_add() if NULL is returned! */

end:
	return bo;
}

static void
backend_file_add(GHashTable* files, JBackendObject* object)
{
	g_hash_table_insert(jd_backend_file_cache, object->path, object);
	g_hash_table_insert(files, object->path, object);

	G_UNLOCK(jd_backend_file_cache);
}

static gboolean
backend_create(gpointer backend_data, gchar const* namespace, gchar const* path, gpointer* backend_object)
{
	JBackendData* bd = backend_data;
	GHashTable* files = jd_backend_files_get_thread();

	JBackendObject* bo = NULL;

	err_t* err = NULL;

	// TODO: re-implement namespacing
	if ((bo = backend_file_get(files, path)) != NULL)
	{
		goto end;
	}

	j_trace_file_begin(path, J_TRACE_FILE_CREATE);

	obj_t* obj = betree_object_create(bd->os, path, strlen(path), &err);

	j_trace_file_end(path, J_TRACE_FILE_CREATE, 0, 0);

	bo = g_slice_new(JBackendObject);
	bo->obj = obj;
	bo->path = g_strdup(path);
	bo->ref_count = 1;

	backend_file_add(files, bo);

end:
	*backend_object = bo;

	return (err != NULL);
}

static gboolean
backend_open(gpointer backend_data, gchar const* namespace, gchar const* path, gpointer* backend_object)
{
	JBackendData* bd = backend_data;
	GHashTable* files = jd_backend_files_get_thread();

	JBackendObject* bo = NULL;

	err_t* err = NULL;

	if ((bo = backend_file_get(files, path)) != NULL)
	{
		goto end;
	}

	j_trace_file_begin(path, J_TRACE_FILE_OPEN);

	obj_t* obj = betree_object_open(bd->os, path, strlen(path), &err);

	j_trace_file_end(path, J_TRACE_FILE_OPEN, 0, 0);

	if (obj)
	{
		bo = g_slice_new(JBackendObject);
		bo->obj = obj;
		bo->path = g_strdup(path);
		bo->ref_count = 1;

		backend_file_add(files, bo);
	}
	else
	{
		return FALSE;
	}

end:
	*backend_object = bo;

	return (err != NULL);
}

static gboolean
backend_delete(gpointer backend_data, gpointer backend_object)
{
	JBackendObject* bo = backend_object;
	GHashTable* files = jd_backend_files_get_thread();
	gboolean ret;

	(void)backend_data;
	err_t* err = NULL;

	j_trace_file_begin(bo->path, J_TRACE_FILE_DELETE);
	ret = (betree_object_delete(bo->obj, &err) == 0);
	if (err)
	{
		betree_print_error(err);
		betree_free_err(err);
		ret = false;
	}
	j_trace_file_end(bo->path, J_TRACE_FILE_DELETE, 0, 0);

	g_hash_table_remove(files, bo->path);

	return ret;
}

static gboolean
backend_close(gpointer backend_data, gpointer backend_object)
{
	JBackendObject* bo = backend_object;
	GHashTable* files = jd_backend_files_get_thread();
	gboolean ret;

	(void)backend_data;

	ret = g_hash_table_remove(files, bo->path);

	return ret;
}

static gboolean
backend_status(gpointer backend_data, gpointer backend_object, gint64* modification_time, guint64* size)
{
	JBackendObject* bo = backend_object;
	gboolean ret = TRUE;

	(void)backend_data;

	if (modification_time != NULL || size != NULL)
	{
		j_trace_file_begin(bo->path, J_TRACE_FILE_STATUS);

		if (modification_time != NULL)
		{
			*modification_time = betree_object_mtime_us(bo->obj);
		}

		if (size != NULL)
		{
			*size = betree_object_size(bo->obj);
		}

		j_trace_file_end(bo->path, J_TRACE_FILE_STATUS, 0, 0);
	}

	return ret;
}

static gboolean
backend_sync(gpointer backend_data, gpointer backend_object)
{
	JBackendData* bd = backend_data;
	JBackendObject* bo = backend_object;
	gboolean ret;

	j_trace_file_begin(bo->path, J_TRACE_FILE_SYNC);
	err_t* err = NULL;
	ret = (betree_sync_db(bd->db, &err) == 0);
	if (err)
	{
		betree_print_error(err);
		betree_free_err(err);
		ret = false;
	}
	j_trace_file_end(bo->path, J_TRACE_FILE_SYNC, 0, 0);

	return ret;
}

static gboolean
backend_read(gpointer backend_data, gpointer backend_object, gpointer buffer, guint64 length, guint64 offset, guint64* bytes_read)
{
	JBackendObject* bo = backend_object;

	gsize nbytes_total = 0;

	(void)backend_data;

	j_trace_file_begin(bo->path, J_TRACE_FILE_READ);

	err_t* err = NULL;
	if (betree_object_read_at(bo->obj, buffer, length, offset, &nbytes_total, &err))
	{
		// FIXME: got err, handle it somehow
		betree_print_error(err);
		betree_free_err(err);
	}

	j_trace_file_end(bo->path, J_TRACE_FILE_READ, nbytes_total, offset);

	if (bytes_read != NULL)
	{
		*bytes_read = nbytes_total;
	}

	return (nbytes_total == length);
}

static gboolean
backend_write(gpointer backend_data, gpointer backend_object, gconstpointer buffer, guint64 length, guint64 offset, guint64* bytes_written)
{
	JBackendObject* bo = backend_object;

	gsize nbytes_total = 0;

	(void)backend_data;
	err_t* err = NULL;

	j_trace_file_begin(bo->path, J_TRACE_FILE_WRITE);
	betree_object_write_at(bo->obj, buffer, length, offset, &nbytes_total, &err);
	j_trace_file_end(bo->path, J_TRACE_FILE_WRITE, nbytes_total, offset);

	if (bytes_written != NULL)
	{
		*bytes_written = nbytes_total;
	}

	return (nbytes_total == length);
}

static gboolean
backend_init(gchar const* path, gpointer* backend_data)
{
	JBackendData* bd;

	betree_init_env_logger();

	err_t* err = NULL;
	// TODO: split by ; and pass multiple vdevs
	// const gchar** vdevs = g_strsplit(path, ";", 32);
	cfg_t* cfg = betree_parse_configuration(&path, 1, &err);
	if (err)
	{
		betree_print_error(err);
		betree_free_err(err);
		return FALSE;
	}

	db_t* db = betree_open_db(cfg, &err);
	if (cfg)
	{
		betree_free_cfg(cfg);
	}
	if (err)
	{
		betree_print_error(err);
		betree_free_err(err);
		return FALSE;
	}

	obj_store_t* os = betree_create_object_store(db, &err);
	if (err)
	{
		betree_print_error(err);
		betree_free_err(err);
		return FALSE;
	}

	bd = g_slice_new(JBackendData);
	bd->db = db;
	bd->os = os;

	jd_backend_file_cache = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

	g_atomic_int_inc(&jd_num_backends);

	*backend_data = bd;

	return TRUE;
}

static void
backend_fini(gpointer backend_data)
{
	JBackendData* bd = backend_data;

	if (g_atomic_int_dec_and_test(&jd_num_backends))
	{
		g_assert(g_hash_table_size(jd_backend_file_cache) == 0);
		g_hash_table_destroy(jd_backend_file_cache);
	}

	if (bd->db)
	{
		err_t* err = NULL;
		betree_sync_db(bd->db, &err);
		if (err)
		{
			betree_print_error(err);
			betree_free_err(err);
		}

		betree_close_db(bd->db);
	}
	g_slice_free(JBackendData, bd);
}

static JBackend betree_backend = {
	.type = J_BACKEND_TYPE_OBJECT,
	.component = J_BACKEND_COMPONENT_SERVER,
	.object = {
		.backend_init = backend_init,
		.backend_fini = backend_fini,
		.backend_create = backend_create,
		.backend_delete = backend_delete,
		.backend_open = backend_open,
		.backend_close = backend_close,
		.backend_status = backend_status,
		.backend_sync = backend_sync,
		.backend_read = backend_read,
		.backend_write = backend_write }
};

G_MODULE_EXPORT
JBackend*
backend_info(void)
{
	return &betree_backend;
}
