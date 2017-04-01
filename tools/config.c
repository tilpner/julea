/*
 * JULEA - Flexible storage framework
 * Copyright (C) 2010-2017 Michael Kuhn
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
#include <glib-object.h>
#include <gio/gio.h>

#include <string.h>

static gboolean opt_local = FALSE;
static gboolean opt_global = FALSE;
static gboolean opt_print = FALSE;
static gchar const* opt_servers_data = NULL;
static gchar const* opt_servers_meta = NULL;
static gchar const* opt_data_backend = NULL;
static gchar const* opt_data_path = NULL;
static gchar const* opt_meta_backend = NULL;
static gchar const* opt_meta_path = NULL;
static gint opt_max_connections = 0;

static
gchar**
string_split (gchar const* string)
{
	guint i;
	guint len;
	gchar** arr;

	arr = g_strsplit(string, ",", 0);
	len = g_strv_length(arr);

	for (i = 0; i < len; i++)
	{
		g_strstrip(arr[i]);
	}

	return arr;
}

static
gboolean
read_config (gchar* path)
{
	gboolean ret = TRUE;
	GFile* file;
	gchar* buf;

	if (path == NULL)
	{
		ret = FALSE;
		goto end;
	}

	file = g_file_new_for_commandline_arg(path);
	ret = g_file_load_contents(file, NULL, &buf, NULL, NULL, NULL);

	if (ret)
	{
		g_print("%s", buf);
		g_free(buf);
	}

	g_object_unref(file);

end:
	return ret;
}

static
gboolean
write_config (gchar* path)
{
	GKeyFile* key_file;
	gboolean ret = TRUE;
	gsize key_file_data_len;
	gchar* key_file_data;
	g_auto(GStrv) servers_data = NULL;
	g_auto(GStrv) servers_meta = NULL;

	servers_data = string_split(opt_servers_data);
	servers_meta = string_split(opt_servers_meta);

	key_file = g_key_file_new();
	g_key_file_set_integer(key_file, "clients", "max-connections", opt_max_connections);
	g_key_file_set_string_list(key_file, "servers", "data", (gchar const* const*)servers_data, g_strv_length(servers_data));
	g_key_file_set_string_list(key_file, "servers", "metadata", (gchar const* const*)servers_meta, g_strv_length(servers_meta));
	g_key_file_set_string(key_file, "data", "backend", opt_data_backend);
	g_key_file_set_string(key_file, "data", "path", opt_data_path);
	g_key_file_set_string(key_file, "metadata", "backend", opt_meta_backend);
	g_key_file_set_string(key_file, "metadata", "path", opt_meta_path);
	key_file_data = g_key_file_to_data(key_file, &key_file_data_len, NULL);

	if (path != NULL)
	{
		GFile* file;
		GFile* parent;

		file = g_file_new_for_commandline_arg(path);
		parent = g_file_get_parent(file);
		g_file_make_directory_with_parents(parent, NULL, NULL);
		ret = g_file_replace_contents(file, key_file_data, key_file_data_len, NULL, FALSE, G_FILE_CREATE_NONE, NULL, NULL, NULL);

		g_object_unref(file);
		g_object_unref(parent);
	}
	else
	{
		g_print("%s", key_file_data);
	}

	g_free(key_file_data);
	g_key_file_free(key_file);

	return ret;
}

gint
main (gint argc, gchar** argv)
{
	GError* error = NULL;
	GOptionContext* context;
	gboolean ret;
	gchar* path;

	GOptionEntry entries[] = {
		{ "local", 0, 0, G_OPTION_ARG_NONE, &opt_local, "Write local configuration", NULL },
		{ "global", 0, 0, G_OPTION_ARG_NONE, &opt_global, "Write global configuration", NULL },
		{ "print", 0, 0, G_OPTION_ARG_NONE, &opt_print, "Print configuration", NULL },
		{ "data-servers", 0, 0, G_OPTION_ARG_STRING, &opt_servers_data, "Data servers to use", "host1,host2" },
		{ "metadata-servers", 0, 0, G_OPTION_ARG_STRING, &opt_servers_meta, "Metadata servers to use", "host1,host2" },
		{ "data-backend", 0, 0, G_OPTION_ARG_STRING, &opt_data_backend, "Data backend to use", "posix|null|gio|…" },
		{ "data-path", 0, 0, G_OPTION_ARG_STRING, &opt_data_path, "Data path to use", "/path/to/storage" },
		{ "metadata-backend", 0, 0, G_OPTION_ARG_STRING, &opt_meta_backend, "Metadata backend to use", "posix|null|gio|…" },
		{ "metadata-path", 0, 0, G_OPTION_ARG_STRING, &opt_meta_path, "Metadata path to use", "/path/to/storage" },
		{ "max-connections", 0, 0, G_OPTION_ARG_INT, &opt_max_connections, "Maximum number of connections", "0" },
		{ NULL, 0, 0, 0, NULL, NULL, NULL }
	};

	context = g_option_context_new(NULL);
	g_option_context_add_main_entries(context, entries, NULL);

	if (!g_option_context_parse(context, &argc, &argv, &error))
	{
		g_option_context_free(context);

		if (error)
		{
			g_printerr("%s\n", error->message);
			g_error_free(error);
		}

		return 1;
	}

	if ((opt_local && opt_global)
	    || (opt_print && (opt_servers_data != NULL || opt_servers_meta != NULL || opt_data_backend != NULL || opt_data_path != NULL || opt_meta_backend != NULL || opt_meta_path != NULL))
	    || (opt_print && !opt_local && !opt_global)
	    || (!opt_print && (opt_servers_data == NULL || opt_servers_meta == NULL || opt_data_backend == NULL || opt_data_path == NULL || opt_meta_backend == NULL || opt_meta_path == NULL))
	    || opt_max_connections < 0
	)
	{
		gchar* help;

		help = g_option_context_get_help(context, TRUE, NULL);
		g_option_context_free(context);

		g_print("%s", help);
		g_free(help);

		return 1;
	}

	g_option_context_free(context);

	if (opt_local)
	{
		path = g_build_filename(g_get_user_config_dir(), "julea", "julea", NULL);
	}
	else if (opt_global)
	{
		path = g_build_filename(g_get_system_config_dirs()[0], "julea", "julea", NULL);
	}
	else
	{
		path = NULL;
	}

	if (opt_print)
	{
		ret = read_config(path);
	}
	else
	{
		ret = write_config(path);
	}

	g_free(path);

	return (ret) ? 0 : 1;
}
