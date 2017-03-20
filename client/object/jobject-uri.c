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

/**
 * \file
 **/

#include <julea-config.h>

#include <glib.h>

#include <object/jobject-uri.h>

#include <object/jobject.h>

#include <string.h>

/**
 * \defgroup JObjectURI Object URI
 *
 * @{
 **/

/**
 * An object URI.
 **/
struct JObjectURI
{
	JObjectURIScheme scheme;

	/**
	 * The index.
	 */
	guint32 index;

	/**
	 * The namespace.
	 **/
	gchar* namespace;

	/**
	 * The name.
	 **/
	gchar* name;

	/**
	 * The object.
	 **/
	JObject* object;
};

/**
 * Parses a given URI.
 *
 * \private
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * uri = g_slice_new(JObjectURI);
 *
 * j_object_uri_parse(uri, "julea://foo/bar");
 * \endcode
 *
 * \param uri  A URI.
 * \param uri_ A URI string.
 **/
static
gboolean
j_object_uri_parse (JObjectURI* uri, gchar const* uri_)
{
	gchar** parts = NULL;
	gchar const* illegal[2] = { "/", "/" };
	guint parts_len;
	guint scheme_parts = 0;
	guint i;

	if (!g_str_has_prefix(uri_, "object://"))
	{
		goto error;
	}

	switch (uri->scheme)
	{
		case J_OBJECT_URI_SCHEME_NAMESPACE:
			// object://index/namespace
			scheme_parts = 2;
			break;
		case J_OBJECT_URI_SCHEME_OBJECT:
			// object://index/namespace/object
			scheme_parts = 3;
			break;
		case J_OBJECT_URI_SCHEME_DISTRIBUTED_OBJECT:
			// object://namespace/object
			scheme_parts = 2;
			break;
		default:
			g_warn_if_reached();
			break;
	}

	parts = g_strsplit(uri_ + strlen("object://"), "/", scheme_parts);
	parts_len = g_strv_length(parts);

	if (parts_len != scheme_parts)
	{
		goto error;
	}

	for (i = 0; i < parts_len; i++)
	{
		if (g_strcmp0(parts[i], "") == 0)
		{
			goto error;
		}
	}

	switch (uri->scheme)
	{
		case J_OBJECT_URI_SCHEME_NAMESPACE:
		case J_OBJECT_URI_SCHEME_OBJECT:
			for (i = 0; i < 2; i++)
			{
				if (strpbrk(parts[i], illegal[i]) != NULL)
				{
					goto error;
				}
			}
			break;
		case J_OBJECT_URI_SCHEME_DISTRIBUTED_OBJECT:
			for (i = 1; i < 2; i++)
			{
				if (strpbrk(parts[i - 1], illegal[i]) != NULL)
				{
					goto error;
				}
			}
			break;
		default:
			g_warn_if_reached();
			break;
	}

	switch (uri->scheme)
	{
		case J_OBJECT_URI_SCHEME_NAMESPACE:
		case J_OBJECT_URI_SCHEME_OBJECT:
			// FIXME check for errors
			uri->index = g_ascii_strtoull(parts[0], NULL, 10);
			uri->namespace = g_strdup(parts[1]);

			if (parts_len >= 3)
			{
				uri->name = g_strdup(parts[2]);
				uri->object = j_object_new(uri->index, uri->namespace, uri->name);
			}
			break;
		case J_OBJECT_URI_SCHEME_DISTRIBUTED_OBJECT:
			uri->namespace = g_strdup(parts[0]);
			uri->name = g_strdup(parts[1]);

			// FIXME
			//uri->object = j_object_new(uri->index, uri->namespace, uri->name);
			break;
		default:
			g_warn_if_reached();
			break;
	}

	g_strfreev(parts);

	return TRUE;

error:
	g_strfreev(parts);

	return FALSE;
}

/**
 * Creates a new URI.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * uri = j_object_uri_new("julea://foo/bar");
 * \endcode
 *
 * \param uri_ A URI string.
 *
 * \return A new URI. Should be freed with j_object_uri_free().
 **/
JObjectURI*
j_object_uri_new (gchar const* uri_, JObjectURIScheme scheme)
{
	JObjectURI* uri;

	uri = g_slice_new(JObjectURI);

	uri->scheme = scheme;
	uri->index = 0;
	uri->namespace = NULL;
	uri->name = NULL;
	uri->object = NULL;

	if (!j_object_uri_parse(uri, uri_))
	{
		g_slice_free(JObjectURI, uri);

		return NULL;
	}

	return uri;
}

/**
 * Frees the memory allocated by a URI.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * ...
 *
 * j_object_uri_free(uri);
 * \endcode
 *
 * \param uri A URI.
 **/
void
j_object_uri_free (JObjectURI* uri)
{
	g_return_if_fail(uri != NULL);

	j_object_unref(uri->object);

	g_free(uri->namespace);
	g_free(uri->name);

	g_slice_free(JObjectURI, uri);
}

/**
 * Returns the index.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * ...
 *
 * g_print("%s\n", j_object_uri_get_collection_name(uri));
 * \endcode
 *
 * \param uri A URI.
 *
 * \return The index.
 **/
guint32
j_object_uri_get_index (JObjectURI* uri)
{
	g_return_val_if_fail(uri != NULL, 0);

	return uri->index;
}

/**
 * Returns the namespace.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * ...
 *
 * g_print("%s\n", j_object_uri_get_collection_name(uri));
 * \endcode
 *
 * \param uri A URI.
 *
 * \return The namespace.
 **/
gchar const*
j_object_uri_get_namespace (JObjectURI* uri)
{
	g_return_val_if_fail(uri != NULL, NULL);

	return uri->namespace;
}

/**
 * Returns the name.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * ...
 *
 * g_print("%s\n", j_object_uri_get_item_name(uri));
 * \endcode
 *
 * \param uri A URI.
 *
 * \return The name.
 **/
gchar const*
j_object_uri_get_name (JObjectURI* uri)
{
	g_return_val_if_fail(uri != NULL, NULL);

	return uri->name;
}

/**
 * Returns the object.
 *
 * \author Michael Kuhn
 *
 * \code
 * JObjectURI* uri;
 *
 * ...
 *
 * g_print("%s\n", j_object_uri_get_object(uri));
 * \endcode
 *
 * \param uri A URI.
 *
 * \return The object.
 **/
JObject*
j_object_uri_get_object (JObjectURI* uri)
{
	g_return_val_if_fail(uri != NULL, NULL);

	return uri->object;
}

/**
 * @}
 **/
