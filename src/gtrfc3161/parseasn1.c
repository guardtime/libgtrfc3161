#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "parseasn1.h"
#include "tsconvert.h"

typedef struct tag_name_st {
	unsigned char tag;
	char *name;
} tag_name;

static const tag_name tag_names[] = {
	{ 0x02, "INTEGER" },
	{ 0x03, "BIT STRING"},
	{ 0x04, "OCTET STRING" },
	{ 0x05, "NULL" },
	{ 0x06, "OBJECT IDENTIFIER" },
	{ 0x10, "SEQUENCE" },
	{ 0x11, "SET" },
	{ 0x13, "PrintableString" },
	{ 0x14, "T61String" },
	{ 0x16, "IA5String" },
	{ 0x17, "UTCTime" },
	{ 0x00, NULL }
};

const char *find_tag_name(unsigned char tag) {
	size_t i = 0;

	while (tag_names[i].name != NULL) {
		if (tag_names[i].tag == tag) {
			return tag_names[i].name;
		}
		i++;
	}

	return NULL;
}

int asn1_dom_new(size_t initial_size, asn1_dom **out) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *tmp = NULL;

	if (out == NULL || initial_size == 0) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	tmp = (asn1_dom*)KSI_calloc(sizeof(asn1_dom), 1);
	if (tmp == NULL) {
		res = LEGACY_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->objects=(asn1_object*)KSI_malloc(initial_size * sizeof(asn1_object));
	if (tmp->objects == NULL) {
		res = LEGACY_OUT_OF_MEMORY;
		goto cleanup;
	}

	tmp->data = NULL;
	tmp->allocated = initial_size;
	tmp->used = 0;

	*out = tmp;
	tmp = NULL;
	res = LEGACY_OK;

cleanup:

	asn1_dom_free(tmp);
	return res;
}

void asn1_dom_free(asn1_dom *dom) {
	if (dom != NULL) {
		KSI_free(dom->objects);
		KSI_free(dom);
	}
}

static void *asn1_dom_realloc(void *ptr, size_t old_size, size_t new_size) {
	void *tmp = NULL;

	if (ptr == NULL || old_size == 0 || new_size == 0) {
		return NULL;
	}

	tmp = KSI_malloc(new_size);
	if (tmp == NULL) {
		return NULL;
	} else {
		size_t n = old_size < new_size ? old_size : new_size;
		memcpy(tmp, ptr, n);
		KSI_free(ptr);
		return tmp;
	}
}

int asn1_dom_add_object(asn1_dom *dom, asn1_object *asn1) {
	int res = LEGACY_UNKNOWN_ERROR;

	if (dom == NULL || dom->objects == NULL || asn1 == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (dom->allocated == dom->used) {
		asn1_object *tmp = (asn1_object*)asn1_dom_realloc(dom->objects, dom->allocated * sizeof(asn1_object), 1.5 * dom->allocated * sizeof(asn1_object));
		if (!tmp) {
			res = LEGACY_OUT_OF_MEMORY;
			goto cleanup;
		}
		dom->objects = tmp;
		dom->allocated = 1.5 * dom->allocated;
	}
	dom->objects[dom->used] = (*asn1);
	dom->used++;

	res = LEGACY_OK;
cleanup:

	return res;
}

void asn1_dom_dump(asn1_dom *dom) {
	int lastlevel = 0;
	int i, j;

	if (dom == NULL || dom->objects == NULL) {
		return;
	}

	for (i = 0; i < dom->used; i++) {
		const asn1_object *asn1 = &dom->objects[i];

		while (asn1->level < lastlevel) {
			for (j = 0; j < lastlevel; j++) {
				printf("  ");
			}
			printf("}\n");
			lastlevel--;
		}

		for (j = 0; j < asn1->level; j++) {
			printf("  ");
		}

		const char *name = find_tag_name(asn1->tag);

		if (name) {
			printf("%s", name);
		} else {
			printf("[%ld]", asn1->tag);
		}

		if (asn1->structured) {
			printf(" { \n");
		} else {
			printf("\n");
			/* printf( detailed obeject ); */
		}

		lastlevel = asn1->level;
	}
}

int asn1_dom_find_child(const asn1_dom *dom, ASN1POSITION parent_index, unsigned tag) {
	unsigned i;
	asn1_object *parent = NULL;

	if (dom == NULL || dom->objects == NULL) {
		return -1;
	}
	if (parent_index >= dom->used - 1) {
		return -1;
	}

	parent=&dom->objects[parent_index];

	for (i = parent_index + 1; i < dom->used && dom->objects[i].level > parent->level; i++) {
		if (dom->objects[i].tag == tag) {
			return i;
		}
	}

	return -1;
}

int asn1_dom_get_child(const asn1_dom *dom, ASN1POSITION parent_index, ASN1POSITION index) {
	int child_found = 0;
	unsigned i;
	asn1_object *parent = NULL;

	if (dom == NULL || dom->objects == NULL) {
		return -1;
	}
	if (parent_index >= dom->used - 1) {
		return -1;
	}

	parent=&dom->objects[parent_index];

	for (i = parent_index + 1; i < dom->used; i++) {

		if (dom->objects[i].level == parent->level) {
			return -1;
		}

		if (dom->objects[i].level == parent->level + 1) {
			child_found++;
		}

		if (child_found - 1 == index) {
			return i;
		}
	}

	return -1;
}

int asn1_dom_get_subobject(const asn1_dom *dom, const char *path, ASN1POSITION *out) {
	int res = LEGACY_UNKNOWN_ERROR;
	const char *p = path;
	int nextpos;
	char *next = NULL;
	ASN1POSITION index = 0;

	if (dom == NULL || path == NULL || out == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	do {
		next = NULL;
		nextpos = strtol(p, &next, 10);

		if (p == next) {
			res = LEGACY_INVALID_FORMAT;
			goto cleanup;
		}

		if ((index = asn1_dom_get_child(dom, index, nextpos)) == -1) {
			res = LEGACY_INVALID_FORMAT;
			goto cleanup;
		}

		if (*next == '.') {
			p = next + 1;
		}
	} while (*next);

	*out = index;
	res = LEGACY_OK;

cleanup:

	return res;
}

int asn1_dom_get_subobject_buf(const asn1_dom *dom, const char *path, int skip_header, const unsigned char **ptr, size_t *size) {
	int res = LEGACY_UNKNOWN_ERROR;
	ASN1POSITION pos = 0;
	size_t delta = 0;

	if (dom == NULL || path == NULL || ptr == NULL || size == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	res = asn1_dom_get_subobject(dom, path, &pos);
	if (res != LEGACY_OK) goto cleanup;

	if (dom->data == NULL || dom->objects == NULL || pos >= dom->used) {
		res = LEGACY_INVALID_STATE;
		goto cleanup;
	}

	if (skip_header) {
		delta = dom->objects[pos].header_length;
	}
	*ptr = dom->data + dom->objects[pos].offset + delta;
	*size = dom->objects[pos].header_length + dom->objects[pos].body_length - delta;

	res = LEGACY_OK;

cleanup:

	return res;
}

int asn1_dom_get_root_buf(const asn1_dom *dom, ASN1POSITION pos, const unsigned char **ptr, size_t *size) {
	int res = LEGACY_UNKNOWN_ERROR;

	if (dom == NULL || ptr == NULL || size == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (dom->data == NULL || dom->objects == NULL || pos >= dom->used) {
		res = LEGACY_INVALID_STATE;
		goto cleanup;
	}

	*ptr = dom->data + dom->objects[pos].offset + dom->objects[pos].header_length;
	*size = dom->objects[pos].body_length;

	res = LEGACY_OK;

cleanup:

	return res;
}

int asn1_dom_get_prefix_buf(const asn1_dom *dom, ASN1POSITION pos, const unsigned char **ptr, size_t *size) {
	int res = LEGACY_UNKNOWN_ERROR;

	if (dom == NULL || ptr == NULL || size == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (dom->data == NULL || dom->objects == NULL || pos >= dom->used) {
		res = LEGACY_INVALID_STATE;
		goto cleanup;
	}

	*ptr = dom->data;
	*size = dom->objects[pos].offset + dom->objects[pos].header_length;

	res = LEGACY_OK;

cleanup:

	return res;
}

int asn1_dom_get_suffix_buf(const asn1_dom *dom, ASN1POSITION pos, size_t total_size, const unsigned char **ptr, size_t *size) {
	int res = LEGACY_UNKNOWN_ERROR;
	size_t prev_size;

	if (dom == NULL || ptr == NULL || size == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	if (dom->data == NULL || dom->objects == NULL || pos >= dom->used) {
		res = LEGACY_INVALID_STATE;
		goto cleanup;
	}

	prev_size = dom->objects[pos].offset + dom->objects[pos].header_length + dom->objects[pos].body_length;
	*ptr = dom->data + prev_size;
	*size = total_size - prev_size;

	res = LEGACY_OK;

cleanup:

	return res;
}

int asn1_parse_object(asn1_dom *dom, const unsigned char *data, size_t length, unsigned level, unsigned offset) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_object asn1 = {0};
	int pos = 0;

	if (dom == NULL || data == NULL || length < 2) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	while (pos < length) {
		memset(&asn1, 0, sizeof(asn1));
		res = asn1_parse_header(data + pos + offset, length - pos, &asn1);
		if (res != LEGACY_OK) goto cleanup;

		asn1.offset = pos + offset;
		asn1.level = level;

		res = asn1_dom_add_object(dom, &asn1);
		if (res != LEGACY_OK) goto cleanup;

		if (asn1.structured) {
			res = asn1_parse_object(dom, data, asn1.body_length, level + 1, pos + asn1.header_length + offset);
			if (res != LEGACY_OK) goto cleanup;
		}

		pos += (asn1.header_length + asn1.body_length);
	}

	if (pos != length) {
		res = LEGACY_ASN1_PARSING_ERROR;
		goto cleanup;
	}

	dom->data = data;
	res = LEGACY_OK;

cleanup:

	return res;
}


int asn1_parse_header(const unsigned char *data, size_t length, asn1_object *asn1){
	int res = LEGACY_ASN1_PARSING_ERROR;
	unsigned pos = 1;
	long tag = 0, l = 0;
	unsigned i;

	if (data == NULL || asn1 == NULL || length < 2) {
		res = LEGACY_INVALID_ARGUMENT;
		goto cleanup;
	}

	asn1->obj_class = (data[0] & 0xc0) >> 6;
	asn1->structured = ((data[0] & 0x20) == 0x20);

	tag = data[0] & 0x1f;

	/* Tag is longer than 5 bits. */
	if (tag == 0x1f) {
		tag = 0;

		/* While the first bit is set there are more tag bytes following. */
		do {
			if (pos == length) {
				goto cleanup;
			}

			/* Seven leftmost bits are used. */
			tag = tag * 128 + data[pos] - 0x80;
			pos++;
		} while (data[pos] >= 0x80);
	}

	asn1->tag = tag;

	if (data[pos] <= 0x80) {
		l = data[pos];
		pos++;
	} else {
		int bytes = data[pos] & 0x7f;
		pos++;
		l = 0;
		for (i = 0; i < bytes; i++) {
			l = l * 256 + data[pos];
			pos++;
		}
	}

	asn1->header_length = pos;

	/* The element is terminated by double zero. */
	if (l == 0x80) {
		l = 0;
		while (data[pos + l] != 0 || data[pos + l + 1] != 0) {
			l += 1;
			if (pos + l + 1 > length - 1) {
				goto cleanup;
			}
		}

		asn1->body_length = l + 2;
	} else {
		asn1->body_length = l;
	}

	if (asn1->header_length + asn1->body_length > length) {
		goto cleanup;
	}

	res = LEGACY_OK;

cleanup:

	return res;
}
