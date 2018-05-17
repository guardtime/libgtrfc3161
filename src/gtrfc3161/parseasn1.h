#ifndef PARSEASN1_H
#define PARSEASN1_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef size_t ASN1POSITION;

typedef struct asn1_object_st {
	bool structured;
	unsigned  obj_class;
	long  tag;
	size_t header_length;
	size_t body_length;
	size_t offset;
	unsigned level;
} asn1_object;

typedef struct asn1_dom_st {
	const unsigned char *data;
	size_t allocated;
	size_t used;
	asn1_object *objects;
} asn1_dom;

int asn1_dom_new(size_t initial_size, asn1_dom **out);
int asn1_dom_init(asn1_dom *dom, size_t initial_size);
void asn1_dom_free(asn1_dom *dom);
int asn1_dom_add_object(asn1_dom *dom, asn1_object *asn1);
void asn1_dom_dump(asn1_dom *dom);
int asn1_dom_find_child(const asn1_dom *dom, ASN1POSITION parent, unsigned tag);
int asn1_dom_get_child(const asn1_dom *dom, ASN1POSITION parent, ASN1POSITION index);
int asn1_dom_get_subobject(const asn1_dom *dom, const char *path, ASN1POSITION *out);
int asn1_dom_get_subobject_buf(const asn1_dom *dom, const char *path, int skip_header, const unsigned char **ptr, size_t *size);
int asn1_dom_get_root_buf(const asn1_dom *dom, ASN1POSITION pos, const unsigned char **ptr, size_t *size);
int asn1_dom_get_prefix_buf(const asn1_dom *dom, ASN1POSITION pos, const unsigned char **ptr, size_t *size);
int asn1_dom_get_suffix_buf(const asn1_dom *dom, ASN1POSITION pos, size_t total_size, const unsigned char **ptr, size_t *size);

int asn1_parse_object(asn1_dom *dom, const unsigned char *data, size_t length, unsigned level, unsigned offset);
int asn1_parse_header(const unsigned char *data, size_t length, asn1_object *asn1);

#ifdef __cplusplus
}
#endif

#endif /* PARSEASN1_H */
