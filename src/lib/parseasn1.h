#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

asn1_dom* asn1_dom_new(size_t initial_size);
bool asn1_dom_init(asn1_dom* dom, size_t initial_size);
void asn1_dom_free(asn1_dom* dom);
bool asn1_dom_add_object(asn1_dom* dom, asn1_object* asn1);
void asn1_dom_dump(asn1_dom* dom);
int asn1_dom_find_child(const asn1_dom* dom, ASN1POSITION parent, unsigned tag);
int asn1_dom_get_child(const asn1_dom* dom, ASN1POSITION parent, ASN1POSITION index);
int asn1_dom_get_subobject(const asn1_dom* dom, const char* path, ASN1POSITION index);
const unsigned char* asn1_dom_get_object_ptr(const asn1_dom* dom, ASN1POSITION index);
int asn1_dom_get_object_size(const asn1_dom* dom, ASN1POSITION index);
const unsigned char* asn1_dom_get_body_ptr(const asn1_dom* dom, ASN1POSITION index);
int asn1_dom_get_body_size(const asn1_dom* dom, ASN1POSITION index);

bool asn1_parse_object(asn1_dom* dom, const unsigned char* data, size_t length, unsigned level, unsigned offset);
bool asn1_parse_header(const unsigned char* data, size_t length, asn1_object *asn1);

uint64_t asn1_decode_integer(asn1_dom* dom, ASN1POSITION index);
