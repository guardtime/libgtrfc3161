#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "parseasn1.h"

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

const char* find_tag_name(unsigned char tag) {

	size_t i=0;
	while(tag_names[i].name!=NULL)
	{
		if(tag_names[i].tag==tag)
			return tag_names[i].name;
		i++;
	}

	return NULL;
}

asn1_dom* asn1_dom_new(size_t initial_size) {
	asn1_dom* dom=(asn1_dom*)calloc(sizeof(asn1_dom), 1);
	if(!dom)
		return NULL;

	if(!asn1_dom_init(dom, initial_size))
	{
		asn1_dom_free(dom);
		return NULL;
	}

	return dom;
}

bool asn1_dom_init(asn1_dom* dom, size_t initial_size) {
	dom->objects=(asn1_object*)malloc(initial_size*sizeof(asn1_object));

	if(!dom->objects)
		return false;

	dom->data=NULL;
	dom->allocated=initial_size;
	dom->used=0;
	return true;
}

void asn1_dom_free(asn1_dom* dom) {
	if(!dom)
		return;

	if(dom->objects)
		free(dom->objects);

	free(dom);
}

bool asn1_dom_add_object(asn1_dom* dom, asn1_object* asn1) {
	if(!dom->objects)

		return false;
	if(dom->allocated==dom->used) {
		asn1_object* tmp=(asn1_object*)realloc(dom->objects, 1.5*dom->allocated*sizeof(asn1_object));
		if(!tmp)
			return false;
		dom->objects=tmp;
	}
	dom->objects[dom->used]=(*asn1);
	dom->used++;

	return true;
}

void asn1_dom_dump(asn1_dom* dom) {

	int lastlevel=0;
	int i, j;

	for(i=0; i<dom->used; i++) {
		const asn1_object* asn1=&dom->objects[i];

		while(asn1->level<lastlevel) {
			for(j=0; j<lastlevel; j++)
				printf("  ");
			printf("}\n");
			lastlevel--;
		}

		for(j=0; j<asn1->level; j++)
			printf("  ");

		const char* name=find_tag_name(asn1->tag);

		if(name)
			printf("%s", name);
		else
			printf("[%ld]", asn1->tag);

		if(asn1->structured)
			printf(" { \n");
		else {
			printf("\n");
			//printf( detailed obeject );
		}

		lastlevel=asn1->level;
	}
}

int asn1_dom_find_child(const asn1_dom* dom, ASN1POSITION parent_index, unsigned tag) {

	unsigned i;

	if(parent_index>=dom->used-1)
		return -1;

	asn1_object *parent=&dom->objects[parent_index];

	for(i=parent_index+1; i<dom->used && dom->objects[i].level > parent->level; i++)
		if(dom->objects[i].tag==tag)
			return i;

	return -1;
}

int asn1_dom_get_child(const asn1_dom* dom, ASN1POSITION parent_index, ASN1POSITION index) {

	int child_found=0;
	unsigned i;

	if(parent_index>=dom->used-1)
		return -1;

	asn1_object *parent=&dom->objects[parent_index];

	for(i=parent_index+1; i<dom->used; i++) {

		if(dom->objects[i].level == parent->level)
			return -1;

		if(dom->objects[i].level == parent->level+1)
			child_found++;

		if(child_found-1 == index)
			return i;
	}

	return -1;
}

int asn1_dom_get_subobject(const asn1_dom* dom, const char* path, ASN1POSITION index) {

	bool go=true;
	const char *p=path;
	int nextpos;

	while(go) {
		char *next=NULL;
		nextpos=strtol(p, &next, 10);

		if(p==next)
			return -1;

		if((index=asn1_dom_get_child(dom, index, nextpos))==-1)
			return -1;

		if(*next==0)
			return index;
		else if(*next=='.')
			p=next+1;
	}
	return -1;
}

const unsigned char* asn1_dom_get_object_ptr(const asn1_dom* dom, ASN1POSITION index) {
	if(index>=dom->used)
		return NULL;
	return dom->data+dom->objects[index].offset;
}

int asn1_dom_get_object_size(const asn1_dom* dom, ASN1POSITION index) {
	if(index>=dom->used)
		return -1;
	return dom->objects[index].body_length+dom->objects[index].header_length;
}

const unsigned char* asn1_dom_get_body_ptr(const asn1_dom* dom, ASN1POSITION index) {
	if(index>=dom->used)
		return NULL;
	return dom->data+dom->objects[index].offset+dom->objects[index].header_length;
}

int asn1_dom_get_body_size(const asn1_dom* dom, ASN1POSITION index) {
	if(index>=dom->used)
		return -1;
	return dom->objects[index].body_length;
}

bool asn1_parse_object(asn1_dom* dom, const unsigned char* data, size_t length,
					   unsigned level, unsigned offset) {

	asn1_object asn1={0};
	int pos=0;

	while(pos<length) {

		memset(&asn1, 0, sizeof(asn1));
		if(!asn1_parse_header(data+pos+offset, length-pos, &asn1))
			return false;

		asn1.offset=pos+offset;
		asn1.level=level;

		if(!asn1_dom_add_object(dom, &asn1))
			return false;

		if(asn1.structured)
			if(!asn1_parse_object(dom, data, asn1.body_length, level+1, pos+asn1.header_length+offset))
				return false;

		pos+=(asn1.header_length+asn1.body_length);
	}

	if(pos!=length)
		return false;

	dom->data=data;

	return true;
}


bool asn1_parse_header(const unsigned char* data, size_t length, asn1_object *asn1) {

	unsigned pos = 1;
	long tag = 0, l=0;
	unsigned i;

	asn1->obj_class = (data[0] & 0xc0) >> 6;
	asn1->structured = ((data[0] & 0x20) == 0x20);

	tag = data[0] & 0x1f;

	//tag is longer than 5 bits
	if (tag == 0x1f) {
		tag = 0;

		//while the first bit is set there are more tag bytes following
		do {
			if (pos == length)
				return false;

			//seven leftmost bits are used
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
		for (i=0; i<bytes; i++) {
			l = l * 256 + data[pos];
			pos++;
		}
	}

	asn1->header_length = pos;

	//The element is terminated by double zero
	if (l == 0x80) {
		l = 0;
		while (data[pos + l] != 0 || data[pos + l + 1] != 0) {
			l += 1;
			if(pos + l + 1 > length -1)
				return false;
		}

		asn1->body_length = l + 2;
	} else {
		asn1->body_length = l;
	}

	if(asn1->header_length + asn1->body_length > length)
		return false;

	return true;
}

uint64_t decode_integer(const unsigned char* data, size_t length)
{
	uint64_t result=0;
	size_t i;

	if (length > 8)
		return false;

	for (i=0; i < length; i++)
	{
		result = (result << 8);
		result += data[i];
	}

	return result;
}

uint64_t asn1_decode_integer(asn1_dom* dom, ASN1POSITION index) {
	return decode_integer(asn1_dom_get_body_ptr(dom, index), asn1_dom_get_body_size(dom, index));
}
