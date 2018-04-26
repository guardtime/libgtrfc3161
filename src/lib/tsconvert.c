#include <string.h>
#include <arpa/inet.h>

#include <ksi/ksi.h>
#include <ksi/types.h>
#include <ksi/crc32.h>
#include <ksi/hashchain.h>
#include <ksi/signature_builder.h>

#include "parseasn1.h"
#include "tsconvert.h"

typedef struct mem_buf_st {
	const unsigned char* ptr;
	size_t size;
} mem_buf;

void set_mem_buf(mem_buf *b, const unsigned char* ptr, size_t size) {
	if (b == NULL || ptr == NULL)
		return;

	b->ptr=ptr;
	b->size=size;
}

typedef struct rfc3161_fields_st{
	mem_buf input_hash;
	mem_buf tst_info_prefix;
	mem_buf tst_info_suffix;

	mem_buf tst_info_hash;
	mem_buf signed_attr_prefix;
	mem_buf signed_attr_suffix;

	mem_buf location_chain;
	mem_buf history_chain;

	uint64_t publication_time;
	mem_buf publication_hash;

	mem_buf signature;
	mem_buf certficate;
} rfc3161_fields;

int parse_values_from_der(const unsigned char* buffer, size_t size, rfc3161_fields* fields) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom=NULL;
	asn1_dom *tst_info=NULL;
	asn1_dom *signed_attr=NULL;
	asn1_dom *time_signature=NULL;
	ASN1POSITION pos, tst_info_pos, signed_attr_pos, time_signature_pos;

	if (buffer == NULL || fields == NULL || size < 2) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = asn1_dom_new(100, &dom);
	if (res != LEGACY_OK) goto done;
	res = asn1_dom_new(100, &tst_info);
	if (res != LEGACY_OK) goto done;
	res = asn1_dom_new(100, &signed_attr);
	if (res != LEGACY_OK) goto done;
	res = asn1_dom_new(100, &time_signature);
	if (res != LEGACY_OK) goto done;

	res = asn1_parse_object(dom, buffer, size, 0, 0);
	if (res != LEGACY_OK) goto done;

	//find encapsulated TSTInfo object
	res = asn1_dom_get_subobject(dom, "1.0.2.1.0", 0, &tst_info_pos);
	if (res != LEGACY_OK) goto done;

	//parse TSTInfo here
	res = asn1_parse_object(tst_info, asn1_dom_get_body_ptr(dom, tst_info_pos), asn1_dom_get_body_size(dom, tst_info_pos), 0, 0);
	if (res != LEGACY_OK) goto done;

	//find input hash inside TSTInfo
	res = asn1_dom_get_subobject(tst_info, "2.1", 0, &pos);
	if (res != LEGACY_OK) goto done;

	//an algorithm identifier has to be prepended to input hash in KSI format
	set_mem_buf(&fields->input_hash, asn1_dom_get_body_ptr(tst_info, pos), asn1_dom_get_body_size(tst_info, pos));

	set_mem_buf(&fields->tst_info_prefix, tst_info->data, tst_info->objects[pos].offset+2);

	set_mem_buf(&fields->tst_info_suffix,
				tst_info->data+tst_info->objects[pos].offset+asn1_dom_get_object_size(tst_info, pos),
				asn1_dom_get_body_size(dom, tst_info_pos)-tst_info->objects[pos].offset-asn1_dom_get_object_size(tst_info, pos));


	//find signed attributes object
	res = asn1_dom_get_subobject(dom, "1.0.4.0.3", 0, &signed_attr_pos);
	if (res != LEGACY_OK) goto done;

	//parse signed attributes here
	res = asn1_parse_object(signed_attr, asn1_dom_get_object_ptr(dom, signed_attr_pos), asn1_dom_get_object_size(dom, signed_attr_pos), 0, 0);
	if (res != LEGACY_OK) goto done;

	//find signed data inside signed attributes
	res = asn1_dom_get_subobject(signed_attr, "1.1.0", 0, &pos);
	if (res != LEGACY_OK) goto done;

	//NB!
	//Here the first byte is 0xa0 (class 2/structured/tag=0)
	//encodeToDER produces 0x31 (class 0/structured/tag=16 (sequence))
	//the 1st byte of fields->signed_attr_prefix has to be changed to 0x31

	set_mem_buf(&fields->signed_attr_prefix, signed_attr->data, signed_attr->objects[pos].offset+signed_attr->objects[pos].header_length);
	((unsigned char*)fields->signed_attr_prefix.ptr)[0]=0x31;

	set_mem_buf(&fields->tst_info_hash, asn1_dom_get_body_ptr(signed_attr, pos), asn1_dom_get_body_size(signed_attr, pos));

	//this should always result in 0 length data
	set_mem_buf(&fields->signed_attr_suffix,
				signed_attr->data+signed_attr->objects[pos].offset+asn1_dom_get_object_size(signed_attr, pos),
				asn1_dom_get_object_size(dom, signed_attr_pos)-
				signed_attr->objects[pos].offset-asn1_dom_get_object_size(signed_attr, pos));

	//find time_signature object
	res = asn1_dom_get_subobject(dom, "1.0.4.0.5", 0, &time_signature_pos);
	if (res != LEGACY_OK) goto done;

	//parse signed attributes here
	res = asn1_parse_object(time_signature, asn1_dom_get_body_ptr(dom, time_signature_pos), asn1_dom_get_body_size(dom, time_signature_pos), 0, 0);
	if (res != LEGACY_OK) goto done;

	//location chain inside GT timesignature
	res = asn1_dom_get_subobject(time_signature, "0", 0, &pos);
	if (res != LEGACY_OK) goto done;

	set_mem_buf(&fields->location_chain, asn1_dom_get_body_ptr(time_signature, pos), asn1_dom_get_body_size(time_signature, pos));

	//history chain inside GT timesignature
	res = asn1_dom_get_subobject(time_signature, "1", 0, &pos);
	if (res != LEGACY_OK) goto done;

	set_mem_buf(&fields->history_chain, asn1_dom_get_body_ptr(time_signature, pos), asn1_dom_get_body_size(time_signature, pos));

	//publication time inside GT timesignature
	res = asn1_dom_get_subobject(time_signature, "2.0", 0, &pos);
	if (res != LEGACY_OK) goto done;

	res = asn1_decode_integer(time_signature, pos, &fields->publication_time);
	if (res != LEGACY_OK) goto done;
	//set_mem_buf(&fields->published_data, asn1_dom_get_object_ptr(time_signature, pos), asn1_dom_get_object_size(time_signature, pos));

	//publication hash inside GT timesignature
	res = asn1_dom_get_subobject(time_signature, "2.1", 0, &pos);
	if (res != LEGACY_OK) goto done;

	set_mem_buf(&fields->publication_hash, asn1_dom_get_body_ptr(time_signature, pos), asn1_dom_get_body_size(time_signature, pos));

	//signature value inside GT timesignature
	res = asn1_dom_get_subobject(time_signature, "3.1", 0, &pos);
	if (res != LEGACY_OK) goto done;

	set_mem_buf(&fields->signature, asn1_dom_get_body_ptr(time_signature, pos), asn1_dom_get_body_size(time_signature, pos));

	//find certificate
	res = asn1_dom_get_subobject(dom, "1.0.3", 0, &pos);
	if (res != LEGACY_OK) goto done;

	set_mem_buf(&fields->certficate, asn1_dom_get_body_ptr(dom, pos), asn1_dom_get_body_size(dom, pos));

	res = LEGACY_OK;

done:

	asn1_dom_free(dom);
	asn1_dom_free(tst_info);
	asn1_dom_free(signed_attr);
	asn1_dom_free(time_signature);

	return res;
}


static inline unsigned get_hash_size(unsigned char id) {
	return id == 3 ? 28 : KSI_getHashLength(id);
}

bool check_link_item(const unsigned char* chain, size_t pos, size_t length)
{
	if (chain == NULL || length - pos < 3)
		return false;

	// Check linking info (LEFT_LINK=1, RIGHT_LINK=0, > 1 is invalid)
	if (chain[pos + 1] > 1)
		return false;

	// Verify imprint aslgorithm
	if (!KSI_isHashAlgorithmSupported(chain[pos + 2]) && chain[pos + 2] != 3)
		return false;

	// Verify step algorithm
	if (!KSI_isHashAlgorithmSupported(chain[pos]) && chain[pos] != 3)
		return false;

	// Check if next step is within the limist of the chain lenght
	if (pos + get_hash_size(chain[pos + 2]) + 4 > length)
		return false;

	return true;
}

int get_chain_item_size(const unsigned char* chain, size_t position) {
	if (chain == NULL)
		return 0;

	return (get_hash_size(chain[position + 2])) + 4;
}

bool is_metahash(const unsigned char *chain, size_t size)
{
	size_t i;

	//Hash code 3 with length 28 is a hardcoded for formerly used SHA2-224
	const size_t hash_len = 28;

	if (chain == NULL || size == 0)
		return false;

	if (chain[0] != 3) {
		/* Sibling not SHA-224. */
		return false;
	}
	if (chain[1] != 0) {
		/* First byte of sibling hash value not the tag value 0. */
		return false;
	}
	if ((size_t) chain[2] + 3 > hash_len) {
		/* Second byte of sibling hash value not a valid name length. */
		return false;
	}
	for (i = 3 + chain[2]; i < hash_len; ++i) {
		if (chain[i] != 0) {
			/* Name not properly padded. */
			return false;
		}
	}
	return true;
}

bool is_last_chain_item(const unsigned char* chain, size_t position, size_t chain_length)
{
	static const uint32_t LOCAL_LEVEL = 3;
	static const uint32_t STATE_LEVEL = 19;
	static const uint32_t NATIONAL_LEVEL = 39;
	static const uint32_t TOP_LEVEL = 60;
	uint32_t level_byte;

	if (chain == NULL || chain_length == 0)
		return false;

	// peek at posistion + 2 element level byte, if this is a known global depth value
	// then we are currently at an aggregator chain border
	if (!check_link_item(chain, position, chain_length))
		return false;

	// Look for global depth
	size_t next_pos = position + get_chain_item_size(chain, position);
	if (next_pos >= chain_length || !check_link_item(chain, next_pos, chain_length))
		return false;

	level_byte = chain[next_pos + get_hash_size(chain[next_pos + 2]) + 3];
	if ((level_byte == LOCAL_LEVEL) ||
		(level_byte == STATE_LEVEL) ||
		(level_byte == NATIONAL_LEVEL) ||
		(level_byte == TOP_LEVEL))
		return true;


	next_pos = next_pos + get_chain_item_size(chain, next_pos);
	if (next_pos >= chain_length || !check_link_item(chain, next_pos, chain_length))
		return false;

	level_byte = chain[next_pos + get_hash_size(chain[next_pos + 2]) + 3];
	if ((level_byte == LOCAL_LEVEL) ||
		(level_byte == STATE_LEVEL) ||
		(level_byte == NATIONAL_LEVEL) ||
		(level_byte == TOP_LEVEL))
	{
		// This is a known global level byte
		// Check if the next or -2 item is a metadata imprint
		// lets go one link deeper

		// if next is metadata imprint then this is the last item
		if (is_metahash(chain + position + 2, get_hash_size(chain[position+2]) + 1))
			return true;
	}

	return false;
}



#define SET_OCTET_STRING(target, parent, child, data, length)  \
	do { \
		KSI_OctetString *tmp_octet_string = NULL; \
		res = KSI_OctetString_new(ctx, data, length, &tmp_octet_string); if (res != KSI_OK) goto done; \
		res = KSI_##parent##_set##child(target, tmp_octet_string); if (res != KSI_OK) { KSI_OctetString_free(tmp_octet_string); goto done; } \
	} while(0)

#define SET_INTEGER(target, parent, child, value)  \
	do { \
		KSI_Integer *tmp_integer = NULL; \
		res = KSI_Integer_new(ctx, value, &tmp_integer); if (res != KSI_OK) goto done; \
		res = KSI_##parent##_set##child(target, tmp_integer); if (res != KSI_OK) { KSI_Integer_free(tmp_integer); goto done; } \
	} while (0)

int convert_rfc3161_fields(KSI_CTX *ctx, rfc3161_fields *fields, KSI_RFC3161 **out)
{
	int res = LEGACY_UNKNOWN_ERROR;
	KSI_DataHash *hash=NULL;
	KSI_RFC3161 *rfc3161 = NULL;

	if (ctx == NULL || fields == NULL || out == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = KSI_DataHash_fromDigest(ctx, 1, fields->input_hash.ptr, 32, &hash);
	if (res != KSI_OK) goto done;

	res = KSI_RFC3161_new(ctx, &rfc3161);
	if (res != KSI_OK) goto done;

	res = KSI_RFC3161_setInputHash(rfc3161, hash);
	if (res != KSI_OK) goto done;
	hash = NULL;

	SET_INTEGER(rfc3161, RFC3161, TstInfoAlgo, 1);
	SET_OCTET_STRING(rfc3161, RFC3161, TstInfoPrefix, fields->tst_info_prefix.ptr, fields->tst_info_prefix.size);
	SET_OCTET_STRING(rfc3161, RFC3161, TstInfoSuffix, fields->tst_info_suffix.ptr, fields->tst_info_suffix.size);

	SET_INTEGER(rfc3161, RFC3161, SigAttrAlgo, 1);
	SET_OCTET_STRING(rfc3161, RFC3161, SigAttrPrefix, fields->signed_attr_prefix.ptr, fields->signed_attr_prefix.size);
	SET_OCTET_STRING(rfc3161, RFC3161, SigAttrSuffix, fields->signed_attr_suffix.ptr, fields->signed_attr_suffix.size);

	*out = rfc3161;
	rfc3161 = NULL;
	res = LEGACY_OK;

done:

	KSI_DataHash_free(hash);
	KSI_RFC3161_free(rfc3161);
	return res;
}

int convert_calendar_auth_rec(KSI_CTX *ctx, rfc3161_fields *fields, KSI_CalendarAuthRec **out)
{
	int res = LEGACY_UNKNOWN_ERROR;
	static const char *oid= "1.2.840.113549.1.1.11";
	uint32_t cert_id;
	KSI_DataHash *hash=NULL;
	KSI_CalendarAuthRec *cal_auth_rec=NULL;
	KSI_PublicationData *publication_data=NULL;
	KSI_PKISignedData *pki_signature = NULL;
	KSI_Utf8String *utf8_string = NULL;

	if (ctx == NULL || fields == NULL || out == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = KSI_PublicationData_new(ctx, &publication_data);
	if (res != KSI_OK) goto done;

	//TODO: hardcoded hash size. nothing else than SHA256 has ever been used?
	res = KSI_DataHash_fromDigest(ctx, 1, fields->publication_hash.ptr+1, 32, &hash);
	if (res != KSI_OK) goto done;

	res = KSI_PublicationData_setImprint(publication_data, hash);
	if (res != KSI_OK) goto done;
	hash = NULL;

	SET_INTEGER(publication_data, PublicationData, Time, fields->publication_time);

	res = KSI_CalendarAuthRec_new(ctx, &cal_auth_rec);
	if (res != KSI_OK) goto done;

	res = KSI_CalendarAuthRec_setPublishedData(cal_auth_rec, publication_data);
	if (res != KSI_OK) goto done;
	publication_data = NULL;

	res = KSI_PKISignedData_new(ctx, &pki_signature);
	if (res != KSI_OK) goto done;

	cert_id=ntohl(KSI_crc32(fields->certficate.ptr, fields->certficate.size, 0));

	SET_OCTET_STRING(pki_signature, PKISignedData, CertId, (unsigned char*)&cert_id, 4);
	SET_OCTET_STRING(pki_signature, PKISignedData, SignatureValue, fields->signature.ptr, fields->signature.size);

	res = KSI_Utf8String_new(ctx, oid, strlen(oid)+1, &utf8_string);
	if (res != KSI_OK) goto done;

	res = KSI_PKISignedData_setSigType(pki_signature, utf8_string);
	if (res != KSI_OK) goto done;
	utf8_string = NULL;

	res = KSI_CalendarAuthRec_setSignatureData(cal_auth_rec, pki_signature);
	if (res != KSI_OK) goto done;
	pki_signature = NULL;

	*out = cal_auth_rec;
	cal_auth_rec = NULL;
	res = LEGACY_OK;

done:

	KSI_DataHash_free(hash);
	KSI_Utf8String_free(utf8_string);
	KSI_PKISignedData_free(pki_signature);
	KSI_PublicationData_free(publication_data);
	KSI_CalendarAuthRec_free(cal_auth_rec);
	return res;
}

int extract_aggr_chain(KSI_CTX *ctx, const unsigned char *chain, size_t chain_size,
						size_t *chain_pos, unsigned char* input_level_byte, KSI_AggregationHashChain **out) {
	int res = LEGACY_UNKNOWN_ERROR;
	KSI_HashChainLink *link=NULL;
	KSI_HashChainLinkList *links=NULL;
	KSI_DataHash *hash=NULL;
	KSI_OctetString *legacy_id=NULL;
	KSI_AggregationHashChain *ksi_chain = NULL;
	size_t current_pos;
	size_t chain_item_count = 0;
	unsigned char level_byte;
	bool is_left_link;
	size_t hash_size;
	int algo_id=-1;
	unsigned char link_algo_id=-1;

	if (ctx == NULL || out == NULL || chain == NULL || chain_size == 0 || chain_pos == NULL || input_level_byte == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	current_pos=*chain_pos;

	res = KSI_HashChainLinkList_new(&links);
	if (res != KSI_OK) goto done;

	while (current_pos < chain_size)
	{
		// some simple checks to verify that the legacy chain and it's intrerpretation is in valid state
		if (!check_link_item(chain, current_pos, chain_size))
		{
			// error is logged within the sanity check
			res = LEGACY_INVALID_FORMAT;
			goto done;
		}
		++chain_item_count;

		res = KSI_HashChainLink_new(ctx, &link);
		if (res != KSI_OK) goto done;

		link_algo_id=chain[current_pos + 2];
		hash_size = get_hash_size(chain[current_pos + 2]);
		is_left_link = chain[current_pos + 1];
		level_byte=chain[current_pos + 3 + hash_size];

		res = KSI_HashChainLink_setIsLeft(link, is_left_link);
		if (res != KSI_OK) goto done;

		if (*input_level_byte + 1 < level_byte)
		{
			SET_INTEGER(link, HashChainLink, LevelCorrection, level_byte - *input_level_byte - 1);
		}

		if(is_left_link && is_metahash(chain + current_pos + 2, hash_size + 1)) {
			res = KSI_OctetString_new(ctx, chain + current_pos + 2, hash_size + 1, &legacy_id);
			if (res != KSI_OK) goto done;
			res = KSI_HashChainLink_setLegacyId(link, legacy_id);
			if (res != KSI_OK) goto done;
			legacy_id = NULL;
		}
		else {
			res = KSI_DataHash_fromDigest(ctx, link_algo_id, chain + current_pos + 3, hash_size, &hash);
			if (res != KSI_OK) goto done;

			res = KSI_HashChainLink_setImprint(link, hash);
			if (res != KSI_OK) goto done;
			hash = NULL;
		}

		res = KSI_HashChainLinkList_append(links, link);
		if (res != KSI_OK) goto done;
		link = NULL;

		// if there is more than one item in the chain then it is possible to extract
		// the hash algorithm from the second chain item, otherwise algorithm will
		// need to be extracted from the first step of the next chain.
		if (chain_item_count == 2)
		{
			algo_id = chain[current_pos];
		}

		*input_level_byte = level_byte;

		// Increment to the next element in legacy chain
		current_pos += hash_size + 4;

		*chain_pos = current_pos;

		// Try to separate the legacy aggregator chains
		// Stop if the next after this one is a known global level
		if ((chain_item_count > 1) && (current_pos < chain_size))
		{
			if (is_last_chain_item(chain, current_pos, chain_size))
			{
				break;
			}
		}
	}

	//if algorithm was not extracted, we assume it is sha_256
	if (algo_id==-1)
		algo_id=1;

	res = KSI_AggregationHashChain_new(ctx, &ksi_chain);
	if (res != KSI_OK) goto done;

	SET_INTEGER(ksi_chain, AggregationHashChain, AggrHashId, algo_id);

	res = KSI_AggregationHashChain_setChain(ksi_chain, links);
	if (res != KSI_OK) goto done;

	*out = ksi_chain;
	ksi_chain = NULL;
	links = NULL;
	res = LEGACY_OK;

done:
	KSI_OctetString_free(legacy_id);
	KSI_DataHash_free(hash);
	KSI_HashChainLink_free(link);
	KSI_HashChainLinkList_free(links);
	KSI_AggregationHashChain_free(ksi_chain);
	return res;
}

int convert_aggregation_chains(KSI_CTX *ctx, const unsigned char *chain, size_t chain_size, KSI_AggregationHashChainList **out) {
	int res = LEGACY_UNKNOWN_ERROR;
	size_t chain_pos = 0;
	unsigned char level_byte = 0;
	KSI_AggregationHashChain *ksi_chain=NULL;
	KSI_AggregationHashChainList *aggr_chains = NULL;

	if (ctx == NULL || chain == NULL || out == NULL || chain_size == 0) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = KSI_AggregationHashChainList_new(&aggr_chains);
	if (res != KSI_OK) goto done;

	// Extraxt all legacy aggregator chains and convert to KSI
	while (chain_pos < chain_size)
	{
		// extract the chain
		res = extract_aggr_chain(ctx, chain, chain_size, &chain_pos, &level_byte, &ksi_chain);
		if (res != LEGACY_OK) goto done;

		res = KSI_AggregationHashChainList_append(aggr_chains, ksi_chain);
		if (res != KSI_OK) goto done;
		ksi_chain = NULL;
	}

	*out = aggr_chains;
	aggr_chains = NULL;
	res = LEGACY_OK;

done:
	KSI_AggregationHashChain_free(ksi_chain);
	KSI_AggregationHashChainList_free(aggr_chains);
	return res;
}

int convert_calendar_chain(KSI_CTX *ctx, const unsigned char *chain, size_t chain_size, KSI_CalendarHashChain **out) {
	int res = LEGACY_UNKNOWN_ERROR;
	size_t current_pos=0;
	unsigned char level_byte;
	unsigned char algo_id;
	unsigned hash_size;
	bool is_left_link;
	KSI_HashChainLinkList *links = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_DataHash *hash = NULL;
	KSI_CalendarHashChain *calendar_chain = NULL;

	if (ctx == NULL || chain == NULL || out == NULL || chain_size == 0) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = KSI_HashChainLinkList_new(&links);
	if (res != KSI_OK) goto done;

	while (current_pos < chain_size)
	{
		// some simple checks to verify that the response chain and it's intrerpretation is in valid state
		if (!check_link_item(chain, current_pos, chain_size)) {
			res = LEGACY_INVALID_FORMAT;
			goto done;
		}

		algo_id=chain[current_pos + 2];
		hash_size = get_hash_size(chain[current_pos + 2]);
		level_byte = chain[current_pos + 3 + hash_size];

		// In legacy calendar chain LevelByte is always 255 (0xFF)
		if (level_byte != 0xFF) {
			res = LEGACY_INVALID_FORMAT;
			goto done;
		}

		// Check that imprint and step algorithms match.
		// Skip the first algorithm, since in that case the step algorithm depends on imprint algorithm
		if (current_pos > 0 && chain[current_pos] != chain[current_pos + 2]) {
			res = LEGACY_INVALID_FORMAT;
			goto done;
		}

		is_left_link = chain[current_pos + 1];

		res = KSI_HashChainLink_new(ctx, &link);
		if (res != KSI_OK) goto done;

		res = KSI_HashChainLink_setIsLeft(link, is_left_link);
		if (res != KSI_OK) goto done;

		res = KSI_DataHash_fromDigest(ctx, algo_id, chain + current_pos + 3, hash_size, &hash);
		if (res != KSI_OK) goto done;

		res = KSI_HashChainLink_setImprint(link, hash);
		if (res != KSI_OK) goto done;
		hash = NULL;

		res = KSI_HashChainLinkList_append(links, link);
		if (res != KSI_OK) goto done;
		link = NULL;

		// Increment to the next element in legacy chain
		current_pos += hash_size + 4;

	}

	if (chain_size!=current_pos) {
		res = LEGACY_INVALID_FORMAT;
		goto done;
	}

	res = KSI_CalendarHashChain_new(ctx, &calendar_chain);
	if (res != KSI_OK) goto done;

	res = KSI_CalendarHashChain_setHashChain(calendar_chain, links);
	if (res != KSI_OK) goto done;

	*out = calendar_chain;
	calendar_chain = NULL;
	links = NULL;

	res = LEGACY_OK;

done:
	KSI_HashChainLinkList_free(links);
	KSI_HashChainLink_free(link);
	KSI_DataHash_free(hash);
	KSI_CalendarHashChain_free(calendar_chain);
	return res;
}

int calculate_aggr_chains(KSI_CTX *ctx, KSI_AggregationHashChainList* chains,
						   KSI_DataHash *input_hash, KSI_DataHash **output_hash) {
	int res = LEGACY_UNKNOWN_ERROR;
	int level_byte=0;
	size_t i, chains_count;
	KSI_DataHash *hash=NULL;
	KSI_DataHash *tmp=NULL;
	KSI_AggregationHashChain *aggr = NULL;
	KSI_HashChainLinkList *links = NULL;
	KSI_Integer *hashId = NULL;

	if (ctx == NULL || chains == NULL || input_hash == NULL || output_hash == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	chains_count=KSI_AggregationHashChainList_length(chains);

	hash = KSI_DataHash_ref(input_hash);

	for(i = 0; i < chains_count; i++)
	{
		res = KSI_AggregationHashChainList_elementAt(chains, i, &aggr);
		if (res != KSI_OK) goto done;

		res = KSI_AggregationHashChain_getChain(aggr, &links);
		if (res != KSI_OK) goto done;
		res = KSI_AggregationHashChain_getAggrHashId(aggr, &hashId);
		if (res != KSI_OK) goto done;

		if (tmp != NULL) {
			hash = tmp;
			tmp = NULL;
		}
		res = KSI_HashChain_aggregate(ctx, links, hash, level_byte, KSI_Integer_getUInt64(hashId), &level_byte, &tmp);
		if (res != KSI_OK) goto done;
		res = KSI_AggregationHashChain_setInputHash(aggr, hash);
		if (res != KSI_OK) goto done;
		hash = NULL;
	}

	*output_hash=tmp;
	tmp = NULL;
	res = LEGACY_OK;

done:
	KSI_DataHash_free(hash);
	KSI_DataHash_free(tmp);
	return res;
}

int copy_indices(KSI_CTX *ctx, KSI_AggregationHashChain *chain, KSI_IntegerList **out) {
	int res = LEGACY_UNKNOWN_ERROR;
	int indices_count;
	KSI_IntegerList *last_indices = NULL;
	KSI_IntegerList *indices = NULL;
	KSI_Integer  *tmp_integer = NULL, *tmp_index = NULL;
	size_t j;

	if (ctx == NULL || out == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = KSI_IntegerList_new(&indices);
	if (res != KSI_OK) goto done;

	if (chain != NULL) {
		res = KSI_AggregationHashChain_getChainIndex(chain, &last_indices);
		if (res != KSI_OK) goto done;

		indices_count=KSI_IntegerList_length(last_indices);

		for (j = 0; j < indices_count; j++)
		{
			res = KSI_IntegerList_elementAt(last_indices, j, &tmp_integer);
			if (res != KSI_OK) goto done;

			res = KSI_Integer_new(ctx, KSI_Integer_getUInt64(tmp_integer), &tmp_index);
			if (res != KSI_OK) goto done;

			res = KSI_IntegerList_append(indices, tmp_index);
			if (res != KSI_OK) goto done;
			tmp_index = NULL;
		}
	}

	*out = indices;
	indices = NULL;
	res = LEGACY_OK;

done:
	KSI_Integer_free(tmp_index);
	KSI_IntegerList_free(indices);
	return res;
}

int create_ksi_signature(KSI_CTX *ctx, KSI_SignatureBuilder *builder, rfc3161_fields *fields) {

	int res = LEGACY_UNKNOWN_ERROR;
	time_t aggregation_time;
	KSI_CalendarHashChain *calendar_chain = NULL;
	KSI_AggregationHashChain *aggr_chain = NULL, *last_chain=NULL;
	KSI_AggregationHashChainList *aggr_chains=NULL;
	KSI_Integer *tmp_index = NULL;
	size_t chains_count, links_count, i;
	KSI_IntegerList *indices = NULL;
	KSI_HashChainLinkList *links = NULL;
	KSI_HashChainLink *link = NULL;
	KSI_RFC3161 *rfc3161 = NULL;
	KSI_CalendarAuthRec *cal_auth_rec = NULL;
	KSI_DataHasher *hasher=NULL;
	KSI_DataHash *hash1 = NULL, *hash2 = NULL, *output_hash = NULL;
	const unsigned char *data = NULL;
	size_t data_size;
	uint64_t index;
	int is_left;
	size_t j;

	if (ctx == NULL || builder == NULL || fields == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	res = convert_rfc3161_fields(ctx, fields, &rfc3161);
	if (res != LEGACY_OK) goto done;

	res = KSI_SignatureBuilder_setRFC3161(builder, rfc3161);
	if (res != KSI_OK) goto done;

	res = convert_calendar_auth_rec(ctx, fields, &cal_auth_rec);
	if (res != LEGACY_OK) goto done;

	res = KSI_SignatureBuilder_setCalendarAuthRecord(builder, cal_auth_rec);
	if (res != KSI_OK) goto done;

	res = convert_calendar_chain(ctx, fields->history_chain.ptr, fields->history_chain.size, &calendar_chain);
	if (res != LEGACY_OK) goto done;

	SET_INTEGER(calendar_chain, CalendarHashChain, PublicationTime, fields->publication_time);

	res = KSI_CalendarHashChain_calculateAggregationTime(calendar_chain, &aggregation_time);
	if (res != KSI_OK) goto done;

	SET_INTEGER(rfc3161, RFC3161, AggregationTime, aggregation_time);
	SET_INTEGER(calendar_chain, CalendarHashChain, AggregationTime, aggregation_time);

	res = convert_aggregation_chains(ctx, fields->location_chain.ptr, fields->location_chain.size, &aggr_chains);
	if (res != LEGACY_OK) goto done;

	chains_count=KSI_AggregationHashChainList_length(aggr_chains);
	for(i=chains_count; i-- > 0;)
	{
		res = KSI_AggregationHashChainList_elementAt(aggr_chains, i, &aggr_chain);
		if (res != KSI_OK) goto done;

		res = KSI_SignatureBuilder_addAggregationChain(builder, aggr_chain);
		if (res != KSI_OK) goto done;
	}

	//Create aggregation chain indices
	for(i=chains_count; i-- > 0;)
	{
		res = KSI_AggregationHashChainList_elementAt(aggr_chains, i, &aggr_chain);
		if (res != KSI_OK) goto done;

		SET_INTEGER(aggr_chain, AggregationHashChain, AggregationTime, aggregation_time);

		//copy the upper chain indices into the lower one
		res = copy_indices(ctx, last_chain, &indices);
		if (res != LEGACY_OK) goto done;

		index = 1;

		res = KSI_AggregationHashChain_getChain(aggr_chain, &links);
		if (res != KSI_OK) goto done;

		links_count = KSI_HashChainLinkList_length(links);

		for (j = links_count; j-- > 0;)
		{
			res = KSI_HashChainLinkList_elementAt(links, j, &link);
			if (res != KSI_OK) goto done;

			index <<= 1;
			res = KSI_HashChainLink_getIsLeft(link, &is_left);
			if (res != KSI_OK) goto done;
			if (is_left)
				index |= 1;
		}

		res = KSI_Integer_new(ctx, index, &tmp_index);
		if (res != KSI_OK) goto done;

		res = KSI_IntegerList_append(indices, tmp_index);
		if (res != KSI_OK) goto done;
		tmp_index = NULL;

		res = KSI_AggregationHashChain_setChainIndex(aggr_chain, indices);
		if (res != KSI_OK) goto done;
		indices = NULL;

		last_chain = aggr_chain;
	}

	//Add indices to rfc3161 record
	res = copy_indices(ctx, last_chain, &indices);
	if (res != LEGACY_OK) goto done;

	res = KSI_RFC3161_setChainIndex(rfc3161, indices);
	if (res != KSI_OK) goto done;
	indices = NULL;

	//set input hashes and verify the hash chain
	res = KSI_DataHasher_open(ctx, 1, &hasher);
	if (res != KSI_OK) goto done;

	res = KSI_DataHasher_add(hasher, fields->signed_attr_prefix.ptr, fields->signed_attr_prefix.size);
	if (res != KSI_OK) goto done;
	res = KSI_DataHasher_add(hasher, fields->tst_info_hash.ptr, fields->tst_info_hash.size);
	if (res != KSI_OK) goto done;
	res = KSI_DataHasher_add(hasher, fields->signed_attr_suffix.ptr, fields->signed_attr_suffix.size);
	if (res != KSI_OK) goto done;

	res = KSI_DataHasher_close(hasher, &hash1);
	if (res != KSI_OK) goto done;

	res = KSI_DataHasher_reset(hasher);
	if (res != KSI_OK) goto done;

	res = KSI_DataHash_getImprint(hash1, &data, &data_size);
	if (res != KSI_OK) goto done;

	res = KSI_DataHasher_add(hasher, data, data_size);
	if (res != KSI_OK) goto done;

	res = KSI_DataHasher_close(hasher, &hash2);
	if (res != KSI_OK) goto done;

	res = calculate_aggr_chains(ctx, aggr_chains, hash2, &output_hash);
	if (res != LEGACY_OK) goto done;

	res = KSI_CalendarHashChain_setInputHash(calendar_chain, output_hash);
	if (res != KSI_OK) goto done;
	output_hash = NULL;
	//ksi->calendarChain->inputHash=output_hash;

	res = KSI_SignatureBuilder_setCalendarHashChain(builder, calendar_chain);
	if (res != KSI_OK) goto done;

	res = LEGACY_OK;

done:
	KSI_DataHash_free(hash1);
	KSI_DataHash_free(hash2);
	KSI_DataHash_free(output_hash);
	KSI_AggregationHashChainList_free(aggr_chains);
	KSI_RFC3161_free(rfc3161);
	KSI_CalendarAuthRec_free(cal_auth_rec);
	KSI_CalendarHashChain_free(calendar_chain);
	KSI_IntegerList_free(indices);
	KSI_Integer_free(tmp_index);
	KSI_DataHasher_free(hasher);

	return res;
}

int convert_signature(KSI_CTX *ctx, const unsigned char *rfc3161_signature, size_t rfc3161_size, KSI_Signature **ksi_signature) {
	int res = LEGACY_UNKNOWN_ERROR;
	rfc3161_fields fields;
	KSI_SignatureBuilder *builder = NULL;
	KSI_Signature *out = NULL;

	if (ctx == NULL || rfc3161_signature == NULL || rfc3161_size == 0 || ksi_signature == NULL) {
		res = LEGACY_INVALID_ARGUMENT;
		goto done;
	}

	memset(&fields, 0, sizeof(fields));

	res = parse_values_from_der(rfc3161_signature, rfc3161_size, &fields);
	if (res != LEGACY_OK) goto done;

	res = KSI_SignatureBuilder_open(ctx, &builder);
	if (res != KSI_OK) goto done;

	res = create_ksi_signature(ctx, builder, &fields);
	if (res != LEGACY_OK) goto done;

	res = KSI_SignatureBuilder_close(builder, 0, &out);
	if (res != KSI_OK) goto done;

	*ksi_signature = out;
	res = LEGACY_OK;

done:
	KSI_SignatureBuilder_free(builder);
	return res;
}

