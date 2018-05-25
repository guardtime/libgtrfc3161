/*
 * Copyright 2013-2016 Guardtime, Inc.
 *
 * This file is part of the Guardtime client SDK.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES, CONDITIONS, OR OTHER LICENSES OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

#include "cutest/CuTest.h"
#include <stdio.h>
#include <string.h>
#include "test_unit_all.h"
#include "../src/gtrfc3161/parseasn1.h"
#include "../src/gtrfc3161/tsconvert.h"


static void Test_Asn1_Dom_new(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom = NULL;

	res = asn1_dom_new(0, &dom);
	CuAssert(tc, "Must not create empty ASN dom.", res == LEGACY_INVALID_ARGUMENT && dom == NULL);

	res = asn1_dom_new(100, &dom);
	CuAssert(tc, "Unable to create ASN dom.", res == LEGACY_OK && dom != NULL);
	CuAssert(tc, "ASN dom not properly initialized.", dom->objects != NULL  && dom->data == NULL && dom->allocated == 100 && dom->used == 0);

	asn1_dom_free(dom);
}

static void Test_Asn1_Dom_resize(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom = NULL;
	asn1_object obj;
	size_t expected_size;
	int i;

	res = asn1_dom_new(1, &dom);
	CuAssert(tc, "Unable to create ASN dom.", res == LEGACY_OK && dom != NULL);
	CuAssert(tc, "ASN dom not properly initialized.", dom->objects != NULL  && dom->data == NULL && dom->allocated == 1 && dom->used == 0);
	expected_size = 1;

	for (i = 1; i <= 5; i++) {
		res = asn1_dom_add_object(dom, &obj);
		CuAssert(tc, "Unable to add ASN object.", res == LEGACY_OK);
		if (i > expected_size) {
			expected_size = expected_size * 2;
		}
		CuAssert(tc, "ASN dom not properly updated.", dom->allocated == expected_size && dom->used == i);
	}
	asn1_dom_free(dom);
}

static void Test_Asn1_Dom_add_object(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom = NULL;
	asn1_object obj[] = {
		{false,	0x00,	0x02,	2,	4,	0,	0},
		{true,	0x01,	0x04,	2,	6,	6,	1},
		{false,	0x02,	0x06,	2,	20,	14,	2},
		{true,	0x03,	0x10,	4,	12,	36,	3},
		{false,	0x00,	0x11,	4,	8,	52,	4}
	};
	int i;
	size_t len = sizeof(obj) / sizeof(asn1_object);

	res = asn1_dom_new(1, &dom);
	CuAssert(tc, "Unable to create ASN dom.", res == LEGACY_OK);

	res = asn1_dom_add_object(NULL, &obj[0]);
	CuAssert(tc, "Must not add to NULL ASN dom.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_add_object(dom, NULL);
	CuAssert(tc, "Must not add NULL ASN object.", res == LEGACY_INVALID_ARGUMENT);

	for (i = 0; i < len; i++) {
		res = asn1_dom_add_object(dom, &obj[i]);
		CuAssert(tc, "Unable to add ASN object.", res == LEGACY_OK);
	}
	for (i = 0; i < len; i++) {
		CuAssert(tc, "ASN objects not properly added.", !memcmp(&obj[i], &dom->objects[i], sizeof(asn1_object)));
	}
	asn1_dom_free(dom);
}

static void Test_Asn1_Dom_get_child(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom = NULL;
	asn1_object obj[] = {
		{false,	0x00,	0x02,	2,	4,	0,	0},
		{true,	0x01,	0x03,	2,	4,	6,	0},
		{false,	0x02,	0x04,	2,	6,	12,	1},
		{true,	0x03,	0x05,	4,	6,	20,	1},
		{false,	0x00,	0x06,	4,	4,	30,	2},
		{true,	0x01,	0x10,	4,	4,	38,	2},
		{false,	0x02,	0x11,	2,	8,	46,	3},
		{true,	0x03,	0x13,	2,	8,	56,	4},
		{false,	0x00,	0x14,	2,	4,	66,	1},
		{true,	0x01,	0x16,	4,	4,	74,	1},
		{false,	0x02,	0x17,	4,	10,	82,	2}
	};
	int i;
	size_t len = sizeof(obj) / sizeof(asn1_object);
	size_t child;

	res = asn1_dom_get_child(NULL, 0, 0, &child);
	CuAssert(tc, "NULL ASN dom should not have any objects or children.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_new(1, &dom);
	CuAssert(tc, "Unable to create ASN dom.", res == LEGACY_OK);

	res = asn1_dom_get_child(dom, 0, 0, &child);
	CuAssert(tc, "Empty ASN dom should not have any objects or children.", res == LEGACY_INVALID_ARGUMENT);

	for (i = 0; i < len; i++) {
		res = asn1_dom_add_object(dom, &obj[i]);
		CuAssert(tc, "Unable to add ASN object.", res == LEGACY_OK);
	}

	res = asn1_dom_get_child(dom, 0, 0, &child);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 1, 0, NULL);
	CuAssert(tc, "Should not be able to get ASN object to NULL child.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_get_child(dom, 1, 0, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 2);

	res = asn1_dom_get_child(dom, 1, 1, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 3);

	res = asn1_dom_get_child(dom, 1, 2, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 8);

	res = asn1_dom_get_child(dom, 1, 3, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 9);

	res = asn1_dom_get_child(dom, 1, 4, &child);
	CuAssert(tc, "ASN object should not have that many children.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 2, 0, &child);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 3, 0, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 4);

	res = asn1_dom_get_child(dom, 3, 1, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 5);

	res = asn1_dom_get_child(dom, 3, 2, &child);
	CuAssert(tc, "ASN object should not have that many children.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 5, 0, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 6);

	res = asn1_dom_get_child(dom, 5, 1, &child);
	CuAssert(tc, "ASN object should not have that many children.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 6, 0, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 7);

	res = asn1_dom_get_child(dom, 6, 1, &child);
	CuAssert(tc, "ASN object should not have that many children.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 9, 0, &child);
	CuAssert(tc, "Unable to get ASN object child.", res == LEGACY_OK && child == 10);

	res = asn1_dom_get_child(dom, 10, 0, &child);
	CuAssert(tc, "The last ASN object can't have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 11, 0, &child);
	CuAssert(tc, "Nonexistent ASN object can't have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, -1, 0, &child);
	CuAssert(tc, "Nonexistent ASN object can't have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_child(dom, 1, -1, &child);
	CuAssert(tc, "ASN object children can't be counted backwards.", res == LEGACY_INVALID_FORMAT);

	asn1_dom_free(dom);
}

static void Test_Asn1_Dom_get_subobject(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_dom *dom = NULL;
	asn1_object obj[] = {
		{false,	0x00,	0x02,	2,	4,	0,	0},
		{true,	0x01,	0x03,	2,	4,	6,	1},
		{false,	0x02,	0x04,	2,	6,	12,	2},
		{true,	0x03,	0x05,	4,	6,	20,	3},
		{false,	0x00,	0x06,	4,	4,	30,	2},
		{true,	0x01,	0x10,	4,	4,	38,	3},
		{false,	0x02,	0x11,	2,	8,	46,	3},
		{true,	0x03,	0x13,	2,	8,	56,	4},
		{false,	0x00,	0x14,	2,	4,	66,	1},
		{true,	0x01,	0x16,	4,	4,	74,	1},
		{false,	0x02,	0x17,	4,	10,	82,	2}
	};
	int i;
	size_t len = sizeof(obj) / sizeof(asn1_object);
	size_t index;

	res = asn1_dom_new(1, &dom);
	CuAssert(tc, "Unable to create ASN dom.", res == LEGACY_OK);

	res = asn1_dom_get_subobject(dom, "0", &index);
	CuAssert(tc, "Empty ASN dom should not have any objects or children.", res == LEGACY_INVALID_ARGUMENT);

	for (i = 0; i < len; i++) {
		res = asn1_dom_add_object(dom, &obj[i]);
		CuAssert(tc, "Unable to add ASN object.", res == LEGACY_OK);
	}

	res = asn1_dom_get_subobject(NULL, "0", &index);
	CuAssert(tc, "NULL ASN dom should not have any objects or children.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_get_subobject(dom, NULL, &index);
	CuAssert(tc, "Should not be able to get ASN subobject by NULL path.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_get_subobject(NULL, "0", NULL);
	CuAssert(tc, "Should not be able to get ASN subobject to NULL index.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_dom_get_subobject(dom, "", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by empty path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "ab0", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by non-numeric path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0ab", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by non-numeric path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "-1", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by negative path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0.1.", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by incorrectly formatted path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, ".0.1", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by incorrectly formatted path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0..1", &index);
	CuAssert(tc, "Should not be able to get ASN subobject by incorrectly formatted path.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 1);

	res = asn1_dom_get_subobject(dom, "1", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 8);

	res = asn1_dom_get_subobject(dom, "2", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 9);

	res = asn1_dom_get_subobject(dom, "3", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0.0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 2);

	res = asn1_dom_get_subobject(dom, "0.1", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 4);

	res = asn1_dom_get_subobject(dom, "0.2", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "1.0", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "2.0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 10);

	res = asn1_dom_get_subobject(dom, "2.1", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0.0.0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 3);

	res = asn1_dom_get_subobject(dom, "0.1.0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 5);

	res = asn1_dom_get_subobject(dom, "0.1.1", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 6);

	res = asn1_dom_get_subobject(dom, "0.1.1.0", &index);
	CuAssert(tc, "Unable to get ASN subobject.", res == LEGACY_OK && index == 7);

	res = asn1_dom_get_subobject(dom, "0.1.1.1", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	res = asn1_dom_get_subobject(dom, "0.1.1.0.0", &index);
	CuAssert(tc, "ASN object should not have a child.", res == LEGACY_INVALID_FORMAT);

	asn1_dom_free(dom);
}

static void Test_Asn1_Dom_parse_header_correct_encoding(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_object obj;
	const unsigned char data[][20] = {
		{0x01, 0x01, 0xff},
		{0x02, 0x02, 0x00, 0x80},
		{0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0},
		{0x04, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x05, 0x00},
		{0x06, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d},
		{0x13, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x14, 0x0d, 0x48, 0xc2, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x16, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x17, 0x0d, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a},
		{0x30, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0x31, 0x08, 0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0, 0x05, 0x00},
		{0x42, 0x02, 0x00, 0x80},
		{0x82, 0x02, 0x00, 0x80},
		{0xc2, 0x02, 0x00, 0x80},
		{0x62, 0x02, 0x00, 0x80},
		{0xa2, 0x02, 0x00, 0x80},
		{0xe2, 0x02, 0x00, 0x80},
		{0x70, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0xb0, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0xf0, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0x50, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0x90, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0xd0, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
	};

	res = asn1_parse_header(NULL, 2, &obj);
	CuAssert(tc, "NULL buffer should not be allowed.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_parse_header(&data[0][0], 1, &obj);
	CuAssert(tc, "Length shorter than 2 should not be allowed.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_parse_header(&data[0][0], 2, NULL);
	CuAssert(tc, "NULL ASN1 object should not be allowed.", res == LEGACY_INVALID_ARGUMENT);

	res = asn1_parse_header(&data[0][0], 3, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 1 && obj.header_length == 2 && obj.body_length == 1);

	res = asn1_parse_header(&data[1][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[2][0], 6, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 3 && obj.header_length == 2 && obj.body_length == 4);

	res = asn1_parse_header(&data[3][0], 8, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 4 && obj.header_length == 2 && obj.body_length == 6);

	res = asn1_parse_header(&data[4][0], 2, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 5 && obj.header_length == 2 && obj.body_length == 0);

	res = asn1_parse_header(&data[5][0], 8, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 6 && obj.header_length == 2 && obj.body_length == 6);

	res = asn1_parse_header(&data[6][0], 14, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 19 && obj.header_length == 2 && obj.body_length == 12);

	res = asn1_parse_header(&data[7][0], 15, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 20 && obj.header_length == 2 && obj.body_length == 13);

	res = asn1_parse_header(&data[8][0], 14, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 22 && obj.header_length == 2 && obj.body_length == 12);

	res = asn1_parse_header(&data[9][0], 15, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 23 && obj.header_length == 2 && obj.body_length == 13);

	res = asn1_parse_header(&data[10][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[11][0], 10, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 17 && obj.header_length == 2 && obj.body_length == 8);

	res = asn1_parse_header(&data[12][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[13][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[14][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[15][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[16][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[17][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 2 && obj.body_length == 2);

	res = asn1_parse_header(&data[18][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[19][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[20][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[21][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[22][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);

	res = asn1_parse_header(&data[23][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 16 && obj.header_length == 2 && obj.body_length == 7);


}

static void Test_Asn1_Dom_parse_header_incorrect_encoding(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_object obj;
	const unsigned char data[][20] = {
		{0x21, 0x01, 0xff},
		{0x22, 0x02, 0x00, 0x80},
		{0x23, 0x04, 0x06, 0x6e, 0x5d, 0xe0},
		{0x24, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x25, 0x00},
		{0x26, 0x06, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d},
		{0x33, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x34, 0x0d, 0x48, 0xc2, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x36, 0x0c, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21},
		{0x37, 0x0d, 0x39, 0x31, 0x30, 0x35, 0x30, 0x36, 0x32, 0x33, 0x34, 0x35, 0x34, 0x30, 0x5a},
		{0x10, 0x07, 0x01, 0x01, 0xff, 0x02, 0x02, 0x00, 0x80},
		{0x11, 0x08, 0x03, 0x04, 0x06, 0x6e, 0x5d, 0xe0, 0x05, 0x00}
	};

	res = asn1_parse_header(&data[0][0], 3, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[1][0], 4, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[2][0], 6, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[3][0], 8, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[4][0], 2, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[5][0], 8, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[6][0], 14, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[7][0], 15, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[8][0], 14, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[9][0], 15, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[10][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[11][0], 10, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_INVALID_FORMAT);
}

static void Test_Asn1_Dom_parse_header_tag_and_length(CuTest* tc) {
	int res = LEGACY_UNKNOWN_ERROR;
	asn1_object obj;
	const unsigned char data[][20] = {
		{0x01, 0x80, 0xff, 0x00, 0x00},
		{0x02, 0x81, 0x7f, 0x00, 0x80},
		{0x02, 0x81, 0x80, 0x00, 0x80},
		{0x03, 0x83, 0x00, 0x01, 0x80, 0x6e, 0x5d, 0xe0},
		{0x03, 0x82, 0x01, 0x80, 0x6e, 0x5d, 0xe0},
		{0x1f, 0x1e, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x1e, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x1f, 0x80, 0x1f, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x1f, 0x1f, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15},
		{0x1f, 0x81, 0x00, 0x06, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15}
	};

	res = asn1_parse_header(&data[0][0], 3, &obj);
	CuAssert(tc, "Indefinite length not allowed.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[1][0], 130, &obj);
	CuAssert(tc, "Length below 128 must be encoded in short form.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[2][0], 131, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 2 && obj.header_length == 3 && obj.body_length == 128);

	res = asn1_parse_header(&data[2][0], 130, &obj);
	CuAssert(tc, "ASN1 object header should not indicate data beyond buffer size.", res == LEGACY_ASN1_PARSING_ERROR);

	res = asn1_parse_header(&data[3][0], 389, &obj);
	CuAssert(tc, "Length must be encoded with the minimum number of octets.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[4][0], 388, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 3 && obj.header_length == 4 && obj.body_length == 384);

	res = asn1_parse_header(&data[4][0], 387, &obj);
	CuAssert(tc, "ASN1 object header should not indicate data beyond buffer size.", res == LEGACY_ASN1_PARSING_ERROR);

	res = asn1_parse_header(&data[5][0], 9, &obj);
	CuAssert(tc, "High-tag-form is reserved for tag numbers 31 and higher.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[6][0], 8, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 30 && obj.header_length == 2 && obj.body_length == 6);

	res = asn1_parse_header(&data[6][0], 7, &obj);
	CuAssert(tc, "ASN1 object header should not indicate data beyond buffer size.", res == LEGACY_ASN1_PARSING_ERROR);

	res = asn1_parse_header(&data[7][0], 10, &obj);
	CuAssert(tc, "Tag number must be encoded with the minimum number of octers.", res == LEGACY_INVALID_FORMAT);

	res = asn1_parse_header(&data[8][0], 9, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 31 && obj.header_length == 3 && obj.body_length == 6);

	res = asn1_parse_header(&data[8][0], 8, &obj);
	CuAssert(tc, "ASN1 object header should not indicate data beyond buffer size.", res == LEGACY_ASN1_PARSING_ERROR);

	res = asn1_parse_header(&data[9][0], 10, &obj);
	CuAssert(tc, "Unable to parse ASN object header.", res == LEGACY_OK);
	CuAssert(tc, "ASN1 object header parsed incorrectly.", obj.tag == 128 && obj.header_length == 4 && obj.body_length == 6);

	res = asn1_parse_header(&data[9][0], 9, &obj);
	CuAssert(tc, "ASN1 object header should not indicate data beyond buffer size.", res == LEGACY_ASN1_PARSING_ERROR);

}

CuSuite* LegacyTest_ASN_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_Asn1_Dom_new);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_resize);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_add_object);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_get_child);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_get_subobject);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_parse_header_correct_encoding);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_parse_header_incorrect_encoding);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_parse_header_tag_and_length);

	return suite;
}
