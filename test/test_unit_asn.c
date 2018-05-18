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

CuSuite* LegacyTest_ASN_getSuite(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, Test_Asn1_Dom_new);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_resize);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_add_object);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_get_child);
	SUITE_ADD_TEST(suite, Test_Asn1_Dom_get_subobject);

	return suite;
}
