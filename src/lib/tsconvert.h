#ifndef _tsconvert_h_included_
#define _tsconvert_h_included_

#include <ksi/signature.h>

#define LEGACY_ERROR_BASE 0x10001

enum Legacy_ErrorCode {
	LEGACY_OK = 0,
	LEGACY_INVALID_ARGUMENT = LEGACY_ERROR_BASE,
	LEGACY_INVALID_FORMAT,
	LEGACY_ASN1_PARSING_ERROR,
	LEGACY_OUT_OF_MEMORY,
	LEGACY_IO_ERROR,
	LEGACY_INVALID_CMD_PARAM,
	LEGACY_UNKNOWN_ERROR,
};

int convert_signature(KSI_CTX *ctx, const unsigned char *rfc3161_signature, size_t rfc3161_size, KSI_Signature **ksi_signature);

#endif //_tsconvert_h_included_
