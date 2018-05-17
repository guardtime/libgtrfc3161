#ifndef TSCONVERT_H
#define TSCONVERT_H

#include <ksi/signature.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LEGACY_ERROR_BASE 0x10001

enum Legacy_ErrorCode {
	LEGACY_OK = 0,
	LEGACY_INVALID_ARGUMENT = LEGACY_ERROR_BASE,
	LEGACY_INVALID_FORMAT,
	LEGACY_INVALID_STATE,
	LEGACY_ASN1_PARSING_ERROR,
	LEGACY_OUT_OF_MEMORY,
	LEGACY_IO_ERROR,
	LEGACY_INVALID_CMD_PARAM,
	LEGACY_UNKNOWN_ERROR,
};

int convert_signature(KSI_CTX *ctx, const unsigned char *rfc3161_signature, size_t rfc3161_size, KSI_Signature **ksi_signature);

#ifdef __cplusplus
}
#endif

#endif /* TSCONVERT_H */
