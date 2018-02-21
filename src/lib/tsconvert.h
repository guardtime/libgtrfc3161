#ifndef _tsconvert_h_included_
#define _tsconvert_h_included_

#include <ksi/signature.h>

bool convert_signature(KSI_CTX *ctx, const unsigned char *rfc3161_signature,
	size_t rfc3161_size, KSI_Signature **ksi_signature);

#endif //_tsconvert_h_included_
