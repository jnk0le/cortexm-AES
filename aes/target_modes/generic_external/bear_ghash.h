#ifndef BEAR_GHASH_H
#define BEAR_GHASH_H

#include <stddef.h>

#ifdef __cplusplus
	extern "C" {
#endif

	// functions extracted from bearssl, should be constant time with ct multipliers
	// there will be a bit of redundancy

	void br_ghash_ctmul32(void *y, const void *h, const void *data, size_t len);
	void br_ghash_ctmul(void *y, const void *h, const void *data, size_t len);


#ifdef __cplusplus
	}
#endif

#endif //BEAR_GHASH_H
