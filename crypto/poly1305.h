/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Common values for the Poly1305 algorithm
 */

#define CHACHA20_IV_SIZE        16
#define CHACHA20_KEY_SIZE       32
#define CHACHA20_BLOCK_SIZE     64
#define POLY1305_BLOCK_SIZE     16
#define POLY1305_KEY_SIZE       32
#define POLY1305_DIGEST_SIZE    16


struct poly1305_desc_ctx {
	uint8 opaque[24 * sizeof(uint64)];
	uint32 nonce[4];
	uint8 data[POLY1305_BLOCK_SIZE];
	size_t num;
};
