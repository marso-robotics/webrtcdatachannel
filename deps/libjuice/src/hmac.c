/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "hmac.h"

#if USE_NETTLE
#include <nettle/hmac.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include "picohash.h"
#endif

#if defined(_WIN32) && !USE_NETTLE
static void bcrypt_hmac(const wchar_t *algorithm, ULONG hash_size,
                        const void *message, size_t size,
                        const void *key, size_t key_size, void *digest) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, algorithm, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_size, 0);
	BCryptHashData(hHash, (PUCHAR)message, (ULONG)size, 0);
	BCryptFinishHash(hHash, (PUCHAR)digest, hash_size, 0);
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
}
#endif

#include <stdio.h>
#include <string.h>
static int hmac_impl_logged = 0;

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
	if (!hmac_impl_logged) {
		hmac_impl_logged = 1;
		/* RFC 2202 test case 2: key="Jefe", data="what do ya want for nothing?" */
		uint8_t test_out[20];
		const char *test_key = "Jefe";
		const char *test_data = "what do ya want for nothing?";
		/* Expected: effcdf6ae5eb2fa2d27416d5f184df9c259a7c79 */
		static const uint8_t expected[20] = {
			0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,0xd2,0x74,
			0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79
		};
#if USE_NETTLE
		fprintf(stderr, "[HMAC-IMPL] Using Nettle");
#elif defined(_WIN32)
		fprintf(stderr, "[HMAC-IMPL] Using BCrypt");
#else
		fprintf(stderr, "[HMAC-IMPL] Using picohash");
#endif
		/* Compute the test vector using the actual compiled implementation */
#if USE_NETTLE
		{ struct hmac_sha1_ctx c; hmac_sha1_set_key(&c,4,(const uint8_t*)test_key);
		  hmac_sha1_update(&c,28,(const uint8_t*)test_data);
		  hmac_sha1_digest(&c,20,test_out); }
#elif defined(_WIN32)
		{ BCRYPT_ALG_HANDLE a=NULL; BCRYPT_HASH_HANDLE h=NULL;
		  BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA1_ALGORITHM,NULL,BCRYPT_ALG_HANDLE_HMAC_FLAG);
		  BCryptCreateHash(a,&h,NULL,0,(PUCHAR)test_key,4,0);
		  BCryptHashData(h,(PUCHAR)test_data,28,0);
		  BCryptFinishHash(h,test_out,20,0);
		  if(h)BCryptDestroyHash(h); if(a)BCryptCloseAlgorithmProvider(a,0); }
#else
		{ picohash_ctx_t c; picohash_init_hmac(&c, picohash_init_sha1, test_key, 4);
		  picohash_update(&c, test_data, 28); picohash_final(&c, test_out); }
#endif
		int ok = (memcmp(test_out, expected, 20) == 0);
		char hex[41];
		for (int i = 0; i < 20; i++) snprintf(hex+i*2, 3, "%02x", test_out[i]);
		fprintf(stderr, " | RFC2202-test2: %s (%s)\n", ok ? "PASS" : "FAIL", hex);
	}
#if USE_NETTLE
	struct hmac_sha1_ctx ctx;
	hmac_sha1_set_key(&ctx, key_size, key);
	hmac_sha1_update(&ctx, size, message);
	hmac_sha1_digest(&ctx, HMAC_SHA1_SIZE, digest);
#elif defined(_WIN32)
	bcrypt_hmac(BCRYPT_SHA1_ALGORITHM, 20, message, size, key, key_size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha1, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hmac_sha256(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, key_size, key);
	hmac_sha256_update(&ctx, size, message);
	hmac_sha256_digest(&ctx, HMAC_SHA256_SIZE, digest);
#elif defined(_WIN32)
	bcrypt_hmac(BCRYPT_SHA256_ALGORITHM, 32, message, size, key, key_size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_hmac(&ctx, picohash_init_sha256, key, key_size);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}
