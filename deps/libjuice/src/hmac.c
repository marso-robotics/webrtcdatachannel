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
#else
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif

#include <stdio.h>
#include <string.h>
static int hmac_impl_logged = 0;

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
	if (!hmac_impl_logged) {
		hmac_impl_logged = 1;
		uint8_t test_out[20];
		const char *test_key = "Jefe";
		const char *test_data = "what do ya want for nothing?";
		static const uint8_t expected[20] = {
			0xef,0xfc,0xdf,0x6a,0xe5,0xeb,0x2f,0xa2,0xd2,0x74,
			0x16,0xd5,0xf1,0x84,0xdf,0x9c,0x25,0x9a,0x7c,0x79
		};
#if USE_NETTLE
		fprintf(stderr, "[HMAC-IMPL] Using Nettle");
		{ struct hmac_sha1_ctx c; hmac_sha1_set_key(&c,4,(const uint8_t*)test_key);
		  hmac_sha1_update(&c,28,(const uint8_t*)test_data);
		  hmac_sha1_digest(&c,20,test_out); }
#else
		fprintf(stderr, "[HMAC-IMPL] Using OpenSSL");
		{ unsigned int ml=20;
		  HMAC(EVP_sha1(),test_key,4,(const unsigned char*)test_data,28,test_out,&ml); }
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
#else
	unsigned int md_len = HMAC_SHA1_SIZE;
	HMAC(EVP_sha1(), key, (int)key_size,
	     (const unsigned char *)message, size,
	     (unsigned char *)digest, &md_len);
#endif
}

void hmac_sha256(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha256_ctx ctx;
	hmac_sha256_set_key(&ctx, key_size, key);
	hmac_sha256_update(&ctx, size, message);
	hmac_sha256_digest(&ctx, HMAC_SHA256_SIZE, digest);
#else
	unsigned int md_len = HMAC_SHA256_SIZE;
	HMAC(EVP_sha256(), key, (int)key_size,
	     (const unsigned char *)message, size,
	     (unsigned char *)digest, &md_len);
#endif
}
