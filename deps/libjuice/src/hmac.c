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
static int hmac_impl_logged = 0;

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
	if (!hmac_impl_logged) {
		hmac_impl_logged = 1;
#if USE_NETTLE
		fprintf(stderr, "[HMAC-IMPL] Using Nettle\n");
#elif defined(_WIN32)
		fprintf(stderr, "[HMAC-IMPL] Using BCrypt\n");
#else
		fprintf(stderr, "[HMAC-IMPL] Using picohash\n");
#endif
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
