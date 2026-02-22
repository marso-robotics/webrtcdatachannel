/**
 * Copyright (c) 2020 Paul-Louis Ageneau
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

#include "hash.h"

#if USE_NETTLE
#include <nettle/md5.h>
#include <nettle/sha1.h>
#include <nettle/sha2.h>
#elif defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#else
#include "picohash.h"
#endif

#if defined(_WIN32) && !USE_NETTLE
static void bcrypt_hash(const wchar_t *algorithm, ULONG hash_size,
                        const void *message, size_t size, void *digest) {
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, algorithm, NULL, 0);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);
	BCryptHashData(hHash, (PUCHAR)message, (ULONG)size, 0);
	BCryptFinishHash(hHash, (PUCHAR)digest, hash_size, 0);
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
}
#endif

void hash_md5(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct md5_ctx ctx;
	md5_init(&ctx);
	md5_update(&ctx, size, message);
	md5_digest(&ctx, HASH_MD5_SIZE, digest);
#elif defined(_WIN32)
	bcrypt_hash(BCRYPT_MD5_ALGORITHM, 16, message, size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_md5(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hash_sha1(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct sha1_ctx ctx;
	sha1_init(&ctx);
	sha1_update(&ctx, size, message);
	sha1_digest(&ctx, HASH_SHA1_SIZE, digest);
#elif defined(_WIN32)
	bcrypt_hash(BCRYPT_SHA1_ALGORITHM, 20, message, size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_sha1(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}

void hash_sha256(const void *message, size_t size, void *digest) {
#if USE_NETTLE
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, size, message);
	sha256_digest(&ctx, HASH_SHA256_SIZE, digest);
#elif defined(_WIN32)
	bcrypt_hash(BCRYPT_SHA256_ALGORITHM, 32, message, size, digest);
#else
	picohash_ctx_t ctx;
	picohash_init_sha256(&ctx);
	picohash_update(&ctx, message, size);
	picohash_final(&ctx, digest);
#endif
}
