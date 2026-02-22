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
#include <openssl/hmac.h>
#include <openssl/evp.h>
#endif

void hmac_sha1(const void *message, size_t size, const void *key, size_t key_size, void *digest) {
#if USE_NETTLE
	struct hmac_sha1_ctx ctx;
	hmac_sha1_set_key(&ctx, key_size, key);
	hmac_sha1_update(&ctx, size, message);
	hmac_sha1_digest(&ctx, HMAC_SHA1_SIZE, digest);
#elif defined(_WIN32)
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA1_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_size, 0);
	BCryptHashData(hHash, (PUCHAR)message, (ULONG)size, 0);
	BCryptFinishHash(hHash, (PUCHAR)digest, 20, 0);
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
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
#elif defined(_WIN32)
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	BCryptCreateHash(hAlg, &hHash, NULL, 0, (PUCHAR)key, (ULONG)key_size, 0);
	BCryptHashData(hHash, (PUCHAR)message, (ULONG)size, 0);
	BCryptFinishHash(hHash, (PUCHAR)digest, 32, 0);
	if (hHash) BCryptDestroyHash(hHash);
	if (hAlg)  BCryptCloseAlgorithmProvider(hAlg, 0);
#else
	unsigned int md_len = HMAC_SHA256_SIZE;
	HMAC(EVP_sha256(), key, (int)key_size,
	     (const unsigned char *)message, size,
	     (unsigned char *)digest, &md_len);
#endif
}
