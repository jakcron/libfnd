#include <fnd/sha.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>

using namespace fnd::sha;

void fnd::sha::Sha1(const uint8_t* in, uint64_t size, uint8_t hash[kSha1HashLen])
{
	mbedtls_sha1(in, size, hash);
}

void fnd::sha::Sha256(const uint8_t* in, uint64_t size, uint8_t hash[kSha256HashLen])
{
	mbedtls_sha256(in, size, hash, false);
}