#include <fnd/rsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/md.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

using namespace fnd::rsa;
using namespace fnd::sha;

mbedtls_md_type_t getMdWrappedHashType(HashType type)
{
	mbedtls_md_type_t md_type = MBEDTLS_MD_NONE;

	switch (type)
	{
	case HASH_SHA1:
		md_type = MBEDTLS_MD_SHA1;
		break;
	case HASH_SHA256:
		md_type = MBEDTLS_MD_SHA256;
		break;
	default:
		break;
	}
	return md_type;
}

uint32_t getWrappedHashSize(HashType type)
{
	uint32_t size = 0;

	switch (type)
	{
	case HASH_SHA1:
		size = kSha1HashLen;
		break;
	case HASH_SHA256:
		size = kSha256HashLen;
		break;
	default:
		break;
	}
	return size;
}

int fnd::rsa::pkcs::rsaSign(const sRsa1024Key & key, HashType hash_type, const uint8_t * hash, uint8_t signature[kRsa1024Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_rsa_context rsa;

	// init context
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init prbg 
	const char* pers = "fnd::rsa::pkcs::rsaSign";
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t*)pers, strlen(pers));
	if (ret) 
		goto cleanup;

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa1024Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             key.priv_exponent, kRsa1024Size, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return ret;
}

int fnd::rsa::pkcs::rsaVerify(const sRsa1024Key & key, HashType hash_type, const uint8_t * hash, const uint8_t signature[kRsa1024Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_rsa_context rsa;

	// init context
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa1024Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );

	return ret;
}

int fnd::rsa::pkcs::rsaSign(const sRsa2048Key & key, HashType hash_type, const uint8_t * hash, uint8_t signature[kRsa2048Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_rsa_context rsa;

	// init context
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init prbg 
	const char* pers = "fnd::rsa::pkcs::rsaSign";
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t*)pers, strlen(pers));
	if (ret) 
		goto cleanup;

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa2048Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             key.priv_exponent, kRsa2048Size, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return ret;
}

int fnd::rsa::pkcs::rsaVerify(const sRsa2048Key & key, HashType hash_type, const uint8_t * hash, const uint8_t signature[kRsa2048Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_rsa_context rsa;

	// init context
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa2048Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );

	return ret;
}

int fnd::rsa::pkcs::rsaSign(const sRsa4096Key & key, HashType hash_type, const uint8_t * hash, uint8_t signature[kRsa4096Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_rsa_context rsa;

	// init context
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init prbg 
	const char* pers = "fnd::rsa::pkcs::rsaSign";
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t*)pers, strlen(pers));
	if (ret) 
		goto cleanup;

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa4096Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             key.priv_exponent, kRsa4096Size, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return ret;
}

int fnd::rsa::pkcs::rsaVerify(const sRsa4096Key & key, HashType hash_type, const uint8_t * hash, const uint8_t signature[kRsa4096Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_rsa_context rsa;

	// init context
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V15, 0 );

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa4096Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pkcs1_v15_verify(&rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );

	return ret;
}

int fnd::rsa::pss::rsaSign(const sRsa2048Key & key, HashType hash_type, const uint8_t * hash, uint8_t signature[kRsa2048Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_rsa_context rsa;

	// init context
	mbedtls_entropy_init( &entropy );
	mbedtls_ctr_drbg_init( &ctr_drbg );
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, getMdWrappedHashType(hash_type) );

	// init prbg 
	const char* pers = "fnd::rsa::pss::rsaSign";
	ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const uint8_t*)pers, strlen(pers));
	if (ret) 
		goto cleanup;

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa2048Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             key.priv_exponent, kRsa2048Size, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pss_sign(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, MBEDTLS_RSA_PRIVATE, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );
	mbedtls_ctr_drbg_free( &ctr_drbg );
	mbedtls_entropy_free( &entropy );

	return ret;
}

int fnd::rsa::pss::rsaVerify(const sRsa2048Key & key, HashType hash_type, const uint8_t * hash, const uint8_t signature[kRsa2048Size])
{
	int ret = 0;
	const uint8_t pub_exp[3] = { 0x01, 0x00, 0x01 };

	mbedtls_rsa_context rsa;

	// init context
	mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, getMdWrappedHashType(hash_type) );

	// init rsa key
	ret = mbedtls_rsa_import_raw(&rsa, \
	                             key.modulus, kRsa2048Size, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             nullptr, 0, \
	                             pub_exp, sizeof(pub_exp));
	if (ret)
		goto cleanup;

	// sign hash
	ret = mbedtls_rsa_rsassa_pss_verify(&rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, getMdWrappedHashType(hash_type), getWrappedHashSize(hash_type), hash, signature);

	cleanup:
	mbedtls_rsa_free( &rsa );

	return ret;
}