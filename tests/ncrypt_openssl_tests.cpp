#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

#undef X509_NAME

#include <openssl/sha.h>
#include <openssl/evp.h>

#include <ext/openssl.hpp>
#include <ext/wincrypt/ncrypt.hpp>
#include <ext/wincrypt/ncrypt-openssl.hpp>

#include <ext/hexdump.hpp>

#include <boost/test/unit_test.hpp>
#include "test_files.h"

static std::vector<unsigned char> sha256(std::string_view str)
{
	std::vector<unsigned char> result;
	result.resize(SHA256_DIGEST_LENGTH);
		
	SHA256(reinterpret_cast<const unsigned char *>(str.data()), str.size(), result.data());
	return result;
}

static std::vector<unsigned char> ncrypt_sign(::NCRYPT_KEY_HANDLE hkey, const unsigned char * hash, std::size_t hash_size)
{
	assert(hkey);
	assert("RSA" == ext::wincrypt::ncrypt::get_string_property(hkey, NCRYPT_ALGORITHM_GROUP_PROPERTY));
	
	std::vector<unsigned char> signature;

	DWORD flags = NCRYPT_PAD_PKCS1_FLAG;
	BCRYPT_PKCS1_PADDING_INFO pkcs1_padding_info;
	pkcs1_padding_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	        
	SECURITY_STATUS status;
	DWORD requested_size;
	
	status = NCryptSignHash(hkey, &pkcs1_padding_info, const_cast<unsigned char *>(hash), hash_size, nullptr, 0, &requested_size, flags);
	if (status != ERROR_SUCCESS)
		throw std::system_error(std::error_code(status, std::system_category()), "ncrypt_hash: NCryptSignHash failed");
	
	assert(requested_size);
	signature.resize(requested_size);
	
	status = NCryptSignHash(hkey, &pkcs1_padding_info, const_cast<unsigned char *>(hash), hash_size, signature.data(), signature.size(), &requested_size, flags);
	if (status != ERROR_SUCCESS)
		throw std::system_error(std::error_code(status, std::system_category()), "ncrypt_hash: NCryptSignHash failed");
	
	signature.resize(requested_size);
	return signature;
}

static bool ncrypt_verify(::NCRYPT_KEY_HANDLE hkey, const unsigned char * signature, std::size_t siglen, const unsigned char * hash, std::size_t hash_size)
{
	DWORD flags = NCRYPT_PAD_PKCS1_FLAG;
	BCRYPT_PKCS1_PADDING_INFO pkcs1_padding_info;
	pkcs1_padding_info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	
	SECURITY_STATUS status = ::NCryptVerifySignature(hkey, &pkcs1_padding_info, const_cast<unsigned char *>(hash), hash_size, const_cast<unsigned char *>(signature), siglen, flags);
	if (status == ERROR_SUCCESS)
		return true;
	if (status == NTE_BAD_SIGNATURE)
		return false;
	
	throw std::system_error(std::error_code(status, std::system_category()), "ncrypt_verify: NCryptVerifySignature failed");
}

static std::vector<unsigned char> openssl_sign(EVP_PKEY * pkey, const void * data, std::size_t datasize)
{
	assert(pkey);
	
	std::vector<unsigned char> signature;
	signature.resize(EVP_PKEY_get_size(pkey));
	
	EVP_MD_CTX * ctx = EVP_MD_CTX_new();
	ext::openssl::evp_md_ctx_uptr uctx(ctx);
	
	if (not ctx)
		ext::openssl::throw_last_error("openssl_sign: EVP_PKEY_MD_new failed");
	
	if (EVP_SignInit(ctx, EVP_sha256()) <= 0)
		ext::openssl::throw_last_error("openssl_sign: EVP_SignInit failed");
	
	if (EVP_SignUpdate(ctx, data, datasize) <= 0)
		ext::openssl::throw_last_error("openssl_sign: EVP_SignUpdate failed");
	
	unsigned int written;
	if (EVP_SignFinal(ctx, signature.data(), &written, pkey) <= 0)
		ext::openssl::throw_last_error("openssl_sign: EVP_SignFinal failed");
	
	signature.resize(written);
	return signature;
}

static bool openssl_verify(EVP_PKEY * pkey, const unsigned char * signature, std::size_t siglen, const void * data, std::size_t datasize)
{
	EVP_MD_CTX * ctx = EVP_MD_CTX_new();
	ext::openssl::evp_md_ctx_uptr uctx(ctx);
	
	if (not ctx)
		ext::openssl::throw_last_error("openssl_verify: EVP_PKEY_MD_new failed");
	
	if (EVP_VerifyInit(ctx, EVP_sha256()) <= 0)
		ext::openssl::throw_last_error("openssl_verify: EVP_VerifyInit failed");
	
	if (EVP_VerifyUpdate(ctx, data, datasize) <= 0)
		ext::openssl::throw_last_error("openssl_verify: EVP_VerifyUpdate failed");
	
	int rc = EVP_VerifyFinal(ctx, signature, siglen, pkey);
	if (rc < 0)
		ext::openssl::throw_last_error("openssl_verify: EVP_VerifyFinal failed");
	
	return rc >= 1;
}

BOOST_AUTO_TEST_SUITE(ncrypt_openssl_tests)

BOOST_AUTO_TEST_CASE(load_ncrypt_privatekey_from_openssl)
{
	std::string key_pem;
	LoadTestFile("test-files/test-key.pem", key_pem);
	
	auto prov = ext::wincrypt::ncrypt::open_storage_provider(MS_KEY_STORAGE_PROVIDER);
	auto openssl_key = ext::openssl::load_private_key(key_pem);
	
	auto rsa_blob = ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob(openssl_key.get());
	auto key = ext::wincrypt::ncrypt::import_key(prov.handle(), nullptr, BCRYPT_RSAFULLPRIVATE_BLOB, rsa_blob, 0);
	
	std::string test_data = "Hello ncrypt world";
	auto hash = sha256(test_data);
	auto sig  = ncrypt_sign(key.handle(), hash.data(), hash.size());
	auto res = openssl_verify(openssl_key.get(), sig.data(), sig.size(), test_data.data(), test_data.size());
	BOOST_CHECK(res);
}

BOOST_AUTO_TEST_CASE(load_ncrypt_privatekey_from_file)
{
	std::string key_pem;
	LoadTestFile("test-files/test-key.pem", key_pem);
	
	auto prov = ext::wincrypt::ncrypt::open_storage_provider(MS_KEY_STORAGE_PROVIDER);
	auto openssl_key = ext::openssl::load_private_key(key_pem);
	
	auto pkcs8_blob = ext::wincrypt::ncrypt::load_rsa_private_key(key_pem.data(), key_pem.size());
	auto key = ext::wincrypt::ncrypt::import_key(prov.handle(), nullptr, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkcs8_blob, 0);
	
	std::string test_data = "Hello ncrypt world";
	auto hash = sha256(test_data);
	auto sig  = ncrypt_sign(key.handle(), hash.data(), hash.size());
	auto res = openssl_verify(openssl_key.get(), sig.data(), sig.size(), test_data.data(), test_data.size());
	BOOST_CHECK(res);
}

BOOST_AUTO_TEST_CASE(verify_openssl_signature_with_ncrypt)
{
	std::string key_pem;
	LoadTestFile("test-files/test-key.pem", key_pem);
	
	auto prov = ext::wincrypt::ncrypt::open_storage_provider(MS_KEY_STORAGE_PROVIDER);
	auto openssl_key = ext::openssl::load_private_key(key_pem);
	
	auto pubkey_blob = ext::wincrypt::ncrypt::create_ncrypt_rsa_public_blob(openssl_key.get());
	auto ncrypt_public_key = ext::wincrypt::ncrypt::import_key(prov.handle(), nullptr, BCRYPT_RSAPUBLIC_BLOB, pubkey_blob, 0);
	
	std::string test_data = "Hello ncrypt world";
	auto hash = sha256(test_data);
	auto sig = openssl_sign(openssl_key.get(), test_data.data(), test_data.size());
	auto res = ncrypt_verify(ncrypt_public_key.handle(), sig.data(), sig.size(), hash.data(), hash.size());
	BOOST_CHECK(res);
}

BOOST_AUTO_TEST_CASE(load_openssl_privatekey_from_ncrtyp)
{
	std::string key_pem;
	LoadTestFile("test-files/test-key.pem", key_pem);
	
	auto prov = ext::wincrypt::ncrypt::open_storage_provider(MS_KEY_STORAGE_PROVIDER);
	auto pkcs8_blob = ext::wincrypt::ncrypt::load_rsa_private_key(key_pem.data(), key_pem.size());
	auto key = ext::wincrypt::ncrypt::import_key(prov.handle(), nullptr, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, pkcs8_blob, NCRYPT_DO_NOT_FINALIZE_FLAG);
	ext::wincrypt::ncrypt::set_scalar_property(key.handle(), NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG);
	ext::wincrypt::ncrypt::finalize_key(key.handle(), 0);
	
	auto openssl_key = ext::wincrypt::ncrypt::create_openssl_rsa_privatekey(key.handle());
	
	std::string test_data = "Hello ncrypt world";
	auto hash = sha256(test_data);
	auto sig = openssl_sign(openssl_key.get(), test_data.data(), test_data.size());
	auto res = ncrypt_verify(key.handle(), sig.data(), sig.size(), hash.data(), hash.size());
	BOOST_CHECK(res);
}

BOOST_AUTO_TEST_SUITE_END()
