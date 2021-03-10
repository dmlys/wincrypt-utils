#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#if EXT_ENABLE_OPENSSL

#include <ext/openssl.hpp>
#include <ext/wincrypt/utils.hpp>

namespace ext::wincrypt
{
	std::string integer_string(const CRYPT_INTEGER_BLOB * num);
	std::wstring integer_u16string(const CRYPT_INTEGER_BLOB * num);
	
	auto openssl_cert(const ::CERT_CONTEXT * wincert)
		-> ext::openssl::x509_iptr;
	
	auto make_openssl_key(const ::CERT_CONTEXT * wincert)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>;
	
	auto make_openssl_key(const ::CERT_CONTEXT * wincert, const CRYPT_KEY_PROV_INFO * info)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>;
	
	
	/// Creates and prepares PRIVATEBLOB for Microsoft RSA base/enhanced/string/aes crypto provider
	/// (basicly any Microsoft RSA crypto provider) from OpenSSL RSA key object.
	/// This blob is suitable for CryptImportKey function.
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_rsa_private_blob(::RSA * rsa);
	
	/// Creates and prepares PRIVATEBLOB for Microsoft RSA or DSS(DSA) crypto provider from OpenSSL EVP_PKEY key object.
	/// Only DSA or RSA(currently only RSA) keys are supported.
	/// This blob is suitable for CryptImportKey function.
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/dss-version-3-private-key-blobs
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-version-3-private-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_private_blob(::EVP_PKEY * pkey);
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
