#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#ifdef EXT_ENABLE_OPENSSL

#include <ext/openssl.hpp>
#include <ext/wincrypt/utils.hpp>

namespace ext::wincrypt
{
	/// Prints big decimal integer, in dec
	std::string integer_string(const ::CRYPT_INTEGER_BLOB * num);
	std::wstring integer_wstring(const ::CRYPT_INTEGER_BLOB * num);
	
	/// Creates OpenSSL certificate from wincrypt certificate.
	/// This function parses wincert->pbCertEncoded with ::d2i_X509
	/// @Throws system_error in case of errors
	auto create_openssl_cert(const ::CERT_CONTEXT * wincert) -> ext::openssl::x509_iptr;
	/// Creates wincrypt cert context from OpenSSL certificate.
	/// This function serialises OpenSSL certificate into memory in PEM format, then loads result via load_certificate
	/// @Throws system_error in case of errors
	cert_iptr create_wincrypt_cert(::X509 * cert);
	
	
	/// Creates and prepares PUBLICBLOB for wincrypto provider(should be any crypto provider)
	/// This blob is suitable for CryptImportKey function.
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs#public-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_wincrypt_public_blob(::RSA * rsa);
	/// Creates and prepares PRIVATEBLOB for Microsoft RSA base/enhanced/string/aes crypto provider
	/// (basicly any Microsoft RSA crypto provider) from OpenSSL RSA key object.
	/// This blob is suitable for CryptImportKey function.
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_wincrypt_private_blob(::RSA * rsa);
	
	/// Creates and prepares PUBLICBLOB for wincrypto provider(should be any crypto provider)
	/// Only DSA or RSA(currently only RSA) keys are supported.
	/// This blob is suitable for CryptImportKey function.
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs#public-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_wincrypt_public_blob(::EVP_PKEY * pkey);
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
	std::vector<unsigned char> create_wincrypt_private_blob(::EVP_PKEY * pkey);
	
	/// Creates OpenSSL RSA key from PUBLICBLOB of crypto RSA crypto provider.
	/// This blob usually comes from CryptExportKey function
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs#public-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	ext::openssl::rsa_iptr create_openssl_rsa_publickey(const unsigned char * publickey_blob_data, std::size_t publickey_blob_size);
	inline ext::openssl::rsa_iptr create_openssl_rsa_publickey(const std::vector<unsigned char> & publickey_blob)
	{ return create_openssl_rsa_publickey(publickey_blob.data(), publickey_blob.size()); }
	
	/// Creates OpenSSL RSA key from PRIVATEBLOB of Microsoft RSA crypto provider.
	/// This blob usually comes from CryptExportKey function(and if it' marked as exportable)
	/// 
	/// blob is described in MSDN pages:
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	ext::openssl::rsa_iptr create_openssl_rsa_privatekey(const unsigned char * privatekey_blob_data, std::size_t privatekey_blob_size);
	inline ext::openssl::rsa_iptr create_openssl_rsa_privatekey(const std::vector<unsigned char> & privatekey_blob)
	{ return create_openssl_rsa_privatekey(privatekey_blob.data(), privatekey_blob.size()); }
	
	/// Creates OpenSSL RSA key by extracting PUBLICBLOB of crypto RSA crypto provider,
	/// This is convenience function, calls: get_user_key, export_public_key, create_openssl_rsa_publickey.
	/// @Throws system_error in case of errors
	ext::openssl::evp_pkey_iptr create_openssl_publickey(::HCRYPTPROV prov, unsigned keyspec);
	/// Creates OpenSSL RSA key by extracting PRIVATEBLOB of Microsoft RSA crypto provider from given prov,
	/// This is convenience function, calls: get_user_key, export_private_key, create_openssl_rsa_privatekey.
	/// @Throws system_error in case of errors
	ext::openssl::evp_pkey_iptr create_openssl_privatekey(::HCRYPTPROV prov, unsigned keyspec);
	
	/// Creates OpenSSL RSA key via CAPI OpenSSL engine, it's sort of OpenSSL wrapper for wincrypt api
	/// NOTE: capi engine must br created and initialized before this function is used.
	///  somewhere in the main:
	/// 
	///     ::ENGINE_load_builtin_engines();
	///     auto * capi_engine = ::ENGINE_by_id("capi");
	///     ::ENGINE_init(capi_engine);
	/// 
	/// @Throws system_error in case of errors
	auto create_capi_openssl_privatekey(const ::CERT_CONTEXT * wincert)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>;
	
	/// Creates OpenSSL RSA key via CAPI OpenSSL engine, it's sort of OpenSSL wrapper for wincrypt api
	/// NOTE: capi engine must br created and initialized before this function is used.
	///  somewhere in the main:
	/// 
	///     ::ENGINE_load_builtin_engines();
	///     auto * capi_engine = ::ENGINE_by_id("capi");
	///     ::ENGINE_init(capi_engine);
	/// 
	/// @Throws system_error in case of errors
	auto create_capi_openssl_privatekey(const ::CERT_CONTEXT * wincert, const ::CRYPT_KEY_PROV_INFO * info)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>;
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
