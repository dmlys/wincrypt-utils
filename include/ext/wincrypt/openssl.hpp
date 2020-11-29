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
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
