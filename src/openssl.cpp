#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#if EXT_ENABLE_OPENSSL

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

#include <ext/wincrypt/utils.hpp>
#include <ext/wincrypt/openssl.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <codecvt>
#include <ext/codecvt_conv.hpp>

namespace ext::wincrypt
{
	const std::codecvt_utf8_utf16<wchar_t, 0x10FFFF, std::codecvt_mode::little_endian> u8_cvt;
	static std::string to_utf8(std::wstring_view wstr)
	{
		return ext::codecvt_convert::to_bytes(u8_cvt, wstr);
	}

	static std::wstring to_utf16(std::string_view str)
	{
		return ext::codecvt_convert::from_bytes(u8_cvt, str);
	}
	
	static std::string to_string(const ::BIGNUM * num)
	{
		auto * str = ::BN_bn2dec(num);
		std::string result = str;
		::OPENSSL_free(str);
		return result;
	}

	static std::wstring to_u16string(const ::BIGNUM * num)
	{
		auto * str = ::BN_bn2dec(num);
		auto result = to_utf16(str);
		::OPENSSL_free(str);
		return result;
	}

	std::string integer_string(const CRYPT_INTEGER_BLOB * num)
	{
		// use openssl to print big integer as decimal.
		// openssl BIGNUM can be create from binary big-endian octet stream,
		// but CRYPT_INTEGER_BLOB is little-endian octet stream
		std::vector<unsigned char> num_data(num->pbData, num->pbData + num->cbData);
		std::reverse(num_data.begin(), num_data.end());

		::BIGNUM * bn = ::BN_bin2bn(num_data.data(), num_data.size(), nullptr);
		auto result = to_string(bn);
		::BN_free(bn);
		return result;
	}

	std::wstring integer_u16string(const CRYPT_INTEGER_BLOB * num)
	{
		// use openssl to print big integer as decimal.
		// openssl BIGNUM can be create from binary big-endian octet stream,
		// but CRYPT_INTEGER_BLOB is little-endian octet stream
		std::vector<unsigned char> num_data(num->pbData, num->pbData + num->cbData);
		std::reverse(num_data.begin(), num_data.end());

		::BIGNUM * bn = ::BN_bin2bn(num_data.data(), num_data.size(), nullptr);
		auto result = to_u16string(bn);
		::BN_free(bn);
		return result;
	}
	
	
	ext::openssl::x509_iptr openssl_cert(const ::CERT_CONTEXT * wincert)
	{
		using namespace ext::openssl;
		x509_iptr x509_ptr;
		
		auto * cert_blob_ptr = reinterpret_cast<const unsigned char *>(wincert->pbCertEncoded);
		X509 * cert = ::d2i_X509(nullptr, &cert_blob_ptr, wincert->cbCertEncoded);
		if (not cert) throw_last_error("ext::wincrypt::make_openssl_key: d2i_X509 for wincert blob failed");
		x509_ptr.reset(cert, ext::noaddref);
		
		return x509_ptr;
	}	
	
	auto make_openssl_key(const ::CERT_CONTEXT * wincert)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>
	{
		auto info = ext::wincrypt::get_provider_info(wincert);
		return make_openssl_key(wincert, info.get());
	}
	
	auto make_openssl_key(const ::CERT_CONTEXT * wincert, const CRYPT_KEY_PROV_INFO * info)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>
	{
		using namespace ext::openssl;
		
		x509_iptr x509_ptr;
		evp_pkey_iptr evp_ptr;
		int res;
		
		auto cont_name = to_utf8(info->pwszContainerName);
		auto prov_name = to_utf8(info->pwszProvName);
		
		auto * cert_blob_ptr = reinterpret_cast<const unsigned char *>(wincert->pbCertEncoded);
		X509 * cert = ::d2i_X509(nullptr, &cert_blob_ptr, wincert->cbCertEncoded);
		if (not cert) throw_last_error("ext::wincrypt::make_openssl_key: d2i_X509 for wincert blob failed");
		x509_ptr.reset(cert, ext::noaddref);
		
		ENGINE * capi = ::ENGINE_by_id("capi");
		if (not capi) throw_last_error("ext::wincrypt::make_openssl_key: ENGINE_by_id(\"capi\") failed");
		
		// Set key lookup method (1=substring, 2=friendlyname, 3=container name)
		res = ::ENGINE_ctrl_cmd(capi, "lookup_method", 3, nullptr, nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::make_openssl_key: ENGINE_ctrl_cmd/lookup_method=3 failed");
		// Set CSP name, (default CSP used if not specified)
		res = ::ENGINE_ctrl_cmd(capi, "csp_name", 0, prov_name.data(), nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::make_openssl_key: ENGINE_ctrl_cmd/csp_name failed");
		// Key type: 1=AT_KEYEXCHANGE (default), 2=AT_SIGNATURE
		res = ::ENGINE_ctrl_cmd(capi, "key_type", info->dwKeySpec, nullptr, nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::make_openssl_key: ENGINE_ctrl_cmd/key_type failed");
		
		// ENGINE_load_private_key accepts something to lookup key, 
		// how is interpreted depends on lookup_method cmd, and we set it to 3=container name, so pass it
		auto * evp_pkey = ::ENGINE_load_private_key(capi, cont_name.c_str(),  nullptr, nullptr);
		if (not evp_pkey) throw_last_error("ext::wincrypt::make_openssl_key: ENGINE_load_private_key failed");
		
		evp_ptr.reset(evp_pkey, ext::noaddref);
		
		return std::make_tuple(std::move(x509_ptr), std::move(evp_ptr));		
	}
	
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
