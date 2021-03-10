#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#if EXT_ENABLE_OPENSSL

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

// defined in wincrypt, conflicts with openssl
#undef X509_NAME

#include <fmt/core.h>

#include <ext/wincrypt/utils.hpp>
#include <ext/wincrypt/openssl.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <ext/codecvt_conv/generic_conv.hpp>
#include <ext/codecvt_conv/wchar_cvt.hpp>

namespace ext::wincrypt
{
	using ext::codecvt_convert::wchar_cvt::to_utf8;
	using ext::codecvt_convert::wchar_cvt::to_wchar;
	
	
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
		auto result = to_wchar(str);
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
	
	std::vector<unsigned char> create_rsa_private_blob(::RSA * rsa)
	{
		using ext::openssl::throw_last_error;
		// CryptImportKey can import private keys, for RSA/DSA/DH it's expects a blob described in following man pages
		// 
		// DH/DSS
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/dss-version-3-private-key-blobs
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-version-3-private-key-blobs
		// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-dhprivkey_ver3
		// 
		// RSA
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-cryptographic-service-providers
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/base-provider-key-blobs
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/enhanced-provider-key-blobs
		// 
		// RSA private blob:
		//   PUBLICKEYSTRUC  publickeystruc;
		//   RSAPUBKEY rsapubkey;
		//   BYTE modulus          [rsapubkey.bitlen/8];
		//   BYTE prime1           [rsapubkey.bitlen/16];
		//   BYTE prime2           [rsapubkey.bitlen/16];
		//   BYTE exponent1        [rsapubkey.bitlen/16];
		//   BYTE exponent2        [rsapubkey.bitlen/16];
		//   BYTE coefficient      [rsapubkey.bitlen/16];
		//   BYTE privateExponent  [rsapubkey.bitlen/8];
		
		auto * modulus          = ::RSA_get0_n(rsa);
		auto * public_exponent  = ::RSA_get0_e(rsa);
		auto * private_exponent = ::RSA_get0_d(rsa);
		auto * prime1           = ::RSA_get0_p(rsa);
		auto * prime2           = ::RSA_get0_q(rsa);
		auto * exponent1        = ::RSA_get0_dmp1(rsa);
		auto * exponent2        = ::RSA_get0_dmq1(rsa);
		auto * coefficient      = ::RSA_get0_iqmp(rsa);
		
		auto rsa_version = RSA_get_version(rsa);
		auto rsa_size    = RSA_size(rsa);
		auto bitlen      = rsa_size * 8;
		
		if (rsa_version != RSA_ASN1_VERSION_DEFAULT)
			throw std::runtime_error("ext::wincrypt::create_rsa_private_blob: Only RSA_ASN1_VERSION_DEFAULT supported(regular 2 prime keys, not multiprime)");
	
		assert(rsa_size % 8 == 0);
		
		auto blobsize = sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)
		        + bitlen / 8   // modulus
		        + bitlen / 16  // prime1
		        + bitlen / 16  // prime2
		        + bitlen / 16  // exponent1
		        + bitlen / 16  // exponent2
		        + bitlen / 16  // coefficient
		        + bitlen / 8   // privateExponent
		        ;
		
		std::vector<unsigned char> blob_buffer;
		blob_buffer.resize(blobsize);
		auto * ptr = blob_buffer.data();
		
		auto * pubkey = reinterpret_cast<PUBLICKEYSTRUC *>(ptr);
		auto * rsapub = reinterpret_cast<RSAPUBKEY * >(ptr + sizeof(PUBLICKEYSTRUC));
		
		pubkey->bType = PRIVATEKEYBLOB;
		pubkey->bVersion = CUR_BLOB_VERSION;
		pubkey->reserved = 0;
		pubkey->aiKeyAlg = CALG_RSA_KEYX;
		
		rsapub->magic = 0x32415352; // RSA2 in ASCII
		rsapub->bitlen = bitlen;
		rsapub->pubexp = BN_get_word(public_exponent);
		assert(rsapub->pubexp != -1);
		
		auto * modulus_ptr          = ptr += sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY);
		auto * prime1_ptr           = ptr += bitlen / 8;
		auto * prime2_ptr           = ptr += bitlen / 16;
		auto * exponent1_ptr        = ptr += bitlen / 16;
		auto * exponent2_ptr        = ptr += bitlen / 16;
		auto * coefficient_ptr      = ptr += bitlen / 16;
		auto * private_exponent_ptr = ptr += bitlen / 16;
		
		int res;
		res = ::BN_bn2lebinpad(modulus,          modulus_ptr,          bitlen / 8);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for modulus");
		
		res = ::BN_bn2lebinpad(prime1,           prime1_ptr,           bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for prime1");
		
		res = ::BN_bn2lebinpad(prime2,           prime2_ptr,           bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for prime2");
		
		res = ::BN_bn2lebinpad(exponent1,        exponent1_ptr,        bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for exponent1");
		
		res = ::BN_bn2lebinpad(exponent2,        exponent2_ptr,        bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for exponent2");
		
		res = ::BN_bn2lebinpad(coefficient,      coefficient_ptr,      bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for coefficient");
		
		res = ::BN_bn2lebinpad(private_exponent, private_exponent_ptr, bitlen / 8);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_private_blob: ::BN_bn2lebinpad failed for private_exponent");
		
		
		return blob_buffer;
	}

	std::vector<unsigned char> create_private_blob(::EVP_PKEY * pkey)
	{
		int type = ::EVP_PKEY_base_id(pkey); // can return EVP_PKEY_RSA/EVP_PKEY_RSA2, EVP_PKEY_DSA1, EVP_PKEY_RSA2, ...
		type = ::EVP_PKEY_type(type);        // more like family, EVP_PKEY_RSA2 -> EVP_PKEY_RSA, EVP_PKEY_DSA2 -> EVP_PKEY_DSA, etc
		
		if (type != EVP_PKEY_RSA)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_private_blob: only EVP_PKEY_RSA is supported, was = {}", type));
		
		auto * rsa = ::EVP_PKEY_get0_RSA(pkey);
		return create_rsa_private_blob(rsa);
	}
	
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
