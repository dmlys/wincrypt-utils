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

	static std::wstring to_wstring(const ::BIGNUM * num)
	{
		auto * str = ::BN_bn2dec(num);
		auto result = to_wchar(str);
		::OPENSSL_free(str);
		return result;
	}

	std::string integer_string(const ::CRYPT_INTEGER_BLOB * num)
	{
		// use openssl to print big integer as decimal.
		// openssl BIGNUM can be create from binary big-endian octet stream,
		// but CRYPT_INTEGER_BLOB is little-endian octet stream
		std::vector<unsigned char> num_data(num->pbData, num->pbData + num->cbData);
		std::reverse(num_data.begin(), num_data.end());

		ext::openssl::bignum_uptr bn(::BN_bin2bn(num_data.data(), num_data.size(), nullptr));
		auto result = to_string(bn.get());
		return result;
	}

	std::wstring integer_wstring(const ::CRYPT_INTEGER_BLOB * num)
	{
		// use openssl to print big integer as decimal.
		// openssl BIGNUM can be create from binary big-endian octet stream,
		// but CRYPT_INTEGER_BLOB is little-endian octet stream
		std::vector<unsigned char> num_data(num->pbData, num->pbData + num->cbData);
		std::reverse(num_data.begin(), num_data.end());

		ext::openssl::bignum_uptr bn(::BN_bin2bn(num_data.data(), num_data.size(), nullptr));
		auto result = to_wstring(bn.get());
		return result;
	}
	
	
	ext::openssl::x509_iptr create_openssl_cert(const ::CERT_CONTEXT * wincert)
	{
		using namespace ext::openssl;
		x509_iptr x509_ptr;
		
		auto * cert_blob_ptr = reinterpret_cast<const unsigned char *>(wincert->pbCertEncoded);
		auto * cert = ::d2i_X509(nullptr, &cert_blob_ptr, wincert->cbCertEncoded);
		if (not cert) throw_last_error("ext::wincrypt::create_openssl_cert: d2i_X509 for wincert blob failed");
		x509_ptr.reset(cert, ext::noaddref);
		
		return x509_ptr;
	}
	
	cert_iptr create_wincrypt_cert(::X509 * cert)
	{
		auto pem = ext::openssl::write_certificate(cert);
		return ext::wincrypt::load_certificate(pem);
	}
	
	std::vector<unsigned char> create_rsa_public_blob(::RSA * rsa)
	{
		using ext::openssl::throw_last_error;
		// RSA public blob:
		//   PUBLICKEYSTRUC  publickeystruc;
		//   RSAPUBKEY rsapubkey;
		//   BYTE modulus[rsapubkey.bitlen/8];
		// 
		auto * modulus          = ::RSA_get0_n(rsa);
		auto * public_exponent  = ::RSA_get0_e(rsa);
		
		auto rsa_version = ::RSA_get_version(rsa);
		auto rsa_size    = ::RSA_size(rsa);
		auto bitlen      = rsa_size * 8;
		
		if (rsa_version != RSA_ASN1_VERSION_DEFAULT)
			throw std::runtime_error("ext::wincrypt::create_rsa_public_blob: Only RSA_ASN1_VERSION_DEFAULT supported(regular 2 prime keys, not multiprime)");
	
		assert(rsa_size % 8 == 0);
		
		auto blobsize = sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)
		        + bitlen / 8;   // modulus
		
		std::vector<unsigned char> blob_buffer;
		blob_buffer.resize(blobsize);
		auto * ptr = blob_buffer.data();
		
		auto * blobhdr = reinterpret_cast<::PUBLICKEYSTRUC *>(ptr);
		auto * rsapub  = reinterpret_cast<::RSAPUBKEY * >(ptr + sizeof(::PUBLICKEYSTRUC));
		
		blobhdr->bType = PUBLICKEYBLOB;
		blobhdr->bVersion = CUR_BLOB_VERSION;
		blobhdr->reserved = 0;
		blobhdr->aiKeyAlg = CALG_RSA_KEYX;
		
		rsapub->magic = 0x32415352; // RSA2 in ASCII
		rsapub->bitlen = bitlen;
		rsapub->pubexp = ::BN_get_word(public_exponent);
		assert(rsapub->pubexp != -1);
		
		auto * modulus_ptr = ptr += sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY);
		
		int res;
		res = ::BN_bn2lebinpad(modulus, modulus_ptr, bitlen / 8);
		if (not res) throw_last_error("ext::wincrypt::create_rsa_public_blob: ::BN_bn2lebinpad failed for modulus");
		
		return blob_buffer;
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
		
		auto rsa_version = ::RSA_get_version(rsa);
		auto rsa_size    = ::RSA_size(rsa);
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
		
		auto * blobhdr = reinterpret_cast<::PUBLICKEYSTRUC *>(ptr);
		auto * rsapub  = reinterpret_cast<::RSAPUBKEY * >(ptr + sizeof(::PUBLICKEYSTRUC));
		
		blobhdr->bType = PRIVATEKEYBLOB;
		blobhdr->bVersion = CUR_BLOB_VERSION;
		blobhdr->reserved = 0;
		blobhdr->aiKeyAlg = CALG_RSA_KEYX;
		
		rsapub->magic = 0x32415352; // RSA2 in ASCII
		rsapub->bitlen = bitlen;
		rsapub->pubexp = ::BN_get_word(public_exponent);
		assert(rsapub->pubexp != -1);
		
		auto * modulus_ptr          = ptr += sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY);
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

	std::vector<unsigned char> create_wincrypt_public_blob(::EVP_PKEY * pkey)
	{
		int type = ::EVP_PKEY_base_id(pkey); // can return EVP_PKEY_RSA/EVP_PKEY_RSA2, EVP_PKEY_DSA1, EVP_PKEY_RSA2, ...
		type = ::EVP_PKEY_type(type);        // more like family, EVP_PKEY_RSA2 -> EVP_PKEY_RSA, EVP_PKEY_DSA2 -> EVP_PKEY_DSA, etc
		
		if (type != EVP_PKEY_RSA)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_wincrypt_public_blob: only EVP_PKEY_RSA is supported, was = {}", type));
		
		auto * rsa = ::EVP_PKEY_get0_RSA(pkey);
		return create_rsa_public_blob(rsa);
	}
	
	std::vector<unsigned char> create_wincrypt_private_blob(::EVP_PKEY * pkey)
	{
		int type = ::EVP_PKEY_base_id(pkey); // can return EVP_PKEY_RSA/EVP_PKEY_RSA2, EVP_PKEY_DSA1, EVP_PKEY_RSA2, ...
		type = ::EVP_PKEY_type(type);        // more like family, EVP_PKEY_RSA2 -> EVP_PKEY_RSA, EVP_PKEY_DSA2 -> EVP_PKEY_DSA, etc
		
		if (type != EVP_PKEY_RSA)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_wincrypt_private_blob: only EVP_PKEY_RSA is supported, was = {}", type));
		
		auto * rsa = ::EVP_PKEY_get0_RSA(pkey);
		return create_rsa_private_blob(rsa);
	}
	
	ext::openssl::rsa_iptr create_openssl_rsa_publickey(const unsigned char * data, std::size_t datalen)
	{
		if (datalen < sizeof(::PUBLICKEYSTRUC))
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_publickey: sizeof blob < PUBLICKEYSTRUC({} < {})", datalen, sizeof(::PUBLICKEYSTRUC)));

		if (datalen < sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY))
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_publickey: sizeof blob < PUBLICKEYSTRUC + RSAPUBKEY({} < {})", datalen, sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)));
		
		auto * blobhdr = reinterpret_cast<const ::PUBLICKEYSTRUC *>(data);
		auto * rsapub  = reinterpret_cast<const ::RSAPUBKEY *>(data + sizeof(::PUBLICKEYSTRUC));
		
		if(blobhdr->bType != PUBLICKEYBLOB)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_publickey: expected PUBLICKEYBLOB, was = {}", blobhdr->bType));
		
		assert(blobhdr->bVersion == CUR_BLOB_VERSION);
		assert(blobhdr->aiKeyAlg == CALG_RSA_KEYX);
		
		auto bitlen = rsapub->bitlen;
		
		auto expected_blobsize = sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)
		        + bitlen / 8;  // modulus
		
		if (datalen < expected_blobsize)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_publickey: wrong private blob size, was = {}, expected = {}", datalen, expected_blobsize));
		
		auto * ptr = data;
		auto * modulus_ptr          = ptr += sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY);
		
		int res;
		const char * errmsg;
		::BIGNUM * public_exponent, * modulus;
		::RSA * rsa;
		
		public_exponent = modulus = nullptr;
		rsa = nullptr;
		
		public_exponent = ::BN_new();
		if (not public_exponent) { errmsg = "ext::wincrypt::create_openssl_rsa_publickey: ::BN_new failed for public_exponent creation"; goto error; }
		::BN_set_word(public_exponent, rsapub->pubexp);
		
		modulus = ::BN_lebin2bn(modulus_ptr, bitlen / 8,  nullptr);
		if (not modulus) { errmsg = "ext::wincrypt::create_openssl_rsa_publickey: ::BN_lebin2bn failed for modulus creation"; goto error; }
		
		rsa = ::RSA_new();
		if (not rsa) { errmsg = "ext::wincrypt::create_openssl_rsa_publickey: ::RSA_new failed"; goto error; }
		
		res = ::RSA_set0_key(rsa, modulus, public_exponent, nullptr);
		modulus = public_exponent = nullptr;
		if (not res) { errmsg = "ext::wincrypt::create_openssl_rsa_publickey: ::RSA_set0_key failed"; goto error; }
		
		return ext::openssl::rsa_iptr(rsa, ext::noaddref);
		
	error:
		::RSA_free(rsa);
		::BN_clear_free(modulus);
		::BN_clear_free(public_exponent);
		
		auto errc = ext::openssl::last_error();
		throw std::system_error(errc, errmsg);
	}
	
	ext::openssl::rsa_iptr create_openssl_rsa_privatekey(const unsigned char * data, std::size_t datalen)
	{
		if (datalen < sizeof(::PUBLICKEYSTRUC))
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_privatekey: sizeof blob < PUBLICKEYSTRUC({} < {})", datalen, sizeof(::PUBLICKEYSTRUC)));

		if (datalen < sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY))
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_privatekey: sizeof blob < PUBLICKEYSTRUC + RSAPUBKEY({} < {})", datalen, sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)));
		
		auto * blobhdr = reinterpret_cast<const ::PUBLICKEYSTRUC *>(data);
		auto * rsapub  = reinterpret_cast<const ::RSAPUBKEY *>(data + sizeof(::PUBLICKEYSTRUC));
		
		if(blobhdr->bType != PRIVATEKEYBLOB)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_privatekey: expected PRIVATEKEYBLOB, was = {}", blobhdr->bType));
		
		assert(blobhdr->bVersion == CUR_BLOB_VERSION);
		assert(blobhdr->aiKeyAlg == CALG_RSA_KEYX);
		
		auto bitlen = rsapub->bitlen;
		
		auto expected_blobsize = sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY)
		        + bitlen / 8   // modulus
		        + bitlen / 16  // prime1
		        + bitlen / 16  // prime2
		        + bitlen / 16  // exponent1
		        + bitlen / 16  // exponent2
		        + bitlen / 16  // coefficient
		        + bitlen / 8   // privateExponent
		        ;
		
		if (datalen < expected_blobsize)
			throw std::runtime_error(fmt::format("ext::wincrypt::create_openssl_rsa_privatekey: wrong private blob size, was = {}, expected = {}", datalen, expected_blobsize));
		
		auto * ptr = data;
		auto * modulus_ptr          = ptr += sizeof(::PUBLICKEYSTRUC) + sizeof(::RSAPUBKEY);
		auto * prime1_ptr           = ptr += bitlen / 8;
		auto * prime2_ptr           = ptr += bitlen / 16;
		auto * exponent1_ptr        = ptr += bitlen / 16;
		auto * exponent2_ptr        = ptr += bitlen / 16;
		auto * coefficient_ptr      = ptr += bitlen / 16;
		auto * private_exponent_ptr = ptr += bitlen / 16;
		
		
		int res;
		const char * errmsg;
		::BIGNUM * public_exponent, * modulus, * prime1, * prime2, * exponent1, * exponent2, * coefficient, * private_exponent;
		::RSA * rsa;
		
		public_exponent = modulus = prime1 = prime2 = exponent1 = exponent2 = coefficient = private_exponent = nullptr;
		rsa = nullptr;
		
		public_exponent = ::BN_new();
		if (not public_exponent) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_new failed for public_exponent creation"; goto error; }
		::BN_set_word(public_exponent, rsapub->pubexp);
		
		modulus = ::BN_lebin2bn(modulus_ptr, bitlen / 8,  nullptr);
		if (not modulus) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for modulus creation"; goto error; }
		
		prime1 = ::BN_lebin2bn(prime1_ptr, bitlen / 16, nullptr);
		if (not prime1) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for prime1 creation"; goto error; }
		
		prime2 = ::BN_lebin2bn(prime2_ptr, bitlen / 16, nullptr);
		if (not prime2) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for prime2 creation"; goto error; }
		
		exponent1 = ::BN_lebin2bn(exponent1_ptr, bitlen / 16, nullptr);
		if (not exponent1) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for exponent1 creation"; goto error; }
		
		exponent2 = ::BN_lebin2bn(exponent2_ptr, bitlen / 16, nullptr);
		if (not exponent2) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for exponent2 creation"; goto error; }
		
		coefficient = ::BN_lebin2bn(coefficient_ptr, bitlen / 16, nullptr);
		if (not coefficient) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for coefficient creation"; goto error; }
		
		private_exponent = ::BN_lebin2bn(private_exponent_ptr, bitlen / 8,  nullptr);
		if (not private_exponent) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::BN_lebin2bn failed for private_exponent creation"; goto error;  }
		
		
		
		rsa = ::RSA_new();
		if (not rsa) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::RSA_new failed"; goto error; }
		
		res = ::RSA_set0_key(rsa, modulus, public_exponent, private_exponent);
		modulus = public_exponent = private_exponent = nullptr;
		if (not res) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::RSA_set0_key failed"; goto error; }
		
		res = ::RSA_set0_factors(rsa, prime1, prime2);
		prime1 = prime2 = nullptr;
		if (not res) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::RSA_set0_factors failed"; goto error; }
		
		res = ::RSA_set0_crt_params(rsa, exponent1, exponent2, coefficient);
		exponent1 = exponent2 = coefficient = nullptr;
		if (not res) { errmsg = "ext::wincrypt::create_openssl_rsa_privatekey: ::RSA_set0_crt_params failed"; goto error; }
		
		return ext::openssl::rsa_iptr(rsa, ext::noaddref);
		
	error:
		::RSA_free(rsa);
		::BN_clear_free(private_exponent);
		::BN_clear_free(coefficient);
		::BN_clear_free(exponent2);
		::BN_clear_free(exponent1);
		::BN_clear_free(prime2);
		::BN_clear_free(prime1);
		::BN_clear_free(modulus);
		::BN_clear_free(public_exponent);
		
		auto errc = ext::openssl::last_error();
		throw std::system_error(errc, errmsg);
	}
	
	ext::openssl::evp_pkey_iptr create_openssl_publickey(::HCRYPTPROV prov, unsigned keyspec)
	{
		auto hkey = get_user_key(prov, keyspec);
		auto blob = export_public_key(*hkey);
		auto rsa_uptr = create_openssl_rsa_publickey(blob);
		
		auto pkey = ::EVP_PKEY_new();
		if (not pkey) ext::openssl::throw_last_error("ext::wincrypt::create_openssl_publickey: ::EVP_PKEY_new failed");
		
		ext::openssl::evp_pkey_iptr pkey_iptr(pkey, ext::noaddref);
		auto res = ::EVP_PKEY_assign_RSA(pkey, rsa_uptr.release());
		if (not res) ext::openssl::throw_last_error("ext::wincrypt::create_openssl_publickey: ::EVP_PKEY_assign_RSA failed");
		
		return pkey_iptr;
	}
	
	ext::openssl::evp_pkey_iptr create_openssl_privatekey(::HCRYPTPROV prov, unsigned keyspec)
	{
		auto hkey = get_user_key(prov, keyspec);
		auto blob = export_private_key(*hkey);
		auto rsa_uptr = create_openssl_rsa_privatekey(blob);
		
		auto pkey = ::EVP_PKEY_new();
		if (not pkey) ext::openssl::throw_last_error("ext::wincrypt::create_openssl_privatekey: ::EVP_PKEY_new failed");
		
		ext::openssl::evp_pkey_iptr pkey_iptr(pkey, ext::noaddref);
		auto res = ::EVP_PKEY_assign_RSA(pkey, rsa_uptr.release());
		if (not res) ext::openssl::throw_last_error("ext::wincrypt::create_openssl_privatekey: ::EVP_PKEY_assign_RSA failed");
		
		return pkey_iptr;
	}
	
	auto create_capi_openssl_privatekey(const ::CERT_CONTEXT * wincert)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>
	{
		auto info = ext::wincrypt::get_provider_info(wincert);
		return create_capi_openssl_privatekey(wincert, info.get());
	}
	
	auto create_capi_openssl_privatekey(const ::CERT_CONTEXT * wincert, const ::CRYPT_KEY_PROV_INFO * info)
		-> std::tuple<ext::openssl::x509_iptr, ext::openssl::evp_pkey_iptr>
	{
		using namespace ext::openssl;
		
		x509_iptr x509_ptr;
		evp_pkey_iptr evp_ptr;
		int res;
		
		auto cont_name = to_utf8(info->pwszContainerName);
		auto prov_name = to_utf8(info->pwszProvName);
		
		auto * cert_blob_ptr = reinterpret_cast<const unsigned char *>(wincert->pbCertEncoded);
		auto * cert = ::d2i_X509(nullptr, &cert_blob_ptr, wincert->cbCertEncoded);
		if (not cert) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: d2i_X509 for wincert blob failed");
		x509_ptr.reset(cert, ext::noaddref);
		
		ENGINE * capi = ::ENGINE_by_id("capi");
		if (not capi) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_by_id(\"capi\") failed");
		
		// Set key lookup method (1=substring, 2=friendlyname, 3=container name)
		res = ::ENGINE_ctrl_cmd(capi, "lookup_method", 3, nullptr, nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_ctrl_cmd/lookup_method=3 failed");
		// Set CSP type, (default RSA_PROV_FULL)
		res = ::ENGINE_ctrl_cmd(capi, "csp_type", info->dwProvType, nullptr, nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_ctrl_cmd/csp_type failed");
		// Set CSP name, (default CSP used if not specified)
		res = ::ENGINE_ctrl_cmd(capi, "csp_name", 0, prov_name.data(), nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_ctrl_cmd/csp_name failed");
		// Key type: 1=AT_KEYEXCHANGE (default), 2=AT_SIGNATURE
		res = ::ENGINE_ctrl_cmd(capi, "key_type", info->dwKeySpec, nullptr, nullptr, 0);
		if (not res) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_ctrl_cmd/key_type failed");
		
		// ENGINE_load_private_key accepts something to lookup key,
		// how is interpreted depends on lookup_method cmd, and we set it to 3=container name, so pass it
		auto * evp_pkey = ::ENGINE_load_private_key(capi, cont_name.c_str(),  nullptr, nullptr);
		if (not evp_pkey) throw_last_error("ext::wincrypt::create_capi_openssl_privatekey: ENGINE_load_private_key failed");
		
		evp_ptr.reset(evp_pkey, ext::noaddref);
		
		return std::make_tuple(std::move(x509_ptr), std::move(evp_ptr));
	}
}

#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
