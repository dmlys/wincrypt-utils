#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#ifdef EXT_ENABLE_OPENSSL

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

// defined in wincrypt, conflicts with openssl
#undef X509_NAME

#include <fmt/core.h>

#include <ext/wincrypt/ncrypt.hpp>
#include <ext/wincrypt/ncrypt-openssl.hpp>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/engine.h>

#include <ext/codecvt_conv/generic_conv.hpp>
#include <ext/codecvt_conv/wchar_cvt.hpp>


// With OpenSLL v3 some functions now accept some arguments via const pointers.
// Logically they should be accepting those arguments via const pointers from the beginning.
// To support both v1 and v3 versions - accept const pointers and unconst them for v1.

// MNNFFPPS: major minor fix patch status
#if OPENSSL_VERSION_NUMBER >= 0x30000000
// for v3, pointers should be already const - do nothing
#define v1_unconst(arg) arg
#else
// for v1, pointers should be unconst
template <class Type>
static inline Type * v1_unconst(const Type * arg) { return const_cast<Type *>(arg); }
#endif

namespace ext::wincrypt::ncrypt
{
	using ext::codecvt_convert::wchar_cvt::to_utf8;
	using ext::codecvt_convert::wchar_cvt::to_wchar;
	
	
	std::vector<unsigned char> create_ncrypt_rsa_public_blob(const ::RSA * rsa)
	{
		using ext::openssl::throw_last_error;
		
		// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob#remarks
		// Ncrypt RSA public blob:
		//   BCRYPT_RSAKEY_BLOB
		//   PublicExponent[cbPublicExp] // Big-endian.
		//   Modulus[cbModulus] // Big-endian.
		//
		auto * modulus          = ::RSA_get0_n(rsa);
		auto * public_exponent  = ::RSA_get0_e(rsa);
		
		auto rsa_version = ::RSA_get_version(const_cast<::RSA *>(rsa));
		auto rsa_size    = ::RSA_size(rsa);
		
		auto modulus_bytelen = rsa_size;
		auto pubexp_bytelen  = (std::max)(4, BN_num_bytes(public_exponent));
		
		if (rsa_version != RSA_ASN1_VERSION_DEFAULT)
			throw std::runtime_error("ext::wincrypt::create_wincrypt_public_blob: Only RSA_ASN1_VERSION_DEFAULT supported(regular 2 prime keys, not multiprime)");
	
		assert(rsa_size % CHAR_BIT == 0);
		
		auto blobsize = sizeof(::BCRYPT_RSAKEY_BLOB)
		        + pubexp_bytelen   // pubexp
		        + modulus_bytelen; // modulus
		
		std::vector<unsigned char> blob_buffer;
		blob_buffer.resize(blobsize);
		auto * ptr = blob_buffer.data();
		
		auto * blobhdr = reinterpret_cast<::BCRYPT_RSAKEY_BLOB *>(ptr);
		
		blobhdr->Magic = BCRYPT_RSAPUBLIC_MAGIC;
		blobhdr->BitLength = rsa_size * 8;
		blobhdr->cbModulus = modulus_bytelen;
		blobhdr->cbPublicExp = pubexp_bytelen;
		blobhdr->cbPrime1 = blobhdr->cbPrime2 = 0; // only used for private keys
		
		auto * pubexp_ptr  = ptr += sizeof(::BCRYPT_RSAKEY_BLOB);
		auto * modulus_ptr = ptr += pubexp_bytelen;
		
		int res;
		
		res = ::BN_bn2binpad(public_exponent, pubexp_ptr, pubexp_bytelen);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_public_blob: ::BN_bn2binpad failed for public_exponent");
		
		res = ::BN_bn2binpad(modulus, modulus_ptr, modulus_bytelen);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_public_blob: ::BN_bn2binpad failed for modulus");
		
		return blob_buffer;
	}
	
	std::vector<unsigned char> create_ncrypt_rsa_private_blob(const ::RSA * rsa)
	{
		using ext::openssl::throw_last_error;
		
		// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob#remarks
		// Ncrypt RSA public blob:
		//   BCRYPT_RSAKEY_BLOB
		//   PublicExponent[cbPublicExp] // Big-endian.
		//   Modulus[cbModulus] // Big-endian.
		//   Prime1[cbPrime1] // Big-endian.
		//   Prime2[cbPrime2] // Big-endian.
		//   Exponent1[cbPrime1] // Big-endian.
		//   Exponent2[cbPrime2] // Big-endian.
		//   Coefficient[cbPrime1] // Big-endian.
		//   PrivateExponent[cbModulus] // Big-endian.
		//
		
		auto * modulus          = ::RSA_get0_n(rsa);
		auto * public_exponent  = ::RSA_get0_e(rsa);
		auto * private_exponent = ::RSA_get0_d(rsa);
		auto * prime1           = ::RSA_get0_p(rsa);
		auto * prime2           = ::RSA_get0_q(rsa);
		auto * exponent1        = ::RSA_get0_dmp1(rsa);
		auto * exponent2        = ::RSA_get0_dmq1(rsa);
		auto * coefficient      = ::RSA_get0_iqmp(rsa);
		
		auto rsa_version = ::RSA_get_version(const_cast<::RSA *>(rsa));
		auto rsa_size    = ::RSA_size(rsa);
		auto rsa_bitlen  = rsa_size * 8;
		
		auto pubexp_bytelen  = (std::max)(4, BN_num_bytes(public_exponent));

		if (rsa_version != RSA_ASN1_VERSION_DEFAULT)
			throw std::runtime_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: Only RSA_ASN1_VERSION_DEFAULT supported(regular 2 prime keys, not multiprime)");
		
		assert(rsa_size % 8 == 0);
		
		auto blobsize = sizeof(::BCRYPT_RSAKEY_BLOB)
		        + pubexp_bytelen  // publicExponent
		        + rsa_bitlen / 8  // modulus
		        + rsa_bitlen / 16 // prime1
		        + rsa_bitlen / 16 // prime2
		        + rsa_bitlen / 16 // exponent1
		        + rsa_bitlen / 16 // exponent2
		        + rsa_bitlen / 16 // coefficient
		        + rsa_bitlen / 8  // privateExponent
		        ;
		
		std::vector<unsigned char> blob_buffer;
		blob_buffer.resize(blobsize);
		auto * ptr = blob_buffer.data();
		
		auto * blobhdr = reinterpret_cast<::BCRYPT_RSAKEY_BLOB *>(ptr);
		
		blobhdr->Magic = BCRYPT_RSAFULLPRIVATE_MAGIC;
		blobhdr->BitLength = rsa_bitlen;
		blobhdr->cbModulus = rsa_size;
		blobhdr->cbPublicExp = pubexp_bytelen;
		blobhdr->cbPrime1 = rsa_bitlen / 16;
		blobhdr->cbPrime2 = rsa_bitlen / 16;
		
		auto * pubexp_ptr           = ptr += sizeof(::BCRYPT_RSAKEY_BLOB);
		auto * modulus_ptr          = ptr += pubexp_bytelen;
		auto * prime1_ptr           = ptr += rsa_bitlen / 8;
		auto * prime2_ptr           = ptr += rsa_bitlen / 16;
		auto * exponent1_ptr        = ptr += rsa_bitlen / 16;
		auto * exponent2_ptr        = ptr += rsa_bitlen / 16;
		auto * coefficient_ptr      = ptr += rsa_bitlen / 16;
		auto * private_exponent_ptr = ptr += rsa_bitlen / 16;
		
		int res;
		
		res = ::BN_bn2binpad(public_exponent,    pubexp_ptr,           pubexp_bytelen);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for public_exponent");
		
		res = ::BN_bn2binpad(modulus,          modulus_ptr,          rsa_bitlen / 8);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for modulus");
		
		res = ::BN_bn2binpad(prime1,           prime1_ptr,           rsa_bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for prime1");
		
		res = ::BN_bn2binpad(prime2,           prime2_ptr,           rsa_bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for prime2");
		
		res = ::BN_bn2binpad(exponent1,        exponent1_ptr,        rsa_bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for exponent1");
		
		res = ::BN_bn2binpad(exponent2,        exponent2_ptr,        rsa_bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for exponent2");
		
		res = ::BN_bn2binpad(coefficient,      coefficient_ptr,      rsa_bitlen / 16);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for coefficient");
		
		res = ::BN_bn2binpad(private_exponent, private_exponent_ptr, rsa_bitlen / 8);
		if (not res) throw_last_error("ext::wincrypt::ncrypt::create_ncrypt_rsa_private_blob: ::BN_bn2binpad failed for private_exponent");
		
		return blob_buffer;
	}
	
	std::vector<unsigned char> create_ncrypt_rsa_public_blob(const ::EVP_PKEY * pkey)
	{
		int type = ::EVP_PKEY_base_id(pkey); // can return EVP_PKEY_RSA/EVP_PKEY_RSA2, EVP_PKEY_DSA1, EVP_PKEY_RSA2, ...
		type = ::EVP_PKEY_type(type);        // more like family, EVP_PKEY_RSA2 -> EVP_PKEY_RSA, EVP_PKEY_DSA2 -> EVP_PKEY_DSA, etc
		
		if (type != EVP_PKEY_RSA)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_ncrypt_rsa_public_blob: only EVP_PKEY_RSA is supported, was = {}", type));
		
		auto * rsa = ::EVP_PKEY_get0_RSA(v1_unconst(pkey));
		return create_ncrypt_rsa_public_blob(rsa);
	}
	
	std::vector<unsigned char> create_ncrypt_rsa_private_blob(const ::EVP_PKEY * pkey)
	{
		int type = ::EVP_PKEY_base_id(pkey); // can return EVP_PKEY_RSA/EVP_PKEY_RSA2, EVP_PKEY_DSA1, EVP_PKEY_RSA2, ...
		type = ::EVP_PKEY_type(type);        // more like family, EVP_PKEY_RSA2 -> EVP_PKEY_RSA, EVP_PKEY_DSA2 -> EVP_PKEY_DSA, etc
		
		if (type != EVP_PKEY_RSA)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_ncrypt_rsa_public_blob: only EVP_PKEY_RSA is supported, was = {}", type));
		
		auto * rsa = ::EVP_PKEY_get0_RSA(v1_unconst(pkey));
		return create_ncrypt_rsa_private_blob(rsa);
	}
	
	ext::openssl::rsa_iptr create_openssl_rsa_publickey(const unsigned char * data, std::size_t datalen)
	{
		if (datalen < sizeof(::BCRYPT_RSAKEY_BLOB))
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_publickey: sizeof blob < BCRYPT_RSAKEY_BLOB({} < {})", datalen, sizeof(::BCRYPT_RSAKEY_BLOB)));
		
		auto * blobhdr = reinterpret_cast<const ::BCRYPT_RSAKEY_BLOB *>(data);
		
		if(blobhdr->Magic != BCRYPT_RSAPUBLIC_MAGIC)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_publickey: expected BCRYPT_RSAPUBLIC_MAGIC, was = {}", blobhdr->Magic));
		
		auto rsa_bitlen = blobhdr->BitLength;
		auto expected_blobsize = sizeof(::BCRYPT_RSAKEY_BLOB) + blobhdr->cbPublicExp + blobhdr->cbModulus;
		
		if (datalen < expected_blobsize)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_publickey: wrong public blob size, was = {}, expected = {}", datalen, expected_blobsize));
		
		auto * ptr = data;
		auto * pubexp_ptr  = ptr += sizeof(::BCRYPT_RSAKEY_BLOB);
		auto * modulus_ptr = ptr += blobhdr->cbPublicExp;
		
		int res;
		const char * errmsg;
		::BIGNUM * public_exponent, * modulus;
		::RSA * rsa;
		
		public_exponent = modulus = nullptr;
		rsa = nullptr;
		
		public_exponent = ::BN_bin2bn(pubexp_ptr, blobhdr->cbPublicExp, nullptr);
		if (not public_exponent) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::BN_bin2bn failed for public_exponent creation"; goto error; }
		
		modulus = ::BN_bin2bn(modulus_ptr, blobhdr->cbModulus, nullptr);
		if (not modulus) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::BN_bin2bn failed for modulus creation"; goto error; }
		
		rsa = ::RSA_new();
		if (not rsa) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::RSA_new failed"; goto error; }
		
		res = ::RSA_set0_key(rsa, modulus, public_exponent, nullptr);
		modulus = public_exponent = nullptr;
		if (not res) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::RSA_set0_key failed"; goto error; }
		
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
		if (datalen < sizeof(::BCRYPT_RSAKEY_BLOB))
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: sizeof blob < BCRYPT_RSAKEY_BLOB({} < {})", datalen, sizeof(::BCRYPT_RSAKEY_BLOB)));
		
		auto * blobhdr = reinterpret_cast<const ::BCRYPT_RSAKEY_BLOB *>(data);
		
		if(blobhdr->Magic != BCRYPT_RSAFULLPRIVATE_MAGIC)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: expected BCRYPT_RSAFULLPRIVATE_MAGIC, was = {}", blobhdr->Magic));
		
		auto rsa_bitlen = blobhdr->BitLength;
		auto expected_blobsize = sizeof(::BCRYPT_RSAKEY_BLOB) 
		        + blobhdr->cbPublicExp   // publicExponent
		        + blobhdr->cbModulus     // modules
		        + blobhdr->cbPrime1      // prime1
		        + blobhdr->cbPrime2      // prime2
		        + blobhdr->cbPrime1      // exponent1
		        + blobhdr->cbPrime2      // exponent2
		        + blobhdr->cbPrime1      // coefficient
		        + blobhdr->cbModulus;    // privateExponent
		
		if (datalen < expected_blobsize)
			throw std::runtime_error(fmt::format("ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: wrong public blob size, was = {}, expected = {}", datalen, expected_blobsize));
		
		auto * ptr = data;
		auto * pubexp_ptr           = ptr += sizeof(::BCRYPT_RSAKEY_BLOB);
		auto * modulus_ptr          = ptr += blobhdr->cbPublicExp;
		auto * prime1_ptr           = ptr += blobhdr->cbModulus;
		auto * prime2_ptr           = ptr += blobhdr->cbPrime1;
		auto * exponent1_ptr        = ptr += blobhdr->cbPrime2;
		auto * exponent2_ptr        = ptr += blobhdr->cbPrime1;
		auto * coefficient_ptr      = ptr += blobhdr->cbPrime2;
		auto * private_exponent_ptr = ptr += blobhdr->cbPrime1;
		
		
		int res;
		const char * errmsg;
		::BIGNUM * public_exponent, * modulus, * prime1, * prime2, * exponent1, * exponent2, * coefficient, * private_exponent;
		::RSA * rsa;
		
		public_exponent = modulus = prime1 = prime2 = exponent1 = exponent2 = coefficient = private_exponent = nullptr;
		rsa = nullptr;
		
		public_exponent = ::BN_bin2bn(pubexp_ptr, blobhdr->cbPublicExp, nullptr);
		if (not public_exponent) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for public_exponent creation"; goto error; }
		
		modulus = ::BN_bin2bn(modulus_ptr, blobhdr->cbModulus,  nullptr);
		if (not modulus) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for modulus creation"; goto error; }
		
		prime1 = ::BN_bin2bn(prime1_ptr, blobhdr->cbPrime1, nullptr);
		if (not prime1) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for prime1 creation"; goto error; }
		
		prime2 = ::BN_bin2bn(prime2_ptr, blobhdr->cbPrime2, nullptr);
		if (not prime2) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for prime2 creation"; goto error; }
		
		exponent1 = ::BN_bin2bn(exponent1_ptr, blobhdr->cbPrime1, nullptr);
		if (not exponent1) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for exponent1 creation"; goto error; }
		
		exponent2 = ::BN_bin2bn(exponent2_ptr, blobhdr->cbPrime2, nullptr);
		if (not exponent2) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for exponent2 creation"; goto error; }
		
		coefficient = ::BN_bin2bn(coefficient_ptr, blobhdr->cbPrime1, nullptr);
		if (not coefficient) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for coefficient creation"; goto error; }
		
		private_exponent = ::BN_bin2bn(private_exponent_ptr, blobhdr->cbModulus,  nullptr);
		if (not private_exponent) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::BN_bin2bn failed for private_exponent creation"; goto error;  }
		
		
		
		rsa = ::RSA_new();
		if (not rsa) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::RSA_new failed"; goto error; }
		
		res = ::RSA_set0_key(rsa, modulus, public_exponent, private_exponent);
		modulus = public_exponent = private_exponent = nullptr;
		if (not res) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::RSA_set0_key failed"; goto error; }
		
		res = ::RSA_set0_factors(rsa, prime1, prime2);
		prime1 = prime2 = nullptr;
		if (not res) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::RSA_set0_factors failed"; goto error; }
		
		res = ::RSA_set0_crt_params(rsa, exponent1, exponent2, coefficient);
		exponent1 = exponent2 = coefficient = nullptr;
		if (not res) { errmsg = "ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::RSA_set0_crt_params failed"; goto error; }
		
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
	
	ext::openssl::evp_pkey_iptr create_openssl_rsa_publickey(::NCRYPT_PROV_HANDLE hkey)
	{
		auto blob = export_rsa_public_key(hkey);
		auto rsa_uptr = create_openssl_rsa_publickey(blob);
		
		auto pkey = ::EVP_PKEY_new();
		if (not pkey) ext::openssl::throw_last_error("ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::EVP_PKEY_new failed");
		
		ext::openssl::evp_pkey_iptr pkey_iptr(pkey, ext::noaddref);
		auto res = ::EVP_PKEY_assign_RSA(pkey, rsa_uptr.release());
		if (not res) ext::openssl::throw_last_error("ext::wincrypt::ncrypt::create_openssl_rsa_publickey: ::EVP_PKEY_assign_RSA failed");
		
		return pkey_iptr;
	}

	ext::openssl::evp_pkey_iptr create_openssl_rsa_privatekey(::NCRYPT_PROV_HANDLE hkey)
	{
		auto blob = export_rsa_private_key(hkey);
		auto rsa_uptr = create_openssl_rsa_privatekey(blob);
		
		auto pkey = ::EVP_PKEY_new();
		if (not pkey) ext::openssl::throw_last_error("ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::EVP_PKEY_new failed");
		
		ext::openssl::evp_pkey_iptr pkey_iptr(pkey, ext::noaddref);
		auto res = ::EVP_PKEY_assign_RSA(pkey, rsa_uptr.release());
		if (not res) ext::openssl::throw_last_error("ext::wincrypt::ncrypt::create_openssl_rsa_privatekey: ::EVP_PKEY_assign_RSA failed");
		
		return pkey_iptr;
	}
}



#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
