#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

#include <io.h>

#include <fmt/core.h>
#include <boost/range.hpp>
#include <boost/range/as_literal.hpp>
#include <boost/algorithm/string.hpp>

#include <ext/config.hpp>
#include <ext/errors.hpp>
#include <ext/codecvt_conv/generic_conv.hpp>
#include <ext/codecvt_conv/wchar_cvt.hpp>
#include <ext/filesystem_utils.hpp>

#include <ext/wincrypt/utils.hpp>

namespace ext::wincrypt
{
	using ext::codecvt_convert::wchar_cvt::to_utf8;
	using ext::codecvt_convert::wchar_cvt::to_wchar;
	

	void hcrypt_handle_traits::addref(::HCRYPTPROV hprov) noexcept
	{
		if (hprov == 0) return;
		BOOL res = ::CryptContextAddRef(hprov, nullptr, 0);
		assert(res); EXT_UNUSED(res);
	}

	void hcrypt_handle_traits::subref(::HCRYPTPROV hprov) noexcept
	{
		if (hprov == 0) return;
		BOOL res = ::CryptReleaseContext(hprov, 0);
		assert(res); EXT_UNUSED(res);
	}

	auto hcrypt_handle_traits::defval(::HCRYPTPROV hprov) noexcept -> ::HCRYPTPROV
	{
		return 0;
	}

	void cert_ptr_traits::addref(const ::CERT_CONTEXT * pcert) noexcept
	{
		// according to MSDB it is actually does not make copy, but increments reference counter
		::CertDuplicateCertificateContext(pcert);
	}

	void cert_ptr_traits::subref(const ::CERT_CONTEXT * pcert) noexcept
	{
		BOOL res = ::CertFreeCertificateContext(pcert);
		assert(res); EXT_UNUSED(res);
	}

	void hlocal_deleter::operator()(void * ptr) const noexcept
	{
		::LocalFree(ptr);
	};
	
	void hkey_deleter::operator()(::HCRYPTKEY * pkey) const noexcept
	{
		if (not pkey) return;
		BOOL res = ::CryptDestroyKey(*pkey);
		delete pkey;
		assert(res); EXT_UNUSED(res);
	}

	void hcertstore_deleter::operator()(::HCERTSTORE store) const noexcept
	{
		BOOL res = ::CertCloseStore(store, 0);
		assert(res); EXT_UNUSED(res);
	}	

	/// wrapper around CryptAcquireContext
	hprov_handle acquire_provider(const wchar_t * provname, const wchar_t * container, std::uint32_t type, unsigned flags)
	{
		::HCRYPTPROV hprov = 0;
		BOOL res = ::CryptAcquireContextW(&hprov, container, provname, type, flags);
		if (not res)
		{
			auto provnamea = to_utf8(provname ? provname : L"<null>");
			auto containera = to_utf8(container ? container : L"<null>");
			std::string errmsg = fmt::format("ext::wincrypt::acquire_provider: CryptAcquireContext failed with provname = {}, container = {}, type = {}, flags = {}", provnamea, containera, type, flags);

			ext::throw_last_system_error(errmsg);
		}

		return hprov_handle(hprov, ext::noaddref);
	}

	/// wrapper around CryptAcquireContext
	hprov_handle acquire_provider(const char * provname, const char * container, std::uint32_t type, unsigned flags)
	{
		return acquire_provider(provname  ? to_wchar(provname).c_str()  : nullptr,
		                        container ? to_wchar(container).c_str() : nullptr,
		                        type, flags);
	}

	/// wrapper around CryptAcquireContext
	hprov_handle acquire_provider(std::nullptr_t provname, std::nullptr_t container, std::uint32_t type, unsigned flags)
	{
		return acquire_provider(static_cast<const wchar_t *>(nullptr), static_cast<const wchar_t *>(nullptr), type, flags);
	}

	hprov_handle acquire_rsa_provider(unsigned flags)
	{
		return acquire_provider(nullptr, nullptr, PROV_RSA_FULL, flags);
	}

	hprov_handle acquire_rsa_sig_provider(unsigned flags)
	{
		return acquire_provider(nullptr, nullptr, PROV_RSA_SIG, flags);
	}

	hprov_handle acquire_dsa_provider(unsigned flags)
	{
		return acquire_provider(nullptr, nullptr, PROV_DSS_DH, flags);
	}

	hprov_handle acquire_dsa_sig_provider(unsigned flags)
	{
		return acquire_provider(nullptr, nullptr, PROV_DSS, flags);
	}


	std::string provider_name(::HCRYPTPROV prov)
	{
		std::string str;
		DWORD size = 1024;

		do
		{
			str.resize(size);
			BOOL res = ::CryptGetProvParam(prov, PP_NAME, reinterpret_cast<unsigned char *>(str.data()), &size, 0);
			if (not res) ext::throw_last_system_error("ext::wincrypt::provider_name: CryptGetProvParam failed");

		} while(size > str.size());

		str.resize(size);
		return str;
	}

	std::string provider_container(::HCRYPTPROV prov)
	{
		std::string str;
		DWORD size = 1024;

		do
		{
			str.resize(size);
			BOOL res = ::CryptGetProvParam(prov, PP_CONTAINER, reinterpret_cast<unsigned char *>(str.data()), &size, 0);
			if (not res) ext::throw_last_system_error("ext::wincrypt::provider_container: CryptGetProvParam failed");

		} while(size > str.size());

		str.resize(size);
		return str;
	}


	hcertstore_uptr open_system_store(const char * name)
	{
		auto * store = ::CertOpenSystemStoreA(0, name);
		if (not store) ext::throw_last_system_error("ext::wincrypt::open_system_store CertOpenSystemStore failed");

		return hcertstore_uptr(store);
	}

	hcertstore_uptr open_system_store(const wchar_t * name)
	{
		auto * store = ::CertOpenSystemStoreW(0, name);
		if (not store) ext::throw_last_system_error("ext::wincrypt::open_system_store CertOpenSystemStore failed");

		return hcertstore_uptr(store);
	}

	static std::vector<char> read_file(std::FILE * file)
	{
		std::vector<char> content;
		std::size_t file_length = 0;
		auto file_handle = _fileno(file);
		if (file_handle) file_length = ::_filelengthi64(file_handle);

		if (file_length)
		{
			content.resize(file_length);
			auto read = std::fread(content.data(), 1, file_length, file);
			content.resize(read);
		}
		else
		{
			std::size_t cursize = 0;
			std::size_t inc = 1024;
			while (not std::feof(file))
			{
				content.resize(cursize + inc);
				auto read = std::fread(content.data(), 1, inc, file);
				cursize += read;
			}

			content.resize(cursize);
		}

		return content;
	}

	cert_iptr load_certificate(const char * data, std::size_t len, std::string_view passwd)
	{
		DWORD written;
		BOOL res;

		std::vector<unsigned char> der_data;
		der_data.resize(len / 4 * 3);

		// CRYPT_STRING_ANY is actually try in order: CRYPT_STRING_BASE64HEADER, CRYPT_STRING_BASE64, CRYPT_STRING_BINARY
		// so we will read both PEM(with header and without) and DER encodings
		res = ::CryptStringToBinaryA(data, len, CRYPT_STRING_ANY, der_data.data(), &written, nullptr, nullptr);
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_certificate: CryptStringToBinary failed");

		auto * cert = ::CertCreateCertificateContext(X509_ASN_ENCODING, der_data.data(), written);
		if (not cert)
			ext::throw_last_system_error("ext::wincrypt::load_certificate: CertCreateCertificateContext failed");

		return cert_iptr(cert, ext::noaddref);
	}

	cert_iptr load_certificate_from_file(const char * path, std::string_view passwd)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_certificate(content.data(), content.size(), passwd);
	}

	cert_iptr load_certificate_from_file(const wchar_t * path, std::string_view passwd)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_certificate(content.data(), content.size(), passwd);
	}

	cert_iptr load_certificate_from_file(std::FILE * file, std::string_view passwd)
	{
		auto content = read_file(file);
		return load_certificate(content.data(), content.size(), passwd);
	}

	hkey_uptr load_private_key(::HCRYPTPROV prov, const char * data, std::size_t len, std::string_view passwd)
	{
		BOOL res;
		DWORD written, pkey_info_length, pkey_rsa_blob_length;
		CRYPT_PRIVATE_KEY_INFO * pkey_info_ptr = nullptr;
		unsigned char * pkey_rsa_blob_ptr = 0;
		
		hlocal_uptr pkey_info_uptr;
		hlocal_uptr pkey_info_pkey_blob_uptr;
		hlocal_uptr pkey_rsa_blob_uptr;
		
		std::vector<unsigned char> der_data;
		der_data.resize(len / 4 * 3);
		
		res = ::CryptStringToBinaryA(data, len, CRYPT_STRING_ANY, der_data.data(), &written, nullptr, nullptr);
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptStringToBinary failed");
		
		res = ::CryptDecodeObjectEx(PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
		                            der_data.data(), written,
		                            CRYPT_ENCODE_ALLOC_FLAG, nullptr, &pkey_info_ptr, &pkey_info_length);
		
		if (not res)
			ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptDecodeObjectEx(PKCS_PRIVATE_KEY_INFO) failed while decoding encoded RSA private key");
		
		pkey_info_uptr.reset(pkey_info_ptr);
		pkey_info_pkey_blob_uptr.reset(pkey_info_ptr->PrivateKey.pbData);
		
		if (not boost::starts_with(pkey_info_ptr->Algorithm.pszObjId, szOID_RSA))
		{
			std::string errmsg = "ext::wincrypt::load_private_key: bad algorithm. expected RSA";
			errmsg += "("; errmsg += szOID_RSA; errmsg += ")";
			errmsg += "was - "; errmsg += pkey_info_ptr->Algorithm.pszObjId;
			throw std::runtime_error(errmsg);
		}
		
		res = ::CryptDecodeObjectEx(PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
		                            pkey_info_ptr->PrivateKey.pbData, pkey_info_ptr->PrivateKey.cbData,
		                            CRYPT_ENCODE_ALLOC_FLAG, nullptr, &pkey_rsa_blob_ptr, &pkey_rsa_blob_length);
		
		pkey_rsa_blob_uptr.reset(pkey_rsa_blob_ptr);
		if (not res)
			ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptDecodeObjectEx(PKCS_RSA_PRIVATE_KEY) failed while decoding encoded RSA private key");
		
		
		hkey_uptr privkey_uptr(new ::HCRYPTKEY(0));
		res = ::CryptImportKey(prov, pkey_rsa_blob_ptr, pkey_rsa_blob_length, 0, 0, privkey_uptr.get());
		
		if (not res)
			ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptImportKey failed while importing decoded RSA private key");
		
		return privkey_uptr;
	}


	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, const char * path, std::string_view passwd)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_private_key(prov, content.data(), content.size(), passwd);
	}

	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, const wchar_t * path, std::string_view passwd)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_private_key(prov, content.data(), content.size(), passwd);
	}

	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, std::FILE * file, std::string_view passwd)
	{
		auto content = read_file(file);
		return load_private_key(prov, content.data(), content.size(), passwd);
	}


	ALG_ID get_algid(::HCRYPTKEY key)
	{
		ALG_ID algid;
		DWORD len = sizeof(algid);
		BOOL res = ::CryptGetKeyParam(key, KP_ALGID, reinterpret_cast<unsigned char *>(&algid), &len, 0);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::get_algid: CryptGetKeyParam failed with KP_ALGID");

		return algid;
	}

	std::uint32_t get_keyspec(::HCRYPTKEY key)
	{
		auto algid = get_algid(key);

		if (algid == CALG_RSA_KEYX) return AT_KEYEXCHANGE;
		if (algid == CALG_RSA_SIGN) return AT_SIGNATURE;
		if (algid == CALG_DH_SF)    return AT_KEYEXCHANGE;
		if (algid == CALG_DSS_SIGN) return AT_SIGNATURE;

		char buffer[32];
		std::sprintf(buffer, "%#X", algid);

		using namespace std::string_literals;
		throw std::runtime_error("ext::wincrypt::get_keyspec: don't know keyspec for alg "s + buffer);
	}

	auto acquire_certificate_private_key(const CERT_CONTEXT * cert, void * hwnd) -> std::tuple<hprov_handle, std::uint32_t>
	{
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
		DWORD key_spec = 0;
		BOOL should_free;

		BOOL res = ::CryptAcquireCertificatePrivateKey(cert,
			hwnd ? CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0,
			hwnd ? hwnd : nullptr,
			&handle, &key_spec, &should_free);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::acquire_certificate_private_key: CryptAcquireCertificatePrivateKey failed");

		return std::make_tuple(hprov_handle(handle, not should_free), key_spec);
	}

	pkey_prov_info_uptr get_provider_info(const CERT_CONTEXT * cert)
	{
		DWORD len;
		CRYPT_KEY_PROV_INFO * pinfo;
		WINBOOL res;
		res = ::CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &len);
		if (not res) ext::throw_last_system_error("ext::wincrypt::get_provider_info: CertGetCertificateContextProperty failed");
		
		pinfo = static_cast<CRYPT_KEY_PROV_INFO *>(operator new(len));		
		res = ::CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, pinfo, &len);
		if (not res) ext::throw_last_system_error("ext::wincrypt::get_provider_info: CertGetCertificateContextProperty failed");
		
		return pkey_prov_info_uptr(pinfo);
	}
	

	rsapubkey_info extract_rsapubkey_numbers(const CERT_CONTEXT * rsaCert)
	{
		return extract_rsapubkey_numbers(&rsaCert->pCertInfo->SubjectPublicKeyInfo.PublicKey);
	}

	rsapubkey_info extract_rsapubkey_numbers(const CRYPT_BIT_BLOB * rsaPublicKeyBlob)
	{
		unsigned char * data = nullptr;
		DWORD size = 0;

		// CRYPT_DECODE_ALLOC_FLAG - data will be allocated via LocalAlloc and placed into data, free with LocalFree
		int res = ::CryptDecodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		                                rsaPublicKeyBlob->pbData, rsaPublicKeyBlob->cbData,
		                                CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
		                                nullptr, &data, &size);

		if (not res)
			ext::throw_last_system_error("::CryptDecodeObjectEx failed while extracting RSA public key");


		hlocal_uptr data_uptr(data);

		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/constants-for-cryptencodeobject-and-cryptdecodeobject
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-version-3-public-key-blobs

		// as per MSDN for RSA_CSP_PUBLICKEYBLOB result is, qouting MSDN:
		// For the decode functions, pvStructInfo points to a public key BLOB immediately followed by a RSAPUBKEY and the modulus bytes.
		// (For information about public key BLOBs, see CRYPT_INTEGER_BLOB.)
		PUBLICKEYSTRUC pubkeyst;
		RSAPUBKEY rsapubkey;

		rsapubkey_info result;

		std::memcpy(&pubkeyst, data, sizeof(pubkeyst));
		std::memcpy(&rsapubkey, data + sizeof(pubkeyst), sizeof(rsapubkey));

		result.exponent = rsapubkey.pubexp;
		result.modulus.assign(
			data + sizeof(pubkeyst) + sizeof(rsapubkey),
			data + sizeof(pubkeyst) + sizeof(rsapubkey) + rsapubkey.bitlen / CHAR_BIT
		);

		// should be RAII
		//::LocalFree(data);

		return result;
	}

	std::string X509_name_string(const CERT_NAME_BLOB * name)
	{
		return to_utf8(X509_name_u16string(name));
	}

	std::wstring X509_name_u16string(const CERT_NAME_BLOB * name)
	{
		auto flags = CERT_X500_NAME_STR/* | CERT_NAME_STR_NO_PLUS_FLAG*/;

		auto required = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB *>(name), flags, nullptr, 0);
		std::wstring result;
		result.resize(required, 0);

		auto written = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB *>(name), flags, result.data(), required);
		while (not result[written - 1]) --written;
		result.resize(written);

		return result;
	}

	std::string X509_name_reverse_string(const CERT_NAME_BLOB * name)
	{
		return to_utf8(X509_name_reverse_u16string(name));
	}

	std::wstring X509_name_reverse_u16string(const CERT_NAME_BLOB * name)
	{
		auto flags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;

		auto required = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB *>(name), flags, nullptr, 0);
		std::wstring result;
		result.resize(required, 0);

		auto written = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<CERT_NAME_BLOB *>(name), flags, result.data(), required);
		while (not result[written - 1]) --written;
		result.resize(written);

		return result;
	}
}

#endif // BOOST_OS_WINDOWS
