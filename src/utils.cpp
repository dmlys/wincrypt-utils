#include <boost/predef.h>
#if BOOST_OS_WINDOWS

//#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>

#include <io.h>

#include <fmt/core.h>
#include <boost/range.hpp>
#include <boost/range/as_literal.hpp>
#include <boost/algorithm/string.hpp>

#include <ext/config.hpp>
#include <ext/errors.hpp>
#include <ext/time.hpp>
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

	void hkey_handle_traits::close(::HCRYPTKEY key) noexcept
	{
		if (not key) return;
		BOOL res = ::CryptDestroyKey(key);
		assert(res); EXT_UNUSED(res);
	}
	
	void hlocal_deleter::operator()(void * ptr) const noexcept
	{
		::LocalFree(ptr);
	};

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
			auto err = ::GetLastError();
			if (err == NTE_BAD_KEYSET) return hprov_handle();
			
			auto provnamea = to_utf8(provname ? provname : L"<null>");
			auto containera = to_utf8(container ? container : L"<null>");
			std::string errmsg = fmt::format("ext::wincrypt::acquire_provider: CryptAcquireContext failed with provname = {}, container = {}, type = {}, flags = {}", provnamea, containera, type, flags);

			throw std::system_error(err, std::system_category(), errmsg);
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
		assert(prov);
		
		std::string str;
		DWORD size = 1024;

		do
		{
			str.resize(size);
			BOOL res = ::CryptGetProvParam(prov, PP_NAME, reinterpret_cast<unsigned char *>(str.data()), &size, 0);
			if (not res) ext::throw_last_system_error("ext::wincrypt::provider_name: CryptGetProvParam failed");

		} while(size > str.size());

		// trim zero terminators at end
		while (not str[size - 1]) --size;
		
		str.resize(size);
		return str;
	}

	std::string provider_container(::HCRYPTPROV prov)
	{
		assert(prov);
		
		std::string str;
		DWORD size = 1024;

		do
		{
			str.resize(size);
			BOOL res = ::CryptGetProvParam(prov, PP_CONTAINER, reinterpret_cast<unsigned char *>(str.data()), &size, 0);
			if (not res) ext::throw_last_system_error("ext::wincrypt::provider_container: CryptGetProvParam failed");
			
		} while(size > str.size());
		
		// trim zero terminators at end
		while (not str[size - 1]) --size;
		
		str.resize(size);
		return str;
	}

	std::wstring provider_wname(::HCRYPTPROV prov)
	{
		auto name = provider_name(prov);
		return to_wchar(name);
	}
	
	std::wstring provider_wcontainer(::HCRYPTPROV prov)
	{
		auto container = provider_container(prov);
		return to_wchar(container);
	}
	
	unsigned provider_type(::HCRYPTPROV prov)
	{
		assert(prov);
		DWORD type = 0;
		DWORD size = sizeof(type);
		BOOL res = ::CryptGetProvParam(prov, PP_PROVTYPE, reinterpret_cast<unsigned char *>(&type), &size, 0);
		if (not res) ext::throw_last_system_error("ext::wincrypt::provider_type: CryptGetProvParam failed");
		
		return type;
	}
	
	std::vector<prov_alg> enum_provider_algorithms(::HCRYPTPROV hprov)
	{
		std::vector<prov_alg> result;
		PROV_ENUMALGS data;
		DWORD len = sizeof(data);
		DWORD flags = CRYPT_FIRST;
		
		for (;;)
		{
			BOOL res = ::CryptGetProvParam(hprov, PP_ENUMALGS, reinterpret_cast<BYTE *>(&data), &len, flags);
			if (res)
			{
				result.emplace_back();
				auto & item = result.back();
				item.algid = data.aiAlgid;
				item.bitlen = data.dwBitLen;
				
				// trim zero terminators at end
				while (data.szName[data.dwNameLen - 1] == 0) --data.dwNameLen;
				// and assign to std::string
				item.name.assign(data.szName, data.dwNameLen);
				
				flags = CRYPT_NEXT;
			}
			else
			{
				auto err = GetLastError();
				if (err == ERROR_NO_MORE_ITEMS)
					return result;
				
				throw std::system_error(std::error_code(err, std::system_category()), "ext::wincrypt::enum_provider_algorithms: CryptGetProvParam failed");
			}
		}
	}
	
	hkey_handle get_user_key(::HCRYPTPROV prov, unsigned keyspec)
	{
		::HCRYPTKEY hkey = 0;
		BOOL res = ::CryptGetUserKey(prov, keyspec, &hkey);
		if (not res) ext::throw_last_system_error("ext::wincrypt::get_user_key ::CryptGetUserKey failed");
		
		return hkey_handle(hkey);
	}
	
	hkey_handle import_key(::HCRYPTPROV prov, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags, ::HCRYPTKEY decryption_key)
	{
		assert(prov);
		
		::HCRYPTKEY hkey = 0;
		auto res = ::CryptImportKey(prov, blob_buffer, buffer_size, decryption_key, flags, &hkey);
		if (not res) ext::throw_last_system_error("ext::wincrypt::import_key ::CryptImportKey failed");
		
		return hkey_handle(hkey);
	}
	
	std::vector<unsigned char> export_key(::HCRYPTKEY key, unsigned blob_type, unsigned flags, ::HCRYPTKEY encryption_key)
	{
		assert(key);
		
		std::vector<unsigned char> blob;
		
		BOOL res;
		DWORD blob_length = 0;
		res = ::CryptExportKey(key, encryption_key, blob_type, flags, nullptr, &blob_length);
		if (not res) ext::throw_last_system_error("ext::wincrypt::export_key ::CryptExportKey failed");
		
		blob.resize(blob_length);
		res = ::CryptExportKey(key, encryption_key, blob_type, flags, blob.data(), &blob_length);
		if (not res) ext::throw_last_system_error("ext::wincrypt::export_key ::CryptExportKey failed");
		
		return blob;
	}

	std::vector<unsigned char> export_rsa_private_key(::HCRYPTKEY key, unsigned flags, ::HCRYPTKEY encryption_key)
	{
		return export_key(key, PRIVATEKEYBLOB, flags, encryption_key);
	}
	
	std::vector<unsigned char> export_rsa_public_key(::HCRYPTKEY key, unsigned flags)
	{
		return export_key(key, PUBLICKEYBLOB, flags, 0);
	}
	
	::ALG_ID get_algid(::HCRYPTKEY key)
	{
		::ALG_ID algid;
		DWORD len = sizeof(algid);
		BOOL res = ::CryptGetKeyParam(key, KP_ALGID, reinterpret_cast<unsigned char *>(&algid), &len, 0);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::get_algid: CryptGetKeyParam failed with KP_ALGID");

		return algid;
	}

	std::uint32_t translate_keyspec(::ALG_ID algid)
	{
		if (algid == CALG_RSA_KEYX) return AT_KEYEXCHANGE;
		if (algid == CALG_RSA_SIGN) return AT_SIGNATURE;
		if (algid == CALG_DH_SF)    return AT_KEYEXCHANGE;
		if (algid == CALG_DSS_SIGN) return AT_SIGNATURE;

		char buffer[32];
		std::sprintf(buffer, "%#X", algid);

		using namespace std::string_literals;
		throw std::runtime_error("ext::wincrypt::get_keyspec: don't know keyspec for alg "s + buffer);
	}
	
	static BOOL WINAPI system_store_names_callback(const void * pvSystemStore, DWORD dwFlags, ::PCERT_SYSTEM_STORE_INFO pStoreInfo, void * pvReserved, void * pvArg)
	{
		auto * vector = static_cast<std::vector<std::string> *>(pvArg);
		auto * sysstore_name = static_cast<const wchar_t *>(pvSystemStore);
		
		assert(vector);
		assert(sysstore_name);
		
		vector->push_back(to_utf8(sysstore_name));
		return true;
	}
	
	static BOOL WINAPI system_store_wnames_callback(const void * pvSystemStore, DWORD dwFlags, ::PCERT_SYSTEM_STORE_INFO pStoreInfo, void * pvReserved, void * pvArg)
	{
		auto * vector = static_cast<std::vector<std::wstring> *>(pvArg);
		auto * sysstore_name = static_cast<const wchar_t *>(pvSystemStore);
		
		assert(vector);
		assert(sysstore_name);
		
		vector->push_back(sysstore_name);
		return true;
	}
	
	std::vector<std::string> system_store_names(unsigned flags)
	{
		std::vector<std::string> names;
		BOOL res = ::CertEnumSystemStore(flags, 0, &names, system_store_names_callback);
		if (not res) ext::throw_last_system_error("ext::wincrypt::system_store_names: ::CertEnumSystemStore failed");
		
		return names;
	}
	
	std::vector<std::wstring> system_store_wnames(unsigned flags)
	{
		std::vector<std::wstring> names;
		BOOL res = ::CertEnumSystemStore(CERT_SYSTEM_STORE_CURRENT_USER, 0, &names, system_store_wnames_callback);
		if (not res) ext::throw_last_system_error("ext::wincrypt::system_store_wnames: ::CertEnumSystemStore failed");
		
		return names;
	}
	
	std::vector<std::string> system_store_names()
	{
		return system_store_names(CERT_SYSTEM_STORE_CURRENT_USER);
	}
	
	std::vector<std::wstring> system_store_wnames()
	{
		return system_store_wnames(CERT_SYSTEM_STORE_CURRENT_USER);
	}
	
	hcertstore_uptr open_system_store(const char * name)
	{
		assert(name);
		
		auto * store = ::CertOpenSystemStoreA(0, name);
		if (not store) ext::throw_last_system_error("ext::wincrypt::open_system_store: CertOpenSystemStore failed");

		return hcertstore_uptr(store);
	}

	hcertstore_uptr open_system_store(const wchar_t * name)
	{
		assert(name);
		
		auto * store = ::CertOpenSystemStoreW(0, name);
		if (not store) ext::throw_last_system_error("ext::wincrypt::open_system_store: CertOpenSystemStore failed");

		return hcertstore_uptr(store);
	}
	
	auto add_certificate(::HCERTSTORE cert_store, const unsigned char * data, std::size_t data_size, unsigned disposition /* = -1, CERT_STORE_ADD_NEW*/) -> cert_iptr
	{
		assert(cert_store);
		assert(data and data_size);
		
		if (disposition == -1) disposition = CERT_STORE_ADD_NEW;
		
		const ::CERT_CONTEXT * cert;
		BOOL res = ::CertAddEncodedCertificateToStore(
		                 cert_store,
		                 X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		                 data, data_size, disposition,
		                 &cert);
		
		if (not res) ext::throw_last_system_error("ext::wincrypt::add_certificate: CertAddEncodedCertificateToStore failed");
		
		return cert_iptr(cert, ext::noaddref);
	}
	
	auto add_certificate(::HCERTSTORE cert_store, const ::CERT_CONTEXT * cert, unsigned disposition /* = -1, CERT_STORE_ADD_NEW*/) -> cert_iptr
	{
		assert(cert_store);
		assert(cert);
		
		if (disposition == -1) disposition = CERT_STORE_ADD_NEW;
		
		const ::CERT_CONTEXT * cert2;
		BOOL res = ::CertAddCertificateContextToStore(cert_store, cert, disposition, &cert2);
		if (not res) ext::throw_last_system_error("ext::wincrypt::add_certificate: CertAddCertificateContextToStore failed");
		
		return cert_iptr(cert2, ext::noaddref);
	}
	
	void delete_certificate(cert_iptr cert)
	{
		assert(cert);
		
		BOOL res = ::CertDeleteCertificateFromStore(cert.release());
		if (not res) ext::throw_last_system_error("ext::wincrypt::delete_certificate: CertDeleteCertificateFromStore failed");
	}
	
	auto get_certificates(::HCERTSTORE cert_store) -> std::vector<cert_iptr>
	{
		assert(cert_store);
		
		std::vector<cert_iptr> certs;
		
		const ::CERT_CONTEXT * cert = nullptr;
		const ::CERT_CONTEXT * prev = nullptr;
		for (;;)
		{
			cert = ::CertFindCertificateInStore(
			            cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			            0, CERT_FIND_ANY,
			            nullptr, prev);
			
			if (not cert) break;
			
			certs.emplace_back(cert);
			prev = cert;
			
		}
		
		return certs;
	}

	cert_iptr find_first_certificate_by_subject(::HCERTSTORE cert_store, std::string_view subject)
	{
		assert(cert_store);
		
		std::wstring wsubject = ext::codecvt_convert::wchar_cvt::to_wchar(subject);
		auto result = ::CertFindCertificateInStore(
		            cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		            0, CERT_FIND_SUBJECT_STR,
		            wsubject.c_str(), nullptr);
		
		return cert_iptr(result, ext::noaddref);
	}
	
	std::vector<cert_iptr> find_certificates_by_subject(::HCERTSTORE cert_store, std::string_view subject)
	{
		assert(cert_store);
		
		std::vector<cert_iptr> certs;
		std::wstring wsubject = ext::codecvt_convert::wchar_cvt::to_wchar(subject);
		
		const ::CERT_CONTEXT * cert = nullptr;
		const ::CERT_CONTEXT * prev = nullptr;
		for (;;)
		{
			cert = ::CertFindCertificateInStore(
			            cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
			            0, CERT_FIND_SUBJECT_STR,
			            wsubject.c_str(), prev);
			
			if (not cert) break;
			
			certs.emplace_back(cert);
			prev = cert;
		}
		
		return certs;
	}
	
	auto find_certificate_by_hash(::HCERTSTORE cert_store, unsigned int find_type, const unsigned char * hash_data, std::size_t hash_size) -> cert_iptr
	{
		assert(cert_store);
		
		::CRYPT_HASH_BLOB hashblob;
		hashblob.cbData = hash_size;
		hashblob.pbData = const_cast<unsigned char *>(hash_data);
		
		auto result = ::CertFindCertificateInStore(
		            cert_store, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
		            0, find_type,
		            &hashblob, nullptr);
		
		return cert_iptr(result, ext::noaddref);
	}
	
	auto find_certificate_by_sha1fingerprint(::HCERTSTORE cert_store, const unsigned char * fp_data, std::size_t fp_size) -> cert_iptr
	{
		return find_certificate_by_hash(cert_store, CERT_FIND_SHA1_HASH, fp_data, fp_size);
	}
	
	cert_iptr import_certificate(::HCERTSTORE cert_store, const ::CERT_CONTEXT * cert, unsigned dispositionFlags)
	{
		assert(cert_store);
		assert(cert);
		
		const ::CERT_CONTEXT * imported;
		auto res = ::CertAddCertificateContextToStore(cert_store, cert, dispositionFlags, &imported);
		if (not res) ext::throw_last_system_error("ext::wincrypt::import_cert: CertAddCertificateContextToStore failed");
		
		return cert_iptr(imported, ext::noaddref);
	}
	
	static std::string keyspec_name(DWORD keyspec)
	{
		if (keyspec == AT_KEYEXCHANGE) return fmt::format("AT_KEYEXCHANGE({})", keyspec);
		if (keyspec == AT_SIGNATURE  ) return fmt::format("AT_SIGNATURE({})", keyspec);
		
		return fmt::format("UNKNOWN({})", keyspec);
	}
	
	static std::string provtype_name(DWORD provtype)
	{
#define ENTRY(entry) if (provtype == entry) return fmt::format(#entry"({})", provtype)
		ENTRY(PROV_RSA_FULL);
		ENTRY(PROV_RSA_SIG);
		ENTRY(PROV_DSS);
		//ENTRY(PROV_FORTEZZA);
		ENTRY(PROV_MS_EXCHANGE);
		ENTRY(PROV_SSL);
		
		//ENTRY(PROV_STT_MER);
		//ENTRY(PROV_STT_ACQ);
		//ENTRY(PROV_STT_BRND);
		//ENTRY(PROV_STT_ROOT);
		//ENTRY(PROV_STT_ISS);
		
		ENTRY(PROV_RSA_SCHANNEL);
		ENTRY(PROV_DSS_DH);
		
		//ENTRY(PROV_EC_ECDSA_SIG);
		//ENTRY(PROV_EC_ECNRA_SIG);
		//ENTRY(PROV_EC_ECDSA_FULL);
		//ENTRY(PROV_EC_ECNRA_FULL);
		
		ENTRY(PROV_DH_SCHANNEL);
		//ENTRY(PROV_SPYRUS_LYNKS);
		ENTRY(PROV_RNG);
		//ENTRY(PROV_INTEL_SEC);
		
		//ENTRY(PROV_REPLACE_OWF);
		ENTRY(PROV_RSA_AES);
#undef ENTRY
		
		return fmt::format("UNKNOWN({})", provtype);
	}
	
	std::string dump_cryptkey_provider_info(const ::CRYPT_KEY_PROV_INFO * prov_info, std::string_view ident)
	{
		std::string result;
		result.reserve(512);
		if (not prov_info)
			return result.append(ident).append("No private key info\n");
		
		std::string provtype_str = provtype_name(prov_info->dwProvType);
		std::string keyspec_str = keyspec_name(prov_info->dwKeySpec);
		
		std::string prov_name = prov_info->pwszProvName ? to_utf8(prov_info->pwszProvName) : "<null>";
		std::string cont_name = prov_info->pwszContainerName ? to_utf8(prov_info->pwszContainerName) : "<null>";
		
		result.append(ident).append("Private key info:\n");
		result += ident; result += fmt::format("  Provider Type: {}, Provider Name: {}\n", provtype_str, prov_name);
		result += ident; result += fmt::format("  Key Spec: {}, Container Name: {}\n", keyspec_str, cont_name);
		
		return result;
	}
	
	pkey_prov_info_uptr get_provider_info(const ::CERT_CONTEXT * cert)
	{
		assert(cert);
		
		DWORD len, err;
		::CRYPT_KEY_PROV_INFO * pinfo;
		bool res;
		res = ::CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &len);
		if (not res) goto error;
		
		pinfo = static_cast<::CRYPT_KEY_PROV_INFO *>(::LocalAlloc(LMEM_FIXED, len));
		res = ::CertGetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, pinfo, &len);
		if (not res) goto error;
		
		return pkey_prov_info_uptr(pinfo);
		
	error:
		err = ::GetLastError();
		if (err == CRYPT_E_NOT_FOUND)
			return nullptr;
		
		throw std::system_error(err, std::system_category(), "ext::wincrypt::get_provider_info: ::CertGetCertificateContextProperty failed");
	}
	
	void set_provider_info(const ::CERT_CONTEXT * cert, const ::CRYPT_KEY_PROV_INFO * prov_info)
	{
		assert(cert);
		
		auto res = ::CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, prov_info);
		if (not res) ext::throw_last_system_error("ext:::wincrypt::set_provider_info: ::CertSetCertificateContextProperty failed");
	}
	
	void bound_certificate_with_private_key(const ::CERT_CONTEXT * cert, ::HCRYPTPROV prov, unsigned keyspec)
	{
		auto wname = provider_wname(prov);
		auto wcont = provider_wcontainer(prov);
		auto type  = provider_type(prov);
		
		::CRYPT_KEY_PROV_INFO info;
		info.pwszContainerName = wcont.data();
		info.pwszProvName = wname.data();
		info.dwProvType = type;
		info.dwFlags = 0;
		info.cProvParam = 0;
		info.rgProvParam = nullptr;
		info.dwKeySpec = keyspec;
		
		BOOL res = ::CertSetCertificateContextProperty(cert, CERT_KEY_PROV_INFO_PROP_ID, 0, &info);
		if (not res) ext::throw_last_system_error("ext:::wincrypt::bound_certificate_with_private_key: ::CertSetCertificateContextProperty failed");
	}
	
	auto acquire_certificate_private_key(const ::CERT_CONTEXT * cert, void * hwnd) -> std::tuple<hprov_handle, std::uint32_t>
	{
		assert(cert);
		
		::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
		DWORD keyspec = 0;
		BOOL should_free;

		BOOL res = ::CryptAcquireCertificatePrivateKey(cert,
			hwnd ? CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0,
			hwnd ? &hwnd : nullptr,
			&handle, &keyspec, &should_free);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::acquire_certificate_private_key: CryptAcquireCertificatePrivateKey failed");

		return std::make_tuple(hprov_handle(handle, not should_free), keyspec);
	}
	
	rsapubkey_info extract_rsapubkey_numbers(const ::CERT_CONTEXT * rsaCert)
	{
		assert(rsaCert);
		return extract_rsapubkey_numbers(&rsaCert->pCertInfo->SubjectPublicKeyInfo.PublicKey);
	}

	rsapubkey_info extract_rsapubkey_numbers(const ::CRYPT_BIT_BLOB * rsaPublicKeyBlob)
	{
		assert(rsaPublicKeyBlob);
		
		unsigned char * data = nullptr;
		DWORD size = 0;

		// CRYPT_DECODE_ALLOC_FLAG - data will be allocated via LocalAlloc and placed into data, free with LocalFree
		int res = ::CryptDecodeObjectEx(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
		                                rsaPublicKeyBlob->pbData, rsaPublicKeyBlob->cbData,
		                                CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
		                                nullptr, &data, &size);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::extract_rsapubkey_numbers: ::CryptDecodeObjectEx failed while extracting RSA public key");


		hlocal_uptr data_uptr(data);

		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/constants-for-cryptencodeobject-and-cryptdecodeobject
		// https://docs.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-version-3-public-key-blobs

		// as per MSDN for RSA_CSP_PUBLICKEYBLOB result is, quoting MSDN:
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

		return result;
	}

	std::string cert_name_string(const ::CERT_NAME_BLOB * name)
	{
		return to_utf8(cert_name_wstring(name));
	}

	std::wstring cert_name_wstring(const ::CERT_NAME_BLOB * name)
	{
		assert(name);
		
		auto flags = CERT_X500_NAME_STR/* | CERT_NAME_STR_NO_PLUS_FLAG*/;

		auto required = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<::CERT_NAME_BLOB *>(name), flags, nullptr, 0);
		std::wstring result;
		result.resize(required, 0);

		auto written = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<::CERT_NAME_BLOB *>(name), flags, result.data(), required);
		
		// trim zero terminators at end
		while (not result[written - 1])
			--written;
		result.resize(written);

		return result;
	}

	std::string cert_name_reverse_string(const ::CERT_NAME_BLOB * name)
	{
		return to_utf8(cert_name_reverse_wstring(name));
	}

	std::wstring cert_name_reverse_wstring(const ::CERT_NAME_BLOB * name)
	{
		assert(name);
		
		auto flags = CERT_X500_NAME_STR | CERT_NAME_STR_REVERSE_FLAG;

		auto required = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<::CERT_NAME_BLOB *>(name), flags, nullptr, 0);
		std::wstring result;
		result.resize(required, 0);

		auto written = ::CertNameToStrW(X509_ASN_ENCODING, const_cast<::CERT_NAME_BLOB *>(name), flags, result.data(), required);
		
		// trim zero terminators at end
		while (result[written - 1] == 0)
			--written;
		result.resize(written);

		return result;
	}
	
	auto get_notbefore(const ::CERT_CONTEXT * cert) -> std::chrono::system_clock::time_point
	{
		return std::chrono::system_clock::from_time_t(ext::from_filetime(&cert->pCertInfo->NotBefore));
	}
	
	auto get_notafter(const ::CERT_CONTEXT * cert) -> std::chrono::system_clock::time_point
	{
		return std::chrono::system_clock::from_time_t(ext::from_filetime(&cert->pCertInfo->NotAfter));
	}
	
	std::vector<unsigned char> cert_sha1fingerprint(const ::CERT_CONTEXT * cert)
	{
		assert(cert);
		
		std::vector<unsigned char> result;
		DWORD ressize = 20; // SHA1 produces 160-bit (20-byte) hash value
		result.resize(ressize);

		BOOL res = ::CertGetCertificateContextProperty(cert, CERT_HASH_PROP_ID, result.data(), &ressize);
		if (not res) ext::throw_last_system_error("ext::wincrypt::cert_sha1fingerprint: CertGetCertificateContextProperty failed");
		
		assert(ressize == 20);
		//result.resize(ressize);
		return result;
	}
	
	static std::vector<char> read_file(std::FILE * file)
	{
		assert(file);
		
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

	cert_iptr load_certificate(const char * data, std::size_t len)
	{
		assert(data);
		
		DWORD written;
		BOOL res;

		std::vector<unsigned char> der_data;
		der_data.resize(len / 4 * 3);
		written = der_data.size();

		// CRYPT_STRING_ANY is actually try in order: CRYPT_STRING_BASE64HEADER, CRYPT_STRING_BASE64, CRYPT_STRING_BINARY
		// so we will read both PEM(with header and without) and DER encodings
		res = ::CryptStringToBinaryA(data, len, CRYPT_STRING_ANY, der_data.data(), &written, nullptr, nullptr);
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_certificate: CryptStringToBinary failed");

		auto * cert = ::CertCreateCertificateContext(X509_ASN_ENCODING, der_data.data(), written);
		if (not cert)
			ext::throw_last_system_error("ext::wincrypt::load_certificate: CertCreateCertificateContext failed");

		return cert_iptr(cert, ext::noaddref);
	}

	cert_iptr load_certificate_from_file(const char * path)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_certificate(content.data(), content.size());
	}

	cert_iptr load_certificate_from_file(const wchar_t * path)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_certificate(content.data(), content.size());
	}

	cert_iptr load_certificate_from_file(std::FILE * file)
	{
		auto content = read_file(file);
		return load_certificate(content.data(), content.size());
	}

	std::vector<unsigned char> load_rsa_private_key(const char * data, std::size_t len)
	{
		assert(data);
		
		BOOL res;
		DWORD written, pkey_info_length, pkey_rsa_blob_length;
		::CRYPT_PRIVATE_KEY_INFO * pkey_info_ptr = nullptr;
		unsigned char * pkey_rsa_blob_ptr = 0;
		
		hlocal_uptr pkey_info_uptr;
		hlocal_uptr pkey_info_pkey_blob_uptr;
		hlocal_uptr pkey_rsa_blob_uptr;
		
		std::vector<unsigned char> der_data;
		der_data.resize(len / 4 * 3);
		written = der_data.size();
		
		res = ::CryptStringToBinaryA(data, len, CRYPT_STRING_ANY, der_data.data(), &written, nullptr, nullptr);
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptStringToBinary failed");
		
		res = ::CryptDecodeObjectEx(PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
		                            der_data.data(), written,
		                            CRYPT_ENCODE_ALLOC_FLAG, nullptr, &pkey_info_ptr, &pkey_info_length);
		
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptDecodeObjectEx(PKCS_PRIVATE_KEY_INFO) failed while decoding encoded RSA private key");
		
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
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptDecodeObjectEx(PKCS_RSA_PRIVATE_KEY) failed while decoding encoded RSA private key");
		
		return {pkey_rsa_blob_ptr, pkey_rsa_blob_ptr + pkey_rsa_blob_length};
	}


	std::vector<unsigned char> load_rsa_private_key_from_file(const char * path)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_rsa_private_key(content.data(), content.size());
	}

	std::vector<unsigned char> load_rsa_private_key_from_file(const wchar_t * path)
	{
		std::vector<char> content;
		ext::read_file(path, content, std::ios::binary);
		return load_rsa_private_key(content.data(), content.size());
	}

	std::vector<unsigned char> load_rsa_private_key_from_file(std::FILE * file)
	{
		auto content = read_file(file);
		return load_rsa_private_key(content.data(), content.size());
	}
}

#endif // BOOST_OS_WINDOWS
