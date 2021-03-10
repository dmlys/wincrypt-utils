#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <cstdio> // for std::FILE
#include <memory>
#include <string>
#include <vector>
#include <tuple>

#include <ext/intrusive_ptr.hpp>
#include <ext/intrusive_handle.hpp>

struct _CERT_CONTEXT;
typedef _CERT_CONTEXT CERT_CONTEXT;

struct _CRYPTOAPI_BLOB;
typedef _CRYPTOAPI_BLOB CRYPT_INTEGER_BLOB;
typedef _CRYPTOAPI_BLOB CERT_NAME_BLOB;

struct _CRYPT_BIT_BLOB;
typedef _CRYPT_BIT_BLOB CRYPT_BIT_BLOB;

struct _CRYPT_KEY_PROV_INFO;
typedef _CRYPT_KEY_PROV_INFO CRYPT_KEY_PROV_INFO;

typedef std::uintptr_t HCRYPTPROV;
typedef std::uintptr_t HCRYPTKEY;
typedef void * HCERTSTORE;

typedef unsigned int ALG_ID;

namespace ext::wincrypt
{
	class hcrypt_handle_traits
	{
	public:
		static void addref(::HCRYPTPROV hprov) noexcept;
		static void subref(::HCRYPTPROV hprov) noexcept;
		static auto defval(::HCRYPTPROV hprov) noexcept ->::HCRYPTPROV;
	};

	class cert_ptr_traits
	{
	public:
		static void addref(const ::CERT_CONTEXT * pcert) noexcept;
		static void subref(const ::CERT_CONTEXT * pcert) noexcept;
	};

	struct hlocal_deleter { void operator()(void * ptr) const noexcept; };
	struct hkey_deleter { void operator()(::HCRYPTKEY * pkey) const noexcept; };
	struct hcertstore_deleter { void operator()(::HCERTSTORE store) const noexcept; };

	using hlocal_uptr = std::unique_ptr<void, hlocal_deleter>;
	
	using cert_iptr    = ext::intrusive_ptr<const ::CERT_CONTEXT, cert_ptr_traits>;
	using hprov_handle = ext::intrusive_handle<::HCRYPTPROV, hcrypt_handle_traits>;

	using hkey_uptr       = std::unique_ptr<::HCRYPTKEY, hkey_deleter>;
	using hcertstore_uptr = std::unique_ptr<void /*HCERTSTORE*/, hcertstore_deleter>;
	
	using pkey_prov_info_uptr = std::unique_ptr<CRYPT_KEY_PROV_INFO>;

	/// wrapper around CryptAcquireContext
	hprov_handle acquire_provider(const wchar_t * provname, const wchar_t * container, std::uint32_t type, unsigned flags = 0);
	hprov_handle acquire_provider(const char * provname, const char * container, std::uint32_t type, unsigned flags = 0);
	hprov_handle acquire_provider(std::nullptr_t provname, std::nullptr_t container, std::uint32_t type, unsigned flags = 0);

	hprov_handle acquire_rsa_provider(unsigned flags = 0);      // acquire_provider(nullptr, nullptr, PROV_RSA_FULL, flags)
	hprov_handle acquire_rsa_sig_provider(unsigned flags = 0);  // acquire_provider(nullptr, nullptr, PROV_RSA_SIG, flags)
	hprov_handle acquire_dsa_provider(unsigned flags = 0);      // acquire_provider(nullptr, nullptr, PROV_DSS_DH, flags)
	hprov_handle acquire_dsa_sig_provider(unsigned flags = 0);  // acquire_provider(nullptr, nullptr, PROV_DSS, flags)

	std::string provider_name(::HCRYPTPROV prov);
	std::string provider_container(::HCRYPTPROV prov);

	hcertstore_uptr open_system_store(const char * name);
	hcertstore_uptr open_system_store(const wchar_t * name);
	
	/// CryptImportKey wrapper
	/// @Throws system_error in case of errors
	hkey_uptr import_key(::HCRYPTPROV prov, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::HCRYPTKEY decryption_key = 0);

	// https://stackoverflow.com/questions/4191312/windows-cryptoapi-cryptsignhash-with-calg-sha-256-and-private-key-from-my-keyst
	// how to reopen private key that is associated with some certificate in store and is with bound Microsoft Base crypto provider(does not support SHA2)
	// with different provider(MS_ENH_RSA_AES_PROV)

	/// Loads X509 certificate from given memory location and with optional password(password probably will never be used).
	/// Certificate expected to be in usual PEM or DER format
	/// Throws std::system_error in case of errors
	cert_iptr load_certificate(const char * data, std::size_t len, std::string_view passwd = "");
	cert_iptr load_certificate_from_file(const char * path, std::string_view passwd = "");
	cert_iptr load_certificate_from_file(const wchar_t * path, std::string_view passwd = "");
	cert_iptr load_certificate_from_file(std::FILE * file, std::string_view passwd = "");

	inline cert_iptr load_certificate(std::string_view str, std::string_view passwd = "") { return load_certificate(str.data(), str.size(), passwd); }

	/// loads private key from given memory location and with optional password.
	/// private key expected to be in usual PEM or DER format
	/// Throws std::system_error in case of errors
	/// NOTE: this method loads key in PKCS#8 format, identified by header -----BEGIN PRIVATE KEY-----
	///        -----BEGIN RSA PRIVATE KEY----- is PKCS#1 and should be loaded via different method
	/// https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
	/// https://stackoverflow.com/a/20065522/1682317
	/// NOTE: passwords not supported yet,
	///       key is placed into provider, and can be later retrieved via CryptGetUserKey,
	///       also key returned by this function
	hkey_uptr load_private_key(::HCRYPTPROV prov, const char * data, std::size_t len, std::string_view passwd = "");
	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, const char * path, std::string_view passwd = "");
	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, const wchar_t * path, std::string_view passwd = "");
	hkey_uptr load_private_key_from_file(::HCRYPTPROV prov, std::FILE * file, std::string_view passwd = "");

	inline hkey_uptr load_private_key(::HCRYPTPROV prov, std::string_view str, std::string_view passwd = "") { return load_private_key(prov, str.data(), str.size(), passwd); }
		
	/// obtains algorithm id for given key, see:
	/// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetkeyparam
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
	/// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certoidtoalgid
	ALG_ID get_algid(::HCRYPTKEY key);

	/// obtains keyspec(AT_KEYEXCHANGE or AT_SIGNATURE) that this key is presumably have in corresponding HPROV.
	/// this done by inspecting key ALG_ID:
	///   CALG_RSA_KEYX -> AT_KEYEXCHANGE
	///   CALG_RSA_SIGN -> AT_SIGNATURE
	///   CALG_DH_SF    -> AT_KEYEXCHANGE
	///   CALG_DSS_SIGN -> AT_SIGNATURE
	std::uint32_t get_keyspec(::HCRYPTKEY key);

	/// simple wrapper around CryptAcquireCertificatePrivateKey function:
	/// calls CryptAcquireCertificatePrivateKey(cert, 0, nullptr, ...);
	/// if hwnd specified - calls with CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
	///                                                                                                  hprov         key spec
	auto acquire_certificate_private_key(const CERT_CONTEXT * cert, void * hwnd = nullptr) -> std::tuple<hprov_handle, std::uint32_t>;

	/// obtains private key provider info for given certificate, basicly a a wrapper for 
	/// CertGetCertificateContextProperty with CERT_KEY_PROV_INFO_PROP_ID
	pkey_prov_info_uptr get_provider_info(const CERT_CONTEXT * cert);
	

	struct rsapubkey_info
	{
		// everything is little-endian
		std::size_t exponent;
		std::vector<unsigned char> modulus;
	};

	rsapubkey_info extract_rsapubkey_numbers(const CERT_CONTEXT * rsaCert);
	rsapubkey_info extract_rsapubkey_numbers(const CRYPT_BIT_BLOB * rsaPublicKeyBlob);

	std::string X509_name_string(const CERT_NAME_BLOB * name);
	std::string X509_name_reverse_string(const CERT_NAME_BLOB * name);

	std::wstring X509_name_u16string(const CERT_NAME_BLOB * name);
	std::wstring X509_name_reverse_u16string(const CERT_NAME_BLOB * name);


	/// simple wrapper around CryptUIDlgSelectCertificateFromStore
	cert_iptr select_certificate_from_store(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title = nullptr, const wchar_t * display_string = nullptr);
}

#endif // BOOST_OS_WINDOWS
