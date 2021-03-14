#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <cstdio> // for std::FILE
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include <functional>

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

	/************************************************************************/
	/*                     HCRYPTPROV basic stuff                           */
	/************************************************************************/
	/// wrapper around CryptAcquireContext
	hprov_handle acquire_provider(const wchar_t * provname, const wchar_t * container, std::uint32_t type, unsigned flags = 0);
	hprov_handle acquire_provider(const char * provname, const char * container, std::uint32_t type, unsigned flags = 0);
	hprov_handle acquire_provider(std::nullptr_t provname, std::nullptr_t container, std::uint32_t type, unsigned flags = 0);

	hprov_handle acquire_rsa_provider(unsigned flags = 0);      // acquire_provider(nullptr, nullptr, PROV_RSA_FULL, flags)
	hprov_handle acquire_dsa_provider(unsigned flags = 0);      // acquire_provider(nullptr, nullptr, PROV_DSS_DH, flags)

	/// CryptGetProvParam + PP_NAME/PP_CONTAINER wrapper
	std::string provider_name(::HCRYPTPROV prov);
	std::string provider_container(::HCRYPTPROV prov);
	/// CryptGetProvParam + PP_NAME/PP_CONTAINER wrapper
	std::wstring provider_wname(::HCRYPTPROV prov);
	std::wstring provider_wcontainer(::HCRYPTPROV prov);
	// CryptGetProvParam + PP_PROVTYPE wrapper
	unsigned provider_type(::HCRYPTPROV prov);
	
	/// CryptGetUserKey wrapper
	/// Throws system_error in case of errors
	hkey_uptr get_user_key(::HCRYPTPROV prov, unsigned keyspec);
	
	/// CryptImportKey wrapper
	/// Throws system_error in case of errors
	hkey_uptr import_key(::HCRYPTPROV prov, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::HCRYPTKEY decryption_key = 0);
	/// CryptExportKey wrapper
	/// Throws system_error in case of errors
	std::vector<unsigned char> export_key(::HCRYPTKEY key, unsigned blobType, unsigned flags, ::HCRYPTKEY encryption_key = 0);
	
	/// export_key with PRIVATEKEYBLOB
	std::vector<unsigned char> export_private_key(::HCRYPTKEY key, unsigned flags = 0, ::HCRYPTKEY encryption_key = 0);
	/// export_key with PUBLICKEYBLOB
	std::vector<unsigned char> export_public_key(::HCRYPTKEY key, unsigned flags = 0);
	
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
	
	/************************************************************************/
	/*               HCERTSTORE and search certificate stuff                */
	/************************************************************************/
	
	/// Enumerates system stores names via CertEnumSystemStore,
	/// returns system store names
	std::vector<std::string>  system_store_names(unsigned flags);
	std::vector<std::wstring> system_store_wnames(unsigned flags);
	/// Enumerates system stores names via CertEnumSystemStore with flags = CERT_SYSTEM_STORE_CURRENT_USER,
	/// returns system store names
	std::vector<std::string>  system_store_names();
	std::vector<std::wstring> system_store_wnames();
	
	/// CertOpenSystemStore wrapper
	/// Throws system_error in case of errors
	hcertstore_uptr open_system_store(const char * name);
	hcertstore_uptr open_system_store(const wchar_t * name);
	
	/// Gets all certificates from store,
	/// basicly wrapper for CertFindCertificateInStore with findType = CERT_FIND_ANY
	/// Throws system_error in case of errors
	auto get_certificates(::HCERTSTORE cert_store) -> std::vector<cert_iptr>;
	/// Searches first certificate in store whose subject contains given substring,
	/// basicly wrapper for CertFindCertificateInStore with findType = CERT_FIND_SUBJECT_STR
	/// Throws system_error in case of errors
	auto find_first_certificate_by_subject(::HCERTSTORE cert_store, std::string_view subject) -> cert_iptr;
	/// Searches all certificates in store whose subject contains given substring,
	/// basicly wrapper for CertFindCertificateInStore with findType = CERT_FIND_SUBJECT_STR
	/// Throws system_error in case of errors
	auto find_certificates_by_subject(::HCERTSTORE cert_store, std::string_view subject) -> std::vector<cert_iptr>;
	
	/// Adds certificate to store. Basicly a CertAddCertificateContextToStore wrapper
	/// Throws system_error in case of errors
	cert_iptr import_certificate(::HCERTSTORE cert_store, const ::CERT_CONTEXT * cert, unsigned dispositionFlags);
	
	/************************************************************************/
	/*               HCRYPTPROV and certificate connection stuff            */
	/************************************************************************/
	
	/// obtains private key provider info for given certificate,
	/// basicly a wrapper for CertGetCertificateContextProperty with CERT_KEY_PROV_INFO_PROP_ID.
	/// If not info exists for certificate - returns null.
	/// Throws system_error in case of errors
	auto get_provider_info(const CERT_CONTEXT * cert) -> pkey_prov_info_uptr;
	/// sets private key provider info for given certificate, effectively associating private key with certificate
	/// basicly a wrapper for CertSetCertificateContextProperty with CERT_KEY_PROV_INFO_PROP_ID
	/// Throws system_error in case of errors
	void set_provider_info(const CERT_CONTEXT * cert, const CRYPT_KEY_PROV_INFO * prov_info);
	
	/// Associates key with certificate with set_provider_info call.
	/// This association is persistent, further calls to acquire_certificate_private_key will return this key
	/// Throws system_error in case of errors
	void bound_certificate_with_private_key(const CERT_CONTEXT * cert, ::HCRYPTPROV prov, unsigned keyspec);
	/// Removes any association of given certificate with private key, if any
	/// Throws system_error in case of errors
	inline void unbound_certificate(const CERT_CONTEXT * cert) { return set_provider_info(cert, nullptr); }
	
	/// simple wrapper around CryptAcquireCertificatePrivateKey function:
	/// calls CryptAcquireCertificatePrivateKey(cert, 0, nullptr, ...);
	/// if hwnd specified - calls with CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
	///                                                                                                  hprov         key spec
	auto acquire_certificate_private_key(const CERT_CONTEXT * cert, void * hwnd = nullptr) -> std::tuple<hprov_handle, std::uint32_t>;
	

	/************************************************************************/
	/*               Certificate info stuff                                 */
	/************************************************************************/
	
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

	std::wstring X509_name_wstring(const CERT_NAME_BLOB * name);
	std::wstring X509_name_reverse_wstring(const CERT_NAME_BLOB * name);
	
	
	/************************************************************************/
	/*   Certificate and private key loading from memory and files          */
	/************************************************************************/
	
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
	///       key is placed into private key blob and can be later imported into provider via CryptImportKey function
	std::vector<unsigned char> load_private_key(const char * data, std::size_t len, std::string_view passwd = "");
	std::vector<unsigned char> load_private_key_from_file(const char * path, std::string_view passwd = "");
	std::vector<unsigned char> load_private_key_from_file(const wchar_t * path, std::string_view passwd = "");
	std::vector<unsigned char> load_private_key_from_file(std::FILE * file, std::string_view passwd = "");

	inline std::vector<unsigned char> load_private_key(std::string_view str, std::string_view passwd = "") { return load_private_key(str.data(), str.size(), passwd); }
}

#endif // BOOST_OS_WINDOWS
