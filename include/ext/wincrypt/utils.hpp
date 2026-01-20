#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <cstdio> // for std::FILE
#include <memory>
#include <string>
#include <vector>
#include <tuple>
#include <chrono>
#include <functional>

#include <ext/unique_handle.hpp>
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

#if _WIN64
typedef std::uintptr_t HCRYPTPROV;
typedef std::uintptr_t HCRYPTKEY;
#else
typedef unsigned long HCRYPTPROV;
typedef unsigned long HCRYPTKEY;
#endif

typedef void * HCERTSTORE;

typedef unsigned int ALG_ID;


namespace ext::wincrypt
{
	class hcrypt_handle_traits
	{
	public:
		static void addref(::HCRYPTPROV hprov) noexcept;
		static void subref(::HCRYPTPROV hprov) noexcept;
		static auto defval(::HCRYPTPROV hprov) noexcept -> ::HCRYPTPROV;
	};

	class cert_ptr_traits
	{
	public:
		static void addref(const ::CERT_CONTEXT * pcert) noexcept;
		static void subref(const ::CERT_CONTEXT * pcert) noexcept;
	};
	
	class hkey_handle_traits
	{
	public:
		static void close(::HCRYPTKEY key) noexcept;
		static auto emptyval() noexcept -> ::HCRYPTKEY { return 0; }
	};

	struct hlocal_deleter { void operator()(void * ptr) const noexcept; };
	struct hcertstore_deleter { void operator()(::HCERTSTORE store) const noexcept; };

	using hlocal_uptr = std::unique_ptr<void, hlocal_deleter>;
	
	using cert_iptr    = ext::intrusive_ptr<const ::CERT_CONTEXT, cert_ptr_traits>;
	using hprov_handle = ext::intrusive_handle<::HCRYPTPROV, hcrypt_handle_traits>;

	using hkey_handle     = ext::unique_handle<::HCRYPTKEY, hkey_handle_traits>;
	using hcertstore_uptr = std::unique_ptr<void /*HCERTSTORE*/, hcertstore_deleter>;
	
	using pkey_prov_info_uptr = std::unique_ptr<::CRYPT_KEY_PROV_INFO, hlocal_deleter>;
	
	/************************************************************************/
	/*                     HCRYPTPROV basic stuff                           */
	/************************************************************************/
	// NOTE:
	//   https://stackoverflow.com/questions/4191312/windows-cryptoapi-cryptsignhash-with-calg-sha-256-and-private-key-from-my-keyst
	//   how to reopen private key that is associated with some certificate in store and is bound with Microsoft Base crypto provider(does not support SHA2)
	//   with different provider(MS_ENH_RSA_AES_PROV)
	
	
	/// wrapper around CryptAcquireContext
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptographic-provider-types
	/// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
	/// 
	/// provname  - A null-terminated string that contains the name of the CSP to be used.
	///             If this parameter is NULL, the user default provider is used.
	/// container - The key container name, for CRYPT_VERIFYCONTEXT should be null
	/// type      - provider type. Interesting types: PROV_RSA_FULL, PROV_RSA_AES
	/// 
	/// flags:
	///  CRYPT_VERIFYCONTEXT  - This option is intended for applications that are using ephemeral keys,
	///                         or applications that do not require access to persisted private keys
	///  CRYPT_NEWKEYSET      - Creates a new key container with the name specified by container.
	///                         If container is NULL, a key container with the default name is created. 
	///  CRYPT_MACHINE_KEYSET - By default, keys and key containers are stored as user keys.
	///  CRYPT_DELETEKEYSET   - Delete the key container specified by pszContainer. 
	///                         If container is NULL, the key container with the default name is deleted.
	///                         All key pairs in the key container are also destroyed. 
	///  CRYPT_SILENT         - The application requests that the CSP not display any user interface (UI) for this context.
	///                         If the CSP must display the UI to operate, the call fails and the NTE_SILENT_CONTEXT error code is set as the last error.
	/// 
	/// interesting provider names:
	///   MS_DEF_PROV      - Microsoft Base Cryptographic Provider;     type = PROV_RSA_FULL
	///                      https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-base-cryptographic-provider
	///   MS_ENHANCED_PROV - Microsoft Enhanced Cryptographic Provider; type = PROV_RSA_FULL
	///                      https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-enhanced-cryptographic-provider
	///   MS_STRONG_PROV   - Microsoft Strong Cryptographic Provider;   type = PROV_RSA_FULL
	///                      https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-strong-cryptographic-provider
	/// 
	///   MS_ENH_RSA_AES_PROV    - Microsoft AES Cryptographic Provider; type = PROV_RSA_AES
	///                            https://docs.microsoft.com/en-us/windows/win32/seccrypto/microsoft-aes-cryptographic-provider
	///   MS_ENH_RSA_AES_PROV_XP - Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype); type = PROV_RSA_AES
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
	
	/// same as WinAPI PROV_ENUMALGS but defined here as separate struct to avoid including WinAPI headers
	struct prov_alg
	{
		ALG_ID       algid;
		unsigned int bitlen;
		std::string  name;
	};
	
	/// CryptGetProvParam + PP_ENUMALGS wrapper
	std::vector<prov_alg> enum_provider_algorithms(::HCRYPTPROV hprov);
	
	/// CryptGetUserKey wrapper
	/// Throws system_error in case of errors
	hkey_handle get_user_key(::HCRYPTPROV prov, unsigned keyspec);
	
	/// CryptImportKey wrapper
	/// Throws system_error in case of errors
	hkey_handle import_key(::HCRYPTPROV prov, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::HCRYPTKEY decryption_key = 0);
	/// CryptExportKey wrapper
	/// Throws system_error in case of errors
	std::vector<unsigned char> export_key(::HCRYPTKEY key, unsigned blobType, unsigned flags, ::HCRYPTKEY encryption_key = 0);
	
	/// export_key with PRIVATEKEYBLOB
	std::vector<unsigned char> export_rsa_private_key(::HCRYPTKEY key, unsigned flags = 0, ::HCRYPTKEY encryption_key = 0);
	/// export_key with PUBLICKEYBLOB
	std::vector<unsigned char> export_rsa_public_key(::HCRYPTKEY key, unsigned flags = 0);
	
	/// obtains algorithm id for given key, see:
	/// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgetkeyparam
	/// https://docs.microsoft.com/en-us/windows/win32/seccrypto/alg-id
	/// https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certoidtoalgid
	::ALG_ID get_algid(::HCRYPTKEY key);
	
	/// translates ALG_ID to keyspec(AT_KEYEXCHANGE or AT_SIGNATURE)
	/// this done by inspecting key ALG_ID:
	///   CALG_RSA_KEYX -> AT_KEYEXCHANGE
	///   CALG_RSA_SIGN -> AT_SIGNATURE
	///   CALG_DH_SF    -> AT_KEYEXCHANGE
	///   CALG_DSS_SIGN -> AT_SIGNATURE
	///  Otherwise throws std::runtime_error
	std::uint32_t translate_keyspec(::ALG_ID algid);

	/// obtains keyspec(AT_KEYEXCHANGE or AT_SIGNATURE) that this key is presumably have in corresponding HPROV.
	/// this done by inspecting key ALG_ID:
	///   CALG_RSA_KEYX -> AT_KEYEXCHANGE
	///   CALG_RSA_SIGN -> AT_SIGNATURE
	///   CALG_DH_SF    -> AT_KEYEXCHANGE
	///   CALG_DSS_SIGN -> AT_SIGNATURE
	///  Otherwise throws std::runtime_error
	inline std::uint32_t get_keyspec(::HCRYPTKEY key) { return translate_keyspec(get_algid(key)); }
	
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
	
	/// Adds certificate to a given store, adding makes a duplicate and it is returned.
	/// Basicly wrapper CertAddEncodedCertificateToStore 
	/// Throws system_error in case of errors
	auto add_certificate(::HCERTSTORE cert_store, const unsigned char * data, std::size_t data_size, unsigned disposition = -1/*CERT_STORE_ADD_NEW*/) -> cert_iptr;
	/// Adds certificate to a given store, adding makes a duplicate and it is returned.
	/// Basicly wrapper CertAddEncodedCertificateToStore, data is taken from cert structure
	/// Throws system_error in case of errors
	auto add_certificate(::HCERTSTORE cert_store, const ::CERT_CONTEXT * cert, unsigned disposition = -1/*CERT_STORE_ADD_NEW*/) -> cert_iptr;	
	/// Deletes certificate from store. Wrapper around CertDeleteCertificateFromStore.
	/// The CertDeleteCertificateFromStore function always frees pCertContext by calling the CertFreeCertificateContext function, even if an error is encountered.
	/// Thats why this function takes cert by smart pointer.
	/// Throws system_error in case of errors
	void delete_certificate(cert_iptr cert);
	
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
	
	/// Searches certificate in store with given hash property: CERT_FIND_SHA1_HASH, CERT_FIND_MD5_HASH, etc.
	/// Basicly wrapper for CertFindCertificateInStore with given find_type for hash value(CRYPT_HASH_BLOB)
	auto find_certificate_by_hash(::HCERTSTORE cert_store, unsigned int find_type, const unsigned char * hash_data, std::size_t hash_size) -> cert_iptr;
	/// Searches certificate in store with given SHA1 fingerprint.
	/// Basicly wrapper for CertFindCertificateInStore with CERT_FIND_SHA1_HASH
	auto find_certificate_by_sha1fingerprint(::HCERTSTORE cert_store, const unsigned char * fp_data, std::size_t fp_size) -> cert_iptr;
	/// Searches certificate in store with given SHA1 fingerprint.
	/// Basicly wrapper for CertFindCertificateInStore with CERT_FIND_SHA1_HASH
	inline auto find_certificate_by_sha1fingerprint(::HCERTSTORE cert_store, const std::vector<unsigned char> & fingerprint) -> cert_iptr
	{ return find_certificate_by_sha1fingerprint(cert_store, fingerprint.data(), fingerprint.size()); }
	
	
	/// Adds certificate to store. Basicly a CertAddCertificateContextToStore wrapper
	/// Throws system_error in case of errors
	cert_iptr import_certificate(::HCERTSTORE cert_store, const ::CERT_CONTEXT * cert, unsigned dispositionFlags);
	
	/************************************************************************/
	/*               HCRYPTPROV and certificate connection stuff            */
	/************************************************************************/
	/// Prints private key provider info: provider name, container name, etc
	std::string dump_cryptkey_provider_info(const ::CRYPT_KEY_PROV_INFO * prov_info, std::string_view ident = "");
	
	/// obtains private key provider info for given certificate,
	/// basicly a wrapper for CertGetCertificateContextProperty with CERT_KEY_PROV_INFO_PROP_ID.
	/// If not info exists for certificate - returns null.
	/// Throws system_error in case of errors
	auto get_provider_info(const ::CERT_CONTEXT * cert) -> pkey_prov_info_uptr;
	/// sets private key provider info for given certificate, effectively associating private key with certificate
	/// basicly a wrapper for CertSetCertificateContextProperty with CERT_KEY_PROV_INFO_PROP_ID
	/// Throws system_error in case of errors
	void set_provider_info(const ::CERT_CONTEXT * cert, const ::CRYPT_KEY_PROV_INFO * prov_info);
	
	/// Associates key with certificate with set_provider_info call.
	/// This association is persistent, further calls to acquire_certificate_private_key will return this key
	/// Throws system_error in case of errors
	void bound_certificate_with_private_key(const ::CERT_CONTEXT * cert, ::HCRYPTPROV prov, unsigned keyspec);
	/// Removes any association of given certificate with private key, if any
	/// Throws system_error in case of errors
	inline void unbound_certificate(const ::CERT_CONTEXT * cert) { return set_provider_info(cert, nullptr); }
	
	/// simple wrapper around CryptAcquireCertificatePrivateKey function:
	/// calls CryptAcquireCertificatePrivateKey(cert, 0, nullptr, ...);
	/// if hwnd specified - calls with CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
	///                                                                                                  hprov         key spec
	auto acquire_certificate_private_key(const ::CERT_CONTEXT * cert, void * hwnd = nullptr) -> std::tuple<hprov_handle, std::uint32_t>;
	

	/************************************************************************/
	/*               Certificate info stuff                                 */
	/************************************************************************/
	
	struct rsapubkey_info
	{
		// everything is little-endian
		std::size_t exponent;
		std::vector<unsigned char> modulus;
	};

	rsapubkey_info extract_rsapubkey_numbers(const ::CERT_CONTEXT * rsaCert);
	rsapubkey_info extract_rsapubkey_numbers(const ::CRYPT_BIT_BLOB * rsaPublicKeyBlob);

	std::string cert_name_string(const ::CERT_NAME_BLOB * name);
	std::string cert_name_reverse_string(const ::CERT_NAME_BLOB * name);

	std::wstring cert_name_wstring(const ::CERT_NAME_BLOB * name);
	std::wstring cert_name_reverse_wstring(const ::CERT_NAME_BLOB * name);
	
	/// Gets certificate not before property as std::chrono::system_clock::time_point
	auto get_notbefore(const ::CERT_CONTEXT * cert) -> std::chrono::system_clock::time_point;
	/// Gets certificate not after property as std::chrono::system_clock::time_point
	auto get_notafter(const ::CERT_CONTEXT * cert) -> std::chrono::system_clock::time_point;
	
	/// Returns certificate SHA1 fingerprint, calculates if needed.
	/// Basicly wrapper for CertGetCertificateContextProperty + CERT_HASH_PROP_ID.
	/// Throws std::system_error in case of errors
	std::vector<unsigned char> cert_sha1fingerprint(const ::CERT_CONTEXT * cert);
	
	/************************************************************************/
	/*   Certificate and private key loading from memory and files          */
	/************************************************************************/
	
	/// Loads X509 certificate from given memory location
	/// Certificate expected to be in usual PEM or DER format
	/// Throws std::system_error in case of errors
	cert_iptr load_certificate(const char * data, std::size_t len);
	cert_iptr load_certificate_from_file(const char * path);
	cert_iptr load_certificate_from_file(const wchar_t * path);
	cert_iptr load_certificate_from_file(std::FILE * file);

	inline cert_iptr load_certificate(std::string_view str) { return load_certificate(str.data(), str.size()); }

	/// loads RSA private key from given memory location, private key is expected to be unencrypted(no password protection)
	/// private key expected to be in usual PEM or DER format
	/// Throws std::system_error in case of errors
	/// NOTE: this method loads key in PKCS#8 format, identified by header -----BEGIN PRIVATE KEY-----
	///        -----BEGIN RSA PRIVATE KEY----- is PKCS#1 and should be loaded via different method
	/// https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
	/// https://stackoverflow.com/a/20065522/1682317
	/// NOTE: key is placed into private key blob and can be later imported into provider via CryptImportKey function
	std::vector<unsigned char> load_rsa_private_key(const char * data, std::size_t len);
	std::vector<unsigned char> load_rsa_private_key_from_file(const char * path);
	std::vector<unsigned char> load_rsa_private_key_from_file(const wchar_t * path);
	std::vector<unsigned char> load_rsa_private_key_from_file(std::FILE * file);

	inline std::vector<unsigned char> load_rsa_private_key_from_file(std::string_view str) { return load_rsa_private_key(str.data(), str.size()); }
}

#endif // BOOST_OS_WINDOWS
