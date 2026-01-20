#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <cstdio> // for std::FILE
#include <memory>
#include <string>
#include <vector>
#include <optional>

#include <ext/unique_handle.hpp>
#include <ext/intrusive_ptr.hpp>
#include <ext/intrusive_handle.hpp>

#include <ext/wincrypt/utils.hpp>


#if _WIN64
typedef std::uintptr_t NCRYPT_HANDLE;
typedef std::uintptr_t NCRYPT_PROV_HANDLE;
typedef std::uintptr_t NCRYPT_KEY_HANDLE;
#else
typedef unsigned long NCRYPT_HANDLE;
typedef unsigned long NCRYPT_PROV_HANDLE;
typedef unsigned long NCRYPT_KEY_HANDLE;
#endif

// Some articles about CNG
// https://learn.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
// https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-and-retrieval
// https://learn.microsoft.com/en-us/windows/win32/seccng/cryptographic-primitives
//
// https://stackoverflow.com/questions/40596395/cng-when-to-use-bcrypt-vs-ncrypt-family-of-functions

namespace ext::wincrypt::ncrypt
{
	class prov_handle_traits
	{
	public:
		static void close(::NCRYPT_PROV_HANDLE hprov) noexcept;
		static auto emptyval() noexcept -> ::NCRYPT_PROV_HANDLE { return 0; }
	};
	
	class key_handle_traits
	{
	public:
		static void close(::NCRYPT_PROV_HANDLE hprov) noexcept;
		static auto emptyval() noexcept -> ::NCRYPT_PROV_HANDLE { return 0; }
	};
	
	struct buffer_deleter { void operator()(void * ptr) const noexcept; }; 
	
	using prov_handle = ext::unique_handle<NCRYPT_PROV_HANDLE, prov_handle_traits>;
	using key_handle  = ext::unique_handle<NCRYPT_KEY_HANDLE, key_handle_traits>;
	
	/************************************************************************/
	/*                NCRYPT_HANDLE property helpers                        */
	/************************************************************************/
	/// NCryptGetProperty wrapper for querying string properties.
	/// For NTE_NOT_SUPPORTED returns std::nullopt.
	/// Throws system_error in case of errors.
	std::optional<std:: string> get_string_property (::NCRYPT_HANDLE handle, const wchar_t * propname);
	std::optional<std::wstring> get_wstring_property(::NCRYPT_HANDLE handle, const wchar_t * propname);
	
	/// NCryptSetProperty wrapper for string properties.
	/// Throws system_error in case of errors.
	void set_string_property (::NCRYPT_HANDLE handle, const wchar_t * propname, std::string_view  str);
	void set_wstring_property(::NCRYPT_HANDLE handle, const wchar_t * propname, std::wstring_view str);
	
	/// NCryptGetProperty wrapper for querying properties with known size in advance.
	/// For NTE_NOT_SUPPORTED returns false, for other errors throws system_error.
	/// Throws system_error in case of errors.
	bool get_property(::NCRYPT_HANDLE handle, const wchar_t * propname, void * dest, std::size_t dest_size);
	/// NCryptSetProperty wrapper for setting properties with known size in advance.
	/// Throws system_error in case of errors.
	void set_property(::NCRYPT_HANDLE handle, const wchar_t * propname, const void * prop, std::size_t prop_size);
	/// nullptr overload for set_property - basically delete property.
	/// Throws system_error in case of errors.
	inline void set_property(::NCRYPT_HANDLE handle, const wchar_t * propname, std::nullptr_t)
	{ return set_property(handle, nullptr, 0); }
	
	/// NCryptGetProperty wrapper for querying scalar properties.
	template <class Type>
	inline std::optional<Type> get_scalar_property(::NCRYPT_HANDLE handle, const wchar_t * propname)
	{
		static_assert(std::is_scalar<Type>::value);
		
		Type result;
		bool res = get_property(handle, propname, &result, sizeof result);
		if (res)
			return result;
		else
			return std::nullopt;
	}
	
	/// NCryptSetProperty wrapper for setting scalar properties.
	template <class Type>
	inline void set_scalar_property(::NCRYPT_HANDLE handle, const wchar_t * propname, Type val)
	{
		return set_property(handle, propname, &val, sizeof val);
	}
	
	/// NCryptSetProperty wrapper for setting scalar properties.
	template <class Type>
	inline void set_scalar_property(::NCRYPT_HANDLE handle, const wchar_t * propname, const std::optional<Type> & val)
	{
		if (val)
			return set_property(handle, propname, &*val, sizeof *val);
		else
			return set_property(handle, propname, nullptr);
	}
	
	/// NCryptGetProperty  + NCRYPT_NAME_PROPERTY wrapper
	/// For NTE_NOT_SUPPORTED returns <null>, for other errors throws system_error.
	std::string   name_property(::NCRYPT_HANDLE handle);
	/// NCryptGetProperty  + NCRYPT_NAME_PROPERTY wrapper
	/// For NTE_NOT_SUPPORTED returns <null>, for other errors throws system_error.
	std::wstring wname_property(::NCRYPT_HANDLE handle);
		
	/************************************************************************/
	/*                NCRYPT_PROV_HANDLE  basic stuff                       */
	/************************************************************************/	
	/// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
	/// 
	/// NCryptOpenStorageProvider wrapper
	/// 
	/// provider name:
	///   A pointer to a null-terminated Unicode string that identifies the key storage provider to load.
	///   This is the registered alias of the key storage provider. This parameter is optional and can be NULL.
	///   If this parameter is NULL, the default key storage provider is loaded.
	///   The following values identify the built-in key storage providers.
	///
	/// provider names: 
	///   MS_KEY_STORAGE_PROVIDER -   L"Microsoft Software Key Storage Provider".
	///                               Identifies the software key storage provider that is provided by Microsoft. 
	/// 
	///   MS_SMART_CARD_KEY_STORAGE_PROVIDER - L"Microsoft Smart Card Key Storage Provider"
	///                                        Identifies the smart card key storage provider that is provided by Microsoft. 
	/// 
	///   MS_PLATFORM_CRYPTO_PROVIDER - L"Microsoft Platform Crypto Provider"
	///                                 Identifies the TPM key storage provider that is provided by Microsoft.
	/// Throws system_error in case of errors
	prov_handle open_storage_provider(const wchar_t * provname);
	prov_handle open_storage_provider(const char * provname);
	inline prov_handle open_storage_provider(std::nullptr_t provname) { return open_storage_provider(static_cast<const wchar_t *>(provname)); }
	
	
	/// same as CNG NCrypt NCryptAlgorithmName but defined here as separate struct to avoid including WinAPI headers
	struct enum_prov_algorithm_name
	{
		std::string name;             /// name of the algorithm
		unsigned long alg_class;      /// defines which algorithm class this algorithm belongs to.
		unsigned long alg_operations; /// defines which operational classes this algorithm belongs to.
		unsigned long flags;          /// A set of flags that provide more information about the algorithm.
	};
	
	/// same as CNG NCrypt NCryptKeyName but defined here as separate struct to avoid including WinAPI headers
	struct enum_prov_key_name
	{
		std::string name;  // name of the key.
		std::string algid; // identifier of the cryptographic algorithm that the key was created with.
		unsigned keyspec;  // AT_KEYEXCHANGE, AT_SIGNATURE or 0
		unsigned flags;    // can be NCRYPT_MACHINE_KEY_FLAG
	};
	
	/// NCryptEnumAlgorithms wrapper
	///   alg_operations - A set of values that determine which algorithm classes to enumerate. If zero, all algorithms are enumerated.
	///   flags - can be NCRYPT_SILENT_FLAG
	/// Throws system_error in case of errors
	std::vector<enum_prov_algorithm_name> enum_provider_algorithms(::NCRYPT_PROV_HANDLE hprov, unsigned long alg_operations = 0, unsigned flags = 0);
	/// NCryptEnumKeys wrapper
	///  flags - can be NCRYPT_MACHINE_KEY_FLAG, NCRYPT_SILENT_FLAG
	///  scope - unused and should always be nullptr
	/// Throws system_error in case of errors
	std::vector<enum_prov_key_name> enum_provider_keys(::NCRYPT_PROV_HANDLE hprov, unsigned flags, const wchar_t * scope = nullptr);
	
	
	/// NCryptGetProperty  + NCRYPT_NAME_PROPERTY wrapper  for ncrypt storage provider handle(NCryptOpenStorageProvider and others)
	/// For NTE_NOT_SUPPORTED returns <null>, for other errors throws system_error.
	inline std:: string provider_name(::NCRYPT_PROV_HANDLE hprov) { return name_property(hprov); }
	inline std::wstring provider_wname(::NCRYPT_PROV_HANDLE hprov) { return wname_property(hprov); }
	
	/// NCryptGetProperty  + NCRYPT_NAME_PROPERTY wrapper  for ncrypt key, this is same as CryptGetProvParam + PP_NAME/PP_CONTAINER for legacy providers
	/// For NTE_NOT_SUPPORTED returns <null>, for other errors throws system_error.
	inline std:: string container_name(::NCRYPT_KEY_HANDLE hkey) { return name_property(hkey); }
	inline std::wstring container_wname(::NCRYPT_KEY_HANDLE hkey) { return wname_property(hkey); }
	
	/// NCryptGetProperty  + NCRYPT_PROVIDER_HANDLE_PROPERTY wrapper
	/// Throws system_error in case of errors, including NTE_NOT_SUPPORTED - key must have a crypto provider
	prov_handle provider_handle(::NCRYPT_KEY_HANDLE hkey);
	
	
	/// NCryptOpenKey wrapper
	///   key name - A pointer to a null-terminated Unicode string that contains the name of the key to retrieve.
	///              This is same(well it looks like) as container name in CAPI.
	///   flags can be:
	///     NCRYPT_MACHINE_KEY_FLAG - Open the key for the local computer. If this flag is not present, the current user key is opened. 
	///     NCRYPT_SILENT_FLAG - Requests that the key storage provider (KSP) not display any user interface
	///   keyspec is either:
	///     0 or AT_KEYEXCHANGE, AT_SIGNATURE.
	///     For CNG keys it should be 0(in practice always).
	/// 
	/// Throws system_error in case of errors
	key_handle open_key(::NCRYPT_PROV_HANDLE hprov, const wchar_t * keyname, unsigned flags, unsigned keyspec = 0);
	key_handle open_key(::NCRYPT_PROV_HANDLE hprov, const  char   * keyname, unsigned flags, unsigned keyspec = 0);
	
	/// NCryptImportKey wrapper
	///   hprov - The handle of the key storage provider.
	///   key name - A pointer to a null-terminated Unicode string that contains the name of the key to retrieve.
	///              This is same(well it looks like) as container name in CAPI.
	///   blob_type - type of a blob
	///   blob_buffer, buffer_size - key blob
	///   flags - flags, some flags are provider specific, for MS_KEY_STORAGE_PROVIDER additional flags can be:
	///     NCRYPT_NO_KEY_VALIDATION, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG, NCRYPT_DO_NOT_FINALIZE_FLAG
	/// 
	/// MSDN blob description:
	/// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
	/// 
	/// NOTE: For MS_KEY_STORAGE_PROVIDER if keyname is null - key is treated as ephemeral and is not stored persistently.
	/// 
	/// Throws system_error in case of errors
	key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const wchar_t * keyname, const wchar_t * blob_type, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::NCRYPT_KEY_HANDLE decryption_key = 0);
	key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const  char   * keyname, const wchar_t * blob_type, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::NCRYPT_KEY_HANDLE decryption_key = 0);
	inline key_handle import_key(::NCRYPT_PROV_HANDLE hprov, nullptr_t keyname, const wchar_t * blob_type, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags = 0, ::NCRYPT_KEY_HANDLE decryption_key = 0)
	{ return import_key(hprov, static_cast<const wchar_t *>(keyname), blob_type, blob_buffer, buffer_size, flags, decryption_key); }
	
	inline key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const wchar_t * keyname, const wchar_t * blob_type, const std::vector<unsigned char> & blob, unsigned flags, ::NCRYPT_KEY_HANDLE decryption_key = 0)
	{ return import_key(hprov, keyname, blob_type, blob.data(), blob.size(), flags, decryption_key); }
	inline key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const  char   * keyname, const wchar_t * blob_type, const std::vector<unsigned char> & blob, unsigned flags, ::NCRYPT_KEY_HANDLE decryption_key = 0)
	{ return import_key(hprov, keyname, blob_type, blob.data(), blob.size(), flags, decryption_key); }
	inline key_handle import_key(::NCRYPT_PROV_HANDLE hprov, nullptr_t keyname, const wchar_t * blob_type, const std::vector<unsigned char> & blob, unsigned flags, ::NCRYPT_KEY_HANDLE decryption_key = 0)
	{ return import_key(hprov, static_cast<const wchar_t *>(keyname), blob_type, blob, flags, decryption_key); }
	
	
	/// NCryptExportKey wrapper
	///   key name - A pointer to a null-terminated Unicode string that contains the name of the key to retrieve.
	///              This is same(well it looks like) as container name in CAPI.
	///   blob_type - type of a blob
	///   blob_buffer, buffer_size - key blob
	///   flags - flags, some flags are provider specific, for MS_KEY_STORAGE_PROVIDER additional flags can be:
	///     NCRYPT_NO_KEY_VALIDATION, NCRYPT_MACHINE_KEY_FLAG, NCRYPT_OVERWRITE_KEY_FLAG, NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG, NCRYPT_DO_NOT_FINALIZE_FLAG
	/// 
	/// MSDN blob description:
	/// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptexportkey
	/// 
	/// Throws system_error in case of errors
	std::vector<unsigned char> export_key(::NCRYPT_KEY_HANDLE hkey, const wchar_t * blob_type, unsigned flags, ::NCRYPT_KEY_HANDLE encryption_key = 0);
	
	/// export_key with BCRYPT_RSAPUBLIC_BLOB
	std::vector<unsigned char> export_rsa_public_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags = 0);
	/// export_key with BCRYPT_RSAFULLPRIVATE_BLOB
	std::vector<unsigned char> export_rsa_private_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags = 0, ::NCRYPT_KEY_HANDLE encryption_key = 0);
	
	/// NcryptFinalizeKey
	/// Throws system_error in case of errors
	void finalize_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags);
	
	/// NCryptDeleteKey wrapper
	/// Throws system_error in case of errors
	void delete_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags);
	
	
	/// Prints key info, this is mostly for logging/debugging.
	/// Example output:
	/// NCrypt(CNG) Private key info:
	///   Provider Name: Microsoft Software Key Storage Provider
    ///   Container Name: <nullopt>
    ///   KeyType: User, ProvImpType: 0x00000002
    ///   Algorithm Group/Algorithm Name: RSA/RSA
    ///   Key Length: 4096
    ///   Export Policy: 0x00000000
	std::string print_key_info(::NCRYPT_KEY_HANDLE hkey, std::string_view ident = "");
	
	/************************************************************************/
	/*           Private key loading from memory and files                  */
	/************************************************************************/
	/// Loads RSA private key from given memory location, private key is expected to be unencrypted(no password protection).
	/// Private key expected to be in usual PEM or DER format
	/// Throws std::system_error in case of errors
	/// NOTE: this method loads key in PKCS#8 format, identified by header -----BEGIN PRIVATE KEY-----
	///        -----BEGIN RSA PRIVATE KEY----- is PKCS#1 and should be loaded via different method
	/// https://stackoverflow.com/questions/20065304/differences-between-begin-rsa-private-key-and-begin-private-key
	/// https://stackoverflow.com/a/20065522/1682317
	/// 
	/// NOTE: key is placed into private key blob and can be later imported into provider via NCryptImportKey function with type 
	std::vector<unsigned char> load_rsa_private_key(const char * data, std::size_t len);
	std::vector<unsigned char> load_rsa_private_key_from_file(const char * path);
	std::vector<unsigned char> load_rsa_private_key_from_file(const wchar_t * path);
	std::vector<unsigned char> load_rsa_private_key_from_file(std::FILE * file);

	inline std::vector<unsigned char> load_rsa_private_key_from_file(std::string_view str) { return load_rsa_private_key(str.data(), str.size()); }
	
	
	/************************************************************************/
	/*               CryptAcquireCertificatePrivateKey stuff                */
	/************************************************************************/
	
	/// Special handle container class for holding result of CryptAcquireCertificatePrivateKey.
	/// It sort of specialized variant of NCRYPT_KEY_HANDLE and HCRYPTPROV.
	/// 
	/// CryptAcquireCertificatePrivateKey function have somewhat complex semantics:
	///  it can return NCRYPT_KEY_HANDLE or HCRYPTPROV with keyspec, also it returns boolean flag - should handle be freed
	///  those features are controlled by flags and useful in practice.
	/// 
	/// NCRYPT_KEY_HANDLE and HCRYPTPROV have different handle management models:
	///  HCRYPTPROV - reference counted, reference decreased by CryptReleaseContext.
	///  NCRYPT_KEY_HANDLE - unique handle freed by NCryptFreeObject.
	/// HCRYPTPROV can be held by multiple references, while NCRYPT_KEY_HANDLE cannot.
	/// And CallerFreeProvOrNCryptKey flag complicates things even more.
	/// 
	/// To make things somewhat simple this class maintains it's own reference counter - it's always have reference counted semantics.
	/// It also accounts for CallerFreeProvOrNCryptKey flag and calls appropriate functions if needed.
	class privatekey_crypt_handle : public ext::intrusive_atomic_counter<privatekey_crypt_handle>
	{
	private:
		std::uintptr_t m_crypt_handle = 0;
		unsigned m_keyspec = 0;
		unsigned m_should_free = 0;
		
	public:
		static const unsigned ms_ncrypt_keyspec; // CERT_NCRYPT_KEY_SPEC
		
	public:		
		bool is_empty() const { return not m_crypt_handle; }
		operator bool() const { return m_crypt_handle; }
		
		unsigned keyspec() const { return m_keyspec; }
		
		bool is_ncrypt() const { return m_keyspec == ms_ncrypt_keyspec; }
		bool is_wincrypt() const { return m_keyspec != ms_ncrypt_keyspec; }
		
		NCRYPT_KEY_HANDLE ncrypt_handle()   const { return is_ncrypt() ? m_crypt_handle : 0; }
		HCRYPTPROV        wincrypt_handle() const { return is_wincrypt() ? m_crypt_handle : 0; }
		
	public:
		void release() noexcept { m_crypt_handle = 0; m_keyspec = 0; m_should_free = 0; }
		void reset() noexcept;
		
	public:
		static privatekey_crypt_handle ncrypt(std::uintptr_t handle) { return privatekey_crypt_handle(handle, ms_ncrypt_keyspec, 1); }
		static privatekey_crypt_handle wincrypt(std::uintptr_t handle, unsigned keyspec) { return privatekey_crypt_handle(handle, keyspec, 1); }
		
		privatekey_crypt_handle(const privatekey_crypt_handle & ) = delete;
		privatekey_crypt_handle & operator =(const privatekey_crypt_handle &) = delete;
		
		privatekey_crypt_handle(privatekey_crypt_handle && other) noexcept;
		privatekey_crypt_handle & operator =(privatekey_crypt_handle && other) noexcept;
		
		privatekey_crypt_handle() = default;
		privatekey_crypt_handle(std::uintptr_t crypt_handle, unsigned keyspec, unsigned should_free) noexcept
		    : m_crypt_handle(crypt_handle), m_keyspec(keyspec), m_should_free(should_free) {}
		~privatekey_crypt_handle() noexcept;
	};

	/// Wrapper around CryptAcquireCertificatePrivateKey function:
	///  calls CryptAcquireCertificatePrivateKey(cert, flags, hwnd, ...);
	///  if hwnd specified - calls with CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG
	auto acquire_certificate_private_key(const ::CERT_CONTEXT * cert, unsigned flags, void * hwnd = nullptr) -> ext::intrusive_ptr<privatekey_crypt_handle>;
}

#endif // BOOST_OS_WINDOWS
