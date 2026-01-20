#pragma once
#include <boost/predef.h>
#if BOOST_OS_WINDOWS
#ifdef EXT_ENABLE_OPENSSL

#include <ext/openssl.hpp>
#include <ext/wincrypt/ncrypt.hpp>

namespace ext::wincrypt::ncrypt
{
	/// Creates and prepares BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAPUBLIC_BLOB/BCRYPT_RSAPUBLIC_MAGIC 
	/// for ncrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider") from OpenSSL RSA key object.
	/// This blob is suitable for NCryptImportKey function with type BCRYPT_RSAPUBLIC_BLOB.
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_ncrypt_rsa_public_blob(const ::RSA * rsa);
	/// Creates and prepares BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAFULLPRIVATE_BLOB/BCRYPT_RSAFULLPRIVATE_MAGIC 
	/// for ncrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider") from OpenSSL RSA key object.
	/// This blob is suitable for NCryptImportKey function with type BCRYPT_RSAFULLPRIVATE_BLOB.
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_ncrypt_rsa_private_blob(const ::RSA * rsa);
	
	/// Creates and prepares BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAPUBLIC_BLOB/BCRYPT_RSAPUBLIC_MAGIC
	/// for ncrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider") from OpenSSL EVP_PKEY key object.
	/// This blob is suitable for NCryptImportKey function with type BCRYPT_RSAPUBLIC_BLOB.
	/// This is convenience function, only RSA key is supported - otherwise exception will be thrown
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_ncrypt_rsa_public_blob(const ::EVP_PKEY * pkey);
	/// Creates and prepares BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAFULLPRIVATE_BLOB/BCRYPT_RSAFULLPRIVATE_MAGIC
	/// for ncrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider") from OpenSSL RSA key object.
	/// This blob is suitable for NCryptImportKey function with type BCRYPT_RSAFULLPRIVATE_BLOB.
	/// This is convenience function, only RSA key is supported - otherwise exception will be thrown
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	std::vector<unsigned char> create_ncrypt_rsa_private_blob(const ::EVP_PKEY * pkey);
	
	/// Creates OpenSSL RSA public key from BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAPUBLIC_BLOB/BCRYPT_RSAPUBLIC_MAGIC 
	/// of NCrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider").
	/// This blob usually comes from NCryptExportKey function
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	ext::openssl::rsa_iptr create_openssl_rsa_publickey(const unsigned char * publickey_blob_data, std::size_t publickey_blob_size);
	inline ext::openssl::rsa_iptr create_openssl_rsa_publickey(const std::vector<unsigned char> & publickey_blob)
	{ return create_openssl_rsa_publickey(publickey_blob.data(), publickey_blob.size()); }
	
	/// Creates OpenSSL RSA public key from BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAFULLPRIVATE_BLOB/BCRYPT_RSAFULLPRIVATE_MAGIC
	/// of NCrypt MS_KEY_STORAGE_PROVIDER("Microsoft Software Key Storage Provider").
	/// This blob usually comes from NCryptExportKey function
	///
	/// blob is described in MSDN pages:
	/// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
	/// 
	/// @Throws system_error/runtime_error for OpenSSL errors if any
	ext::openssl::rsa_iptr create_openssl_rsa_privatekey(const unsigned char * privatekey_blob_data, std::size_t privatekey_blob_size);
	inline ext::openssl::rsa_iptr create_openssl_rsa_privatekey(const std::vector<unsigned char> & privatekey_blob)
	{ return create_openssl_rsa_privatekey(privatekey_blob.data(), privatekey_blob.size()); }
	
	/// Creates OpenSSL RSA key by extracting BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAPUBLIC_BLOB from NCrypt key,
	/// This is convenience function, calls: export_key, create_openssl_rsa_publickey.
	/// @Throws system_error in case of errors
	ext::openssl::evp_pkey_iptr create_openssl_rsa_publickey(::NCRYPT_PROV_HANDLE hkey);
	/// Creates OpenSSL RSA key by extracting BCRYPT_RSAKEY_BLOB with type BCRYPT_RSAFULLPRIVATE_BLOB from NCrypt key,
	/// This is convenience function, calls: export_key, create_openssl_rsa_privatekey.
	/// @Throws system_error in case of errors
	ext::openssl::evp_pkey_iptr create_openssl_rsa_privatekey(::NCRYPT_PROV_HANDLE hkey);
}


#endif // EXT_ENABLE_OPENSSL
#endif // BOOST_OS_WINDOWS
