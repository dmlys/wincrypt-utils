#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <windows.h>
#include <wincrypt.h>
#include <ncrypt.h>

#include <cassert>
#include <optional>

#include <fmt/format.h>
//#include <fmt/std.h>

#include <ext/config.hpp>
#include <ext/errors.hpp>
#include <ext/filesystem_utils.hpp>
#include <ext/codecvt_conv/generic_conv.hpp>
#include <ext/codecvt_conv/wchar_cvt.hpp>

#include <boost/range.hpp>
#include <boost/range/as_literal.hpp>
#include <boost/algorithm/string.hpp>

#include <ext/wincrypt/ncrypt.hpp>
#include <ext/wincrypt/utils.hpp>

namespace ext::wincrypt
{
	std::vector<char> read_file_intr_impl(std::FILE * file);
}

namespace ext::wincrypt::ncrypt
{
	using ext::codecvt_convert::wchar_cvt::to_utf8;
	using ext::codecvt_convert::wchar_cvt::to_wchar;
	
	void prov_handle_traits::close(::NCRYPT_PROV_HANDLE hprov) noexcept
	{
		auto res = NCryptFreeObject(hprov);
		assert(res == ERROR_SUCCESS); EXT_UNUSED(res);
	}
	
	void key_handle_traits::close(::NCRYPT_KEY_HANDLE hkey) noexcept
	{
		auto res = NCryptFreeObject(hkey);
		assert(res == ERROR_SUCCESS); EXT_UNUSED(res);
	}
	
	void buffer_deleter::operator()(void * ptr) const noexcept
	{
		NCryptFreeBuffer(ptr);
	}
	
	std::optional<std::string> get_string_property (::NCRYPT_HANDLE handle, const wchar_t * propname)
	{
		auto result = get_wstring_property(handle, propname);
		if (result)
			return to_utf8(*result);
		else
			return std::nullopt;
	}
	
	std::optional<std::wstring> get_wstring_property(::NCRYPT_HANDLE handle, const wchar_t * propname)
	{
		std::wstring result;
		DWORD flags = 0, written;
		SECURITY_STATUS status;
		status = NCryptGetProperty(handle, propname, nullptr, 0, &written, flags);
		if (status == NTE_NOT_SUPPORTED)
			return std::nullopt;
		if (status != ERROR_SUCCESS)
		{
			auto propnamea = to_utf8(propname);
			std::string errmsg = fmt::format("ext::wincrypt::ncrypt::get_string_property: NCryptGetProperty failed with propname = {}, flags = {}", propnamea, flags);
			
			throw std::system_error(status, std::system_category(), errmsg);
		}
		
		result.resize(written / sizeof(decltype(result)::value_type));
		auto * ptr = reinterpret_cast<BYTE *>(result.data());
		auto size = result.size() * sizeof(decltype(result)::value_type);
		status = NCryptGetProperty(handle, propname, ptr, size, &written, flags);
		if (status == NTE_NOT_SUPPORTED)
			return std::nullopt;
		else if (status != ERROR_SUCCESS)
		{
			auto propnamea = to_utf8(propname);
			std::string errmsg = fmt::format("ext::wincrypt::ncrypt::get_string_property: NCryptGetProperty failed with propname = {}, flags = {}", propnamea, flags);
			
			throw std::system_error(status, std::system_category(), errmsg);
		}
		
		written /= sizeof(decltype(result)::value_type);
		
		// trim zero terminators at end
		while (result[written - 1] == 0)
			--written;
		
		result.resize(written);
		return result;
	}
	
	void set_string_property (::NCRYPT_HANDLE handle, const wchar_t * propname, std::string_view  str)
	{
		auto wstr = to_wchar(str);
		return set_wstring_property(handle, propname, wstr);
	}
	
	void set_wstring_property(::NCRYPT_HANDLE handle, const wchar_t * propname, std::wstring_view str)
	{
		return set_property(handle, propname, str.data(), str.size());
	}
	
	bool get_property(::NCRYPT_HANDLE handle, const wchar_t * propname, void * dest, std::size_t dest_size)
	{
		DWORD flags = 0, neededSize;
		SECURITY_STATUS status;
		status = NCryptGetProperty(handle, propname, reinterpret_cast<BYTE *>(dest), dest_size, &neededSize, flags);
		if (status == ERROR_SUCCESS)
			return true;
		if (status == NTE_NOT_SUPPORTED)
			return false;
		
		auto propnamea = to_utf8(propname);
		std::string errmsg = fmt::format("ext::wincrypt::ncrypt::get_property: NCryptGetProperty failed with propname = {}, flags = {}", propnamea, flags);
		
		throw std::system_error(status, std::system_category(), errmsg);
	}
	
	void set_property(::NCRYPT_HANDLE handle, const wchar_t * propname, const void * prop, std::size_t prop_size)
	{
		DWORD flags = 0;
		SECURITY_STATUS status;
		status = NCryptSetProperty(handle, propname, static_cast<BYTE *>(const_cast<void *>(prop)), prop_size, flags);
		if (status == ERROR_SUCCESS)
			return;
		
		auto propnamea = to_utf8(propname);
		std::string errmsg = fmt::format("ext::wincrypt::ncrypt::set_property: NCryptSetProperty failed with propname = {}, flags = {}", propnamea, flags);
		
		throw std::system_error(status, std::system_category(), errmsg);
	}
		
	std::string name_property(::NCRYPT_HANDLE handle)
	{
		return get_string_property(handle, NCRYPT_NAME_PROPERTY).value_or("<nullopt>");
	}
	
	std::wstring wname_property(::NCRYPT_HANDLE handle)
	{
		return get_wstring_property(handle, NCRYPT_NAME_PROPERTY).value_or(L"<nullopt>");
	}
	
	prov_handle open_storage_provider(const wchar_t * provname)
	{
		// https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptopenstorageprovider
		// Flags that modify the behavior of the function. No flags are defined for this function.
		constexpr DWORD flags = 0;
		NCRYPT_PROV_HANDLE hprov;
		SECURITY_STATUS status = NCryptOpenStorageProvider(&hprov, provname, flags);
		if (status != ERROR_SUCCESS)
		{
			auto provnamea = to_utf8(provname ? provname : L"<null>");
			std::string errmsg = fmt::format("ext::wincrypt::ncrypt::open_storage_provider: NCryptOpenStorageProvider failed with provname = {}, flags = {}", provnamea, flags);

			throw std::system_error(status, std::system_category(), errmsg);
		}	
		
		return prov_handle(hprov);
	}
	
	std::vector<enum_prov_algorithm_name> enum_provider_algorithms(::NCRYPT_PROV_HANDLE hprov, unsigned long alg_operations, unsigned flags)
	{
		std::vector<enum_prov_algorithm_name> result;
		
		DWORD count;
		NCryptAlgorithmName * alglist;
		SECURITY_STATUS status = NCryptEnumAlgorithms(hprov, alg_operations, &count, &alglist, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::enum_provider_algorithms: NCryptEnumAlgorithms failed");
		
		std::unique_ptr<void, buffer_deleter> memptr(alglist);
		
		result.resize(count);
		for (unsigned i = 0; i < count; ++i)
		{
			auto & r = result[i];
			auto & a = alglist[i];
			
			r.name = to_utf8(a.pszName);
			r.alg_class = a.dwClass;
			r.alg_operations = a.dwAlgOperations;
			r.flags = a.dwFlags;
		}
	
		return result;
	}
	
	std::vector<enum_prov_key_name> enum_provider_keys(::NCRYPT_PROV_HANDLE hprov, unsigned flags, const wchar_t * scope)
	{
		std::vector<enum_prov_key_name> result;
		
		PVOID state = nullptr;
		NCryptKeyName * pKeyName = nullptr;
		SECURITY_STATUS status;
		
		std::unique_ptr<void, buffer_deleter> memptr(state);
		
		for (;;)
		{
			status = NCryptEnumKeys(hprov, scope, &pKeyName, &state, flags);
			if (status == NTE_NO_MORE_ITEMS)
				break;
			
			if (status != ERROR_SUCCESS)
				throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::enum_provider_keys: NCryptEnumKeys failed");
			
			assert(pKeyName);
			
			enum_prov_key_name item;
			item.name = to_utf8(pKeyName->pszName);
			item.algid = to_utf8(pKeyName->pszAlgid);
			
			item.keyspec = pKeyName->dwLegacyKeySpec;
			item.flags = pKeyName->dwFlags;
			
			result.push_back(std::move(item));
		}
		
		return result;
	}
	
	prov_handle open_storage_provider(const char * provname)
	{
		return open_storage_provider(provname ? to_wchar(provname).c_str() : nullptr);
	}
	
	prov_handle provider_handle(::NCRYPT_KEY_HANDLE hkey)
	{
		DWORD flags = 0, neededSize;
		SECURITY_STATUS status;
		NCRYPT_PROV_HANDLE hprov;
		
		status = NCryptGetProperty(hkey, NCRYPT_PROVIDER_HANDLE_PROPERTY, reinterpret_cast<BYTE *>(&hprov), sizeof hprov, &neededSize, flags);
		if (status == ERROR_SUCCESS)
			return prov_handle(hprov);
		
		auto propnamea = to_utf8(NCRYPT_PROVIDER_HANDLE_PROPERTY);
		std::string errmsg = fmt::format("ext::wincrypt::ncrypt::provider_handle: NCryptGetProperty failed with propname = {}, flags = {}", propnamea, flags);
		
		throw std::system_error(status, std::system_category(), errmsg);
	}
	
	key_handle open_key(::NCRYPT_PROV_HANDLE hprov, const wchar_t * keyname, unsigned flags, unsigned keyspec /* = 0 */)
	{
		NCRYPT_KEY_HANDLE hkey = 0;
		SECURITY_STATUS status = NCryptOpenKey(hprov, &hkey, keyname, keyspec, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::open_key: NCryptOpenKey failed");
		
		assert(hkey);
		return key_handle(hkey);
	}
	
	key_handle open_key(::NCRYPT_PROV_HANDLE hprov, const  char   * keyname, unsigned flags, unsigned keyspec /* = 0 */)
	{
		auto wkeyname = to_wchar(keyname);
		return open_key(hprov, wkeyname.c_str(), keyspec, flags);
	}
	
	key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const wchar_t * keyname, const wchar_t * blob_type, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags, ::NCRYPT_KEY_HANDLE decryption_key)
	{
		assert(hprov);
		
		NCRYPT_KEY_HANDLE hkey;
		NCryptBuffer name_buffer;
		NCryptBufferDesc param_list;
		NCryptBufferDesc * pparams_list;
		
		if (not keyname)
			pparams_list = nullptr;
		else
		{
			name_buffer.BufferType = NCRYPTBUFFER_PKCS_KEY_NAME;
			name_buffer.cbBuffer   = (wcslen(keyname) + 1) * sizeof(WCHAR);
			name_buffer.pvBuffer   = const_cast<wchar_t *>(keyname);
		
			param_list.ulVersion = NCRYPTBUFFER_VERSION;
			param_list.cBuffers  = 1;
			param_list.pBuffers  = &name_buffer;
			
			pparams_list = &param_list;
		}
		
		SECURITY_STATUS status = ::NCryptImportKey(hprov, decryption_key, blob_type, pparams_list, &hkey, const_cast<unsigned char * >(blob_buffer), buffer_size, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::import_key: NCryptImportKey failed");
		
		return key_handle(hkey);
	}
	
	key_handle import_key(::NCRYPT_PROV_HANDLE hprov, const  char   * keyname, const wchar_t * blob_type, const unsigned char * blob_buffer, unsigned buffer_size, unsigned flags, ::NCRYPT_KEY_HANDLE decryption_key)
	{
		auto wkeyname = to_wchar(keyname);
		return import_key(hprov, wkeyname.c_str(), blob_type, blob_buffer, buffer_size, flags, decryption_key);
	}
	
	std::vector<unsigned char> export_key(::NCRYPT_KEY_HANDLE hkey, const wchar_t * blob_type, unsigned flags, ::NCRYPT_KEY_HANDLE encryption_key)
	{
		std::vector<unsigned char> blob;
		
		DWORD requestd_size;
		SECURITY_STATUS status;
		
		status = ::NCryptExportKey(hkey, encryption_key, blob_type, nullptr, nullptr, 0, &requestd_size, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::export_key: NCryptExportKey failed");
		
		assert(requestd_size > 0);
		blob.resize(requestd_size);
		
		status = ::NCryptExportKey(hkey, encryption_key, blob_type, nullptr, blob.data(), blob.size(), &requestd_size, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::export_key: NCryptExportKey failed");
		
		assert(requestd_size > 0);
		blob.resize(requestd_size);
		
		return blob;
	}
	
	std::vector<unsigned char> export_rsa_public_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags)
	{
		return export_key(hkey, BCRYPT_RSAPUBLIC_BLOB, flags);
	}
	
	std::vector<unsigned char> export_rsa_private_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags, ::NCRYPT_KEY_HANDLE encryption_key)
	{
		return export_key(hkey, BCRYPT_RSAFULLPRIVATE_BLOB, flags, encryption_key);
	}
	
	void finalize_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags)
	{
		SECURITY_STATUS status = ::NCryptFinalizeKey(hkey, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::finalize_key: NCryptFinalizeKey failed");
	}
	
	void delete_key(::NCRYPT_KEY_HANDLE hkey, unsigned flags)
	{
		SECURITY_STATUS status = ::NCryptDeleteKey(hkey, flags);
		if (status != ERROR_SUCCESS)
			throw std::system_error(std::error_code(status, std::system_category()), "ext::wincrypt::ncrypt::delete_key: NCryptDeleteKey failed");
	}
	
	std::string print_key_info(::NCRYPT_KEY_HANDLE hkey, std::string_view ident)
	{
		std::string result;
		result.reserve(512);
		if (not hkey)
			return result.append(ident).append("<null> key handle\n");
		
		auto hprov = provider_handle(hkey);
		
		auto prov_impl_type = get_scalar_property<DWORD>(hprov.handle(), NCRYPT_IMPL_TYPE_PROPERTY);
		auto key_type = get_scalar_property<DWORD>(hkey, NCRYPT_KEY_TYPE_PROPERTY);
		auto prov_name = provider_name(hprov.handle());
		auto cont_name = container_name(hkey);
		
		auto alg_group = get_string_property(hkey, NCRYPT_ALGORITHM_GROUP_PROPERTY);
		auto alg_name  = get_string_property(hkey, NCRYPT_ALGORITHM_PROPERTY);
		//auto key_usage = get_scalar_property<DWORD>(hkey, NCRYPT_KEY_USAGE_PROPERTY);
		auto key_length = get_scalar_property<DWORD>(hkey, NCRYPT_LENGTH_PROPERTY);
		
		auto export_policy = get_scalar_property<DWORD>(hkey, NCRYPT_EXPORT_POLICY_PROPERTY);
		
		result.append(ident).append("NCrypt(CNG) Private key info:\n");
		result.append(ident).append("  Provider Name: ").append(prov_name).append("\n");
		result.append(ident).append("  Container Name: ").append(cont_name).append("\n");
		
		//"  KeyType: {}, ProvImpType: {:#010x}\n"
		result.append(ident).append("  KeyType: ");
		if (not key_type)
			result.append("<nullopt>");
		else
			result.append(*key_type & NCRYPT_MACHINE_KEY_FLAG ? "Machine" : "User");
		
		result.append(", ProvImpType: ");
		if (not prov_impl_type)
			result.append("<nullopt>");
		else
			result.append(fmt::format("{:#010x}", *prov_impl_type));
		
		result.append("\n");
		
		//result += ident; result += fmt::format("{}/{}\n", alg_group.value_or("<nullopt>"), alg_name.value_or("<nullopt>"));
		result.append(ident).append("  Algorithm Group/Algorithm Name: ")
		        .append(alg_group.value_or("<nullopt>")).append("/").append(alg_name.value_or("<nullopt>"))
		        .append("\n");
		
		result.append(ident).append("  Key Length: ");
		if (not key_length)
			result.append("<nullopt>");
		else
			result.append(fmt::format("{}", *key_length));
		result.append("\n");
		
		result.append(ident).append("  Export Policy: ");
		if (not export_policy)
			result.append("<nullopt>");
		else
			result.append(fmt::format("{:#010x}", *export_policy));
		result.append("\n");
		
		return result;
	}
	
	std::vector<unsigned char> load_rsa_private_key(const char * data, std::size_t len)
	{
		assert(data);
		
		BOOL res;
		DWORD written, pkey_info_length, pkey_rsa_blob_length;
		::CRYPT_PRIVATE_KEY_INFO * pkey_info_ptr = nullptr;
		
		hlocal_uptr pkey_info_uptr;
		hlocal_uptr pkey_info_pkey_blob_uptr;
		
		std::vector<unsigned char> der_data;
		der_data.resize(len / 4 * 3);
		written = der_data.size();
		
		res = ::CryptStringToBinaryA(data, len, CRYPT_STRING_ANY, der_data.data(), &written, nullptr, nullptr);
		if (not res) ext::throw_last_system_error("ext::wincrypt::load_private_key: CryptStringToBinary failed");
		
		/// der_data hols PKCS#8 blob that we need, and can return now,
		/// but first check that this is indeed PKCS#8 blob
		res = ::CryptDecodeObjectEx(PKCS_7_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
		                            der_data.data(), written,
		                            CRYPT_ENCODE_ALLOC_FLAG, nullptr, &pkey_info_ptr, &pkey_info_length);
		
		if (not res)
			ext::throw_last_system_error("ext::wincrypt::ncrypt::load_rsa_private_key: CryptDecodeObjectEx(PKCS_PRIVATE_KEY_INFO) failed while decoding encoded private key");
		
		pkey_info_uptr.reset(pkey_info_ptr);
		pkey_info_pkey_blob_uptr.reset(pkey_info_ptr->PrivateKey.pbData);
		
		return der_data;
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
		auto content = read_file_intr_impl(file);
		return load_rsa_private_key(content.data(), content.size());
	}

	
	const unsigned privatekey_crypt_handle::ms_ncrypt_keyspec = CERT_NCRYPT_KEY_SPEC;
	
	privatekey_crypt_handle::privatekey_crypt_handle(privatekey_crypt_handle && other) noexcept
		: m_crypt_handle(std::exchange(other.m_crypt_handle, 0)), m_keyspec(std::exchange(other.m_keyspec, 0)), m_should_free(std::exchange(other.m_should_free, 0))
	{}
	
	privatekey_crypt_handle & privatekey_crypt_handle::operator =(privatekey_crypt_handle && other) noexcept
	{
		if (this != &other)
		{
			this->~privatekey_crypt_handle();
			new (this) privatekey_crypt_handle(std::move(other));
		}
		
		return *this;
	}
	
	void privatekey_crypt_handle::reset() noexcept
	{
		if (not m_should_free)
			return;
		
		if (m_keyspec == ms_ncrypt_keyspec)
			key_handle_traits::close(m_crypt_handle);
		else
			hcrypt_handle_traits::subref(m_crypt_handle);
		
		m_crypt_handle = 0;
		m_keyspec = 0;
		m_should_free = 0;
	}
	
	privatekey_crypt_handle::~privatekey_crypt_handle() noexcept
	{
		if (not m_should_free)
			return;
		
		if (m_keyspec == ms_ncrypt_keyspec)
			key_handle_traits::close(m_crypt_handle);
		else
			hcrypt_handle_traits::subref(m_crypt_handle);
	}
	
	ext::intrusive_ptr<privatekey_crypt_handle> acquire_certificate_private_key(const ::CERT_CONTEXT * cert, unsigned flags, void * hwnd)
	{
		assert(cert);
		
		::HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
		DWORD keyspec = 0;
		BOOL should_free, res;

		flags |= hwnd ? CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG : 0;
		
		res = ::CryptAcquireCertificatePrivateKey(cert,
			flags, hwnd ? &hwnd : nullptr,
			&handle, &keyspec, &should_free);

		if (not res)
			ext::throw_last_system_error("ext::wincrypt::ncrypt::acquire_certificate_private_key: CryptAcquireCertificatePrivateKey failed");

		return ext::make_intrusive<privatekey_crypt_handle>(handle, keyspec, should_free);
	}
}


#endif // BOOST_OS_WINDOWS
