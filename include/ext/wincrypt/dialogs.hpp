#pragma once
#include <ext/wincrypt/utils.hpp>

namespace ext::wincrypt
{
	/// simple wrapper around CryptUIDlgSelectCertificateFromStore
	cert_iptr cryptui_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title = nullptr, const wchar_t * display_string = nullptr);
	
	/// simple wrapper around CryptUIDlgSelectCertificate
	// looks like CryptUIDlgSelectCertificate existed only in WinXP - Windows7, does not exists in Windows 10
	//cert_iptr cryptui_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, const wchar_t * display_string, std::function<bool(const CERT_CONTEXT *)> filter);
	
	/// simple wrapper around CertSelectCertificate
	cert_iptr cert_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, std::function<bool(const CERT_CONTEXT *)> filter);
}
