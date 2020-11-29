#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <winsock2.h>
#include <windows.h>
#include <prsht.h>
#include <wincrypt.h>
#include <cryptuiapi.h>
//#include <cryptdlg.h>
#include <ext/wincrypt/utils.hpp>

#ifdef _MSC_VER
#pragma comment(lib, "cryptui.lib")
#endif

namespace ext::wincrypt
{
	cert_iptr select_certificate_from_store(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, const wchar_t * display_string)
	{
		DWORD columns_opts = 0;
		DWORD flags = 0;

		auto * cert = ::CryptUIDlgSelectCertificateFromStore(store, reinterpret_cast<HWND>(hwnd_parent), title, display_string, columns_opts, flags, nullptr);
		return cert_iptr(cert, ext::noaddref);
	}
}

#endif // BOOST_OS_WINDOWS
