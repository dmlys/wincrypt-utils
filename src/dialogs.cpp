#include <boost/predef.h>
#if BOOST_OS_WINDOWS

#include <winsock2.h>
#include <windows.h>
#include <prsht.h>
#include <wincrypt.h>
#include <cryptuiapi.h>

#include <ext/errors.hpp>
#include <ext/wincrypt/utils.hpp>
#include <ext/wincrypt/dialogs.hpp>

#ifdef _MSC_VER
#pragma comment(lib, "cryptui.lib")
#endif

// CertSelectCertificate stuff
// Sadly MINGW does not provide cryptdlg.h, also wine does not implement CertSelectCertificate, call to it - returns not implemented.
// Well at least we can make it compile under MINGW, we just need to define struct CERT_SELECT_STRUCT_W and 2 function typedefs
#if not BOOST_PLAT_MINGW
#include <cryptdlg.h>
#else
typedef UINT (WINAPI *PFNCMHOOKPROC)
(
	HWND   hwndDialog,
	UINT   message,
	WPARAM wParam,
	LPARAM lParam
);

typedef BOOL (WINAPI *PFNCMFILTERPROC)
(
	PCCERT_CONTEXT pCertContext,
	LPARAM Arg2,
	DWORD  Arg3,
	DWORD  Arg4
);

typedef struct tagCSSW {
	DWORD           dwSize;
	HWND            hwndParent;
	HINSTANCE       hInstance;
	LPCWSTR         pTemplateName;
	DWORD           dwFlags;
	LPCWSTR         szTitle;
	DWORD           cCertStore;
	HCERTSTORE      *arrayCertStore;
	LPCSTR          szPurposeOid;
	DWORD           cCertContext;
	PCCERT_CONTEXT  *arrayCertContext;
	LPARAM          lCustData;
	PFNCMHOOKPROC   pfnHook;
	PFNCMFILTERPROC pfnFilter;
	LPCWSTR         szHelpFileName;
	DWORD           dwHelpId;
	HCRYPTPROV      hprov;
} CERT_SELECT_STRUCT_W, *PCERT_SELECT_STRUCT_W;

#endif // BOOST_PLAT_MINGW




typedef BOOL (WINAPI * PFNCCERTDISPLAYPROC)(
  _In_ PCCERT_CONTEXT pCertContext,
  _In_ HWND           hWndSelCertDlg,
  _In_ void           *pvCallbackData
);

typedef struct _CRYPTUI_SELECTCERTIFICATE_STRUCT
{
  DWORD               dwSize;
  HWND                hwndParent;
  DWORD               dwFlags;
  LPCTSTR             szTitle;
  DWORD               dwDontUseColumn;
  LPCTSTR             szDisplayString;
  PFNCFILTERPROC      pFilterCallback;
  PFNCCERTDISPLAYPROC pDisplayCallback;
  void                *pvCallbackData;
  DWORD               cDisplayStores;
  HCERTSTORE          *rghDisplayStores;
  DWORD               cStores;
  HCERTSTORE          *rghStores;
  DWORD               cPropSheetPages;
  LPCPROPSHEETPAGE    rgPropSheetPages;
  HCERTSTORE          hSelectedCertStore;
} CRYPTUI_SELECTCERTIFICATE_STRUCT, *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

/// type of CryptUIDlgSelectCertificate
typedef PCCERT_CONTEXT (WINAPI * CryptUIDlgSelectCertificatePtr)(PCRYPTUI_SELECTCERTIFICATE_STRUCT params);

struct SelectCertificateFilterParams
{
	std::function<bool(PCCERT_CONTEXT)> filter;
	std::exception_ptr thrown_exception = nullptr;
};

static BOOL WINAPI CryptUIDlgSelectCertificate_FilterCallBack(PCCERT_CONTEXT pCertContext, BOOL * pfInitialSelectedCert,void * pvCallbackData)
{
	auto * data = reinterpret_cast<SelectCertificateFilterParams *>(pvCallbackData);
	
	try
	{
		return data->filter(pCertContext);
	}
	catch (...)
	{
		data->thrown_exception = std::current_exception();
		return FALSE;
	}
}

static BOOL WINAPI CertSelectCertificate_FilterCallback(PCCERT_CONTEXT pCertContext, LPARAM callback_data, DWORD flags, DWORD arg4)
{
	auto * data = reinterpret_cast<SelectCertificateFilterParams *>(callback_data);
	
	try
	{
		return data->filter(pCertContext);
	}
	catch (...)
	{
		data->thrown_exception = std::current_exception();
		return FALSE;
	}
}

static HMODULE CRYPTDLG_HMODULE = nullptr;
static FARPROC CertSelectCertificateWAddr = nullptr;

static HMODULE acquire_cryptdlg_hmodule(const char * caller)
{
	if (CRYPTDLG_HMODULE) return CRYPTDLG_HMODULE;
	
	auto module = ::LoadLibraryExW(L"CryptDlg.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (not module)
		ext::throw_last_system_error("{}: ::LoadLibraryEx failed with CryptDlg.dll", caller);
	
	return CRYPTDLG_HMODULE = module;
}

static auto acquire_CertSelectCertificate(const char * caller)
{
	using function_type = BOOL (WINAPI *)(IN OUT PCERT_SELECT_STRUCT_W);
	if (CertSelectCertificateWAddr) return reinterpret_cast<function_type>(CertSelectCertificateWAddr);
	
	auto module = acquire_cryptdlg_hmodule(caller);
	auto addr = ::GetProcAddress(module, "CertSelectCertificateW");
	if (not addr)
		ext::throw_last_system_error("{}: ::GetProcAddress failed with CertSelectCertificateW", caller);
	
	CertSelectCertificateWAddr = addr;
	return reinterpret_cast<function_type>(CertSelectCertificateWAddr);
}

namespace ext::wincrypt
{
	cert_iptr cryptui_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, const wchar_t * display_string)
	{
		DWORD columns_opts = 0;
		DWORD flags = 0;

		auto * cert = ::CryptUIDlgSelectCertificateFromStore(store, reinterpret_cast<HWND>(hwnd_parent), title, display_string, columns_opts, flags, nullptr);
		return cert_iptr(cert, ext::noaddref);
	}
	
	cert_iptr cryptui_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, const wchar_t * display_string, std::function<bool(PCCERT_CONTEXT)> filter)
	{
		SelectCertificateFilterParams filter_callback_data;
		filter_callback_data.filter = std::move(filter);
		
		CRYPTUI_SELECTCERTIFICATE_STRUCT params;
		std::memset(&params, 0, sizeof(params));
		params.dwSize = sizeof(params);
		
		params.hwndParent = reinterpret_cast<HWND>(hwnd_parent);
		params.dwFlags = 0;
		params.szTitle = title;
		params.dwDontUseColumn = 0;
		params.pFilterCallback = filter_callback_data.filter ? CryptUIDlgSelectCertificate_FilterCallBack : nullptr;
		params.pDisplayCallback = nullptr;
		params.pvCallbackData = &filter_callback_data;
		params.cDisplayStores = 1;
		params.rghDisplayStores = &store;
		params.cPropSheetPages = 0;
		params.rgPropSheetPages = nullptr;
		params.hSelectedCertStore = nullptr;
		
		auto module = ::GetModuleHandleW(L"Cryptui.dll");
		if (not module) ext::throw_last_system_error("ext::wincrypt::select_certificate_from_store: ::GetModuleHandle failed for Cryptui.dll");
		
		auto addr = GetProcAddress(module, "CryptUIDlgSelectCertificate");
		if (not addr) ext::throw_last_system_error("ext::wincrypt::select_certificate_from_store: ::GetProcAddress failed for CryptUIDlgSelectCertificate");
		
		auto select_proc_ptr = reinterpret_cast<CryptUIDlgSelectCertificatePtr>(addr);
		auto * cert = select_proc_ptr(&params);
		
		//auto * cert = CryptUIDlgSelectCertificate(&params);
		return cert_iptr(cert, ext::noaddref);
	}

	cert_iptr cert_select_certificate(::HCERTSTORE store, void * hwnd_parent, const wchar_t * title, std::function<bool(PCCERT_CONTEXT)> filter)
	{
		SelectCertificateFilterParams filter_callback_data;
		filter_callback_data.filter = std::move(filter);
		
		PCCERT_CONTEXT array_cert_context[1] = {nullptr};
		
		CERT_SELECT_STRUCT_W params;
		std::memset(&params, 0, sizeof(params));
		params.dwSize = sizeof(params);
		
		params.hwndParent = reinterpret_cast<HWND>(hwnd_parent);
		params.hInstance = nullptr;
		params.pTemplateName = nullptr;
		params.dwFlags = 0;
		params.szTitle = title;
		params.cCertStore = 1;
		params.arrayCertStore = &store;
		params.szPurposeOid = nullptr;
		params.arrayCertContext = array_cert_context;
		params.cCertContext = 1;
		params.lCustData = reinterpret_cast<std::uintptr_t>(&filter_callback_data);
		params.pfnFilter = nullptr;
		params.pfnFilter = filter_callback_data.filter ? CertSelectCertificate_FilterCallback : nullptr;
		params.szHelpFileName = nullptr;
		params.dwHelpId = 0;
		params.hprov = 0;
	
		auto addr = acquire_CertSelectCertificate("ext::wincrypt::select_certificate");
		auto res = addr(&params);
		if (not res)
		{
			DWORD err = ::GetLastError();
			// if cancel is pressed - GetLastError will be 0,
			// if filter filtered out all certs, and user pressed ok - GetLastError will be ERROR_END_OF_MEDIA
			if (err and err != ERROR_END_OF_MEDIA and err != ERROR_NO_TOKEN)
				throw std::system_error(std::error_code(err, std::system_category()), "ext::wincrypt::select_certificate: ::CertSelectCertificate failed");
			
			assert(array_cert_context[0] == nullptr);
		}
		
		return cert_iptr(array_cert_context[0], ext::noaddref);
	}
}

#endif // BOOST_OS_WINDOWS
