#include "DIWMICom.h"
#include "LogManager.h"
#include "StringUtils.h"

namespace di_rest_client
{
int InitWmi(HRESULT &hres, IWbemLocator **pLoc, IWbemServices **pSvc)
{

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: CoInitializeEx failed: %x", hres);
        return -1;
    }

    hres = CoInitializeSecurity(
        NULL,
        -1,                           // COM authentication
        NULL,                         // Authentication services
        NULL,                         // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,    // Default authentication
        RPC_C_IMP_LEVEL_IMPERSONATE,  // Default Impersonation
        NULL,                         // Authentication info
        EOAC_NONE,                    // Additional capabilities
        NULL                          // Reserved
    );

    if (FAILED(hres) && hres != RPC_E_TOO_LATE) {
		DI_LOG_ERROR("InitWmi: CoInitializeSecurity failed: %x", hres);
        CoUninitialize();
        return -1;  // Program has failed.
    }

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID *)&(*pLoc));

    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: CoCreateInstance failed: %x", hres);
        CoUninitialize();
        return -1;  // Program has failed.
    }

    hres = (*pLoc)->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),  // Object path of WMI namespace
        NULL,                     // User name. NULL = current user
        NULL,                     // User password. NULL = current
        0,                        // Locale. NULL indicates current
        NULL,                     // Security flags.
        0,                        // Authority (for example, Kerberos)
        0,                        // Context object
        &(*pSvc)                  // pointer to IWbemServices proxy
    );

    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: ConnectServer failed: %x", hres);
        (*pLoc)->Release();
        CoUninitialize();
        return -1;  // Program has failed.
    }

    hres = CoSetProxyBlanket(
        *pSvc,                        // Indicates the proxy to set
        RPC_C_AUTHN_WINNT,            // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE,             // RPC_C_AUTHZ_xxx
        NULL,                         // Server principal name
        RPC_C_AUTHN_LEVEL_CALL,       // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE,  // RPC_C_IMP_LEVEL_xxx
        NULL,                         // client identity
        EOAC_NONE                     // proxy capabilities
    );

    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: CoSetProxyBlanket failed: %x", hres);
        (*pSvc)->Release();
        (*pLoc)->Release();
        CoUninitialize();
        return -1;  // Program has failed.
    }

    return 0;
}

std::string GetWMIInfo(HRESULT hres, IWbemLocator *pLoc, IWbemServices *pSvc, std::string wql, std::wstring field, const std::string& dataType)
{

    std::string info;
    IEnumWbemClassObject *pEnumerator = NULL;

    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t(wql.c_str()),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: ExecQuery failed: %x", hres);
        return "";
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
                                       &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
        if (dataType == "string") {
            info = WcharToString(vtProp.bstrVal);
        } else if (dataType == "int") {
            info = std::to_string(vtProp.intVal);
        } else if (dataType == "bool") {
            if (vtProp.boolVal) {
                info = "true";
            } else {
                info = "false";
            }
        }
        VariantClear(&vtProp);
        pclsObj->Release();
    }

    pEnumerator->Release();
    return info;
}

int UnInitWmi(HRESULT &hres, IWbemLocator *pLoc, IWbemServices *pSvc)
{
  pSvc->Release();
  pLoc->Release();
  CoUninitialize();
  return 0;
}
}
