#include "UtilsWMICom.h"
#include "Logger.h"

int UtilsInitWMI(HRESULT& hres, IWbemLocator** pLoc, IWbemServices** pSvc)
{
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        LOG_ERROR("InitWmi: CoInitializeEx failed: %x", hres);
        return -1;
    }

    hres = CoInitializeSecurity(NULL,
                                -1,                          // COM authentication
                                NULL,                        // Authentication services
                                NULL,                        // Reserved
                                RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication
                                RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation
                                NULL,                        // Authentication info
                                EOAC_NONE,                   // Additional capabilities
                                NULL                         // Reserved
    );

    if (FAILED(hres) && hres != RPC_E_TOO_LATE)
    {
        LOG_ERROR("InitWmi: CoInitializeSecurity failed: %x", hres);
        CoUninitialize();
        return -1; // Program has failed.
    }

    hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&(*pLoc));

    if (FAILED(hres))
    {
        LOG_ERROR("InitWmi: CoCreateInstance failed: %x", hres);
        CoUninitialize();
        return -1; // Program has failed.
    }

    hres = (*pLoc)->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), // Object path of WMI namespace
                                  NULL,                    // User name. NULL = current user
                                  NULL,                    // User password. NULL = current
                                  0,                       // Locale. NULL indicates current
                                  NULL,                    // Security flags.
                                  0,                       // Authority (for example, Kerberos)
                                  0,                       // Context object
                                  &(*pSvc)                 // pointer to IWbemServices proxy
    );

    if (FAILED(hres))
    {
        LOG_ERROR("InitWmi: ConnectServer failed: %x", hres);
        (*pLoc)->Release();
        CoUninitialize();
        return -1; // Program has failed.
    }

    hres = CoSetProxyBlanket(*pSvc,                       // Indicates the proxy to set
                             RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx
                             RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx
                             NULL,                        // Server principal name
                             RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx
                             RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
                             NULL,                        // client identity
                             EOAC_NONE                    // proxy capabilities
    );

    if (FAILED(hres))
    {
        LOG_ERROR("InitWmi: CoSetProxyBlanket failed: %x", hres);
        (*pSvc)->Release();
        (*pLoc)->Release();
        CoUninitialize();
        return -1; // Program has failed.
    }

    return 0;
}

std::wstring UtilsGetWMIInfo(HRESULT hres, IWbemLocator* pLoc, IWbemServices* pSvc, const std::wstring& wql,
                             const std::wstring& field, const std::wstring& dataType)
{

    std::wstring info;
    IEnumWbemClassObject* pEnumerator = NULL;

    hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t(wql.c_str()), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                           NULL, &pEnumerator);

    if (FAILED(hres))
    {
        LOGW_ERROR(L"ExecQuery failed: %x, wql:%s", hres, wql.c_str());
        return L"";
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn             = 0;
    while (pEnumerator)
    {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn)
        {
            break;
        }
        if (FAILED(hr))
        {
            LOG_WARN("pEnumerator->Next failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }

        VARIANT vtProp;
        hr = pclsObj->Get(field.c_str(), 0, &vtProp, 0, 0);
        if (FAILED(hr))
        {
            LOG_WARN("pclsObj->Get failed, errorCode:%x", hr);
            if (pclsObj)
            {
                pclsObj->Release();
                pclsObj = NULL;
            }
            break;
        }
        if (dataType == L"string" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            // info = WcharToString(vtProp.bstrVal);
            if (vtProp.bstrVal != NULL)
            {
                info = vtProp.bstrVal;
            }
        }
        else if (dataType == L"int" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            info = std::to_wstring(vtProp.intVal);
        }
        else if (dataType == L"bool" && !(vtProp.vt == VT_EMPTY || vtProp.vt == VT_NULL))
        {
            if (vtProp.boolVal)
            {
                info = L"true";
            }
            else
            {
                info = L"false";
            }
        }
        VariantClear(&vtProp);
        pclsObj->Release();
        pclsObj = NULL;
    }

    if (pEnumerator)
    {
        pEnumerator->Release();
        pEnumerator = NULL;
    }

    return info;
}

int UtilsUninitWMI(HRESULT& hres, IWbemLocator* pLoc, IWbemServices* pSvc)
{
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return 0;
}

int UtilsGetWMIInfoOnce(std::wstring& out, const std::wstring& wql, const std::wstring& field,
                        const std::wstring& dataType)
{
    if (wql.empty() || field.empty() || dataType.empty())
    {
        LOGW_ERROR(L"Param error! wql:%s", wql.c_str());
        return -1;
    }

    HRESULT hres;
    IWbemLocator* pLoc;
    IWbemServices* pSvc;
    std::wstring data;
    int i = 0;

    while (UtilsInitWMI(hres, &pLoc, &pSvc) != 0)
    {
        if (i < 3)
        {
            i++;
            LOGW_WARN(L"UtilsInitWMI error times:%d! wql:%s", i, wql.c_str());
            continue;
        }
        else
        {
            LOGW_ERROR(L"UtilsInitWMI error! wql:%s", wql.c_str());
            return -2;
        }
    }

    //查询域
    data = UtilsGetWMIInfo(hres, pLoc, pSvc, wql, field, dataType);
    out  = data;

    UtilsUninitWMI(hres, pLoc, pSvc);
    return 0;
}
