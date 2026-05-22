#include "WMICommInterface.h"
#include <Windows.h>
#include <userenv.h>
#include <comdef.h>
#include <iostream>

#pragma comment(lib, "wbemuuid.lib")

WMICommInterface::WMICommInterface()
{
    memset(m_szErrorMsg, 0, sizeof(m_szErrorMsg));
    m_pLoc = nullptr;
    m_pSvc = nullptr;
    m_pEnumerator = nullptr;
    m_bInitialized = false;
}

WMICommInterface::~WMICommInterface()
{
    Uninitialize();
}

bool WMICommInterface::Initialize(const wchar_t* pszNameSpace)
{
    int i = 0;
    while (i < 3)
    {
        ++i;
        if (InitWMI(pszNameSpace))
        {
            return true;
        }
    }
    return false;
}

void WMICommInterface::Uninitialize()
{
    if (m_pLoc)
    {
        m_pLoc->Release();
        m_pLoc = nullptr;
    }

    if (m_pSvc)
    {
        m_pSvc->Release();
        m_pSvc = nullptr;
    }

    if (m_pEnumerator)
    {
        m_pEnumerator->Release();
        m_pEnumerator = nullptr;
    }

    if (m_bInitialized)
    {
        CoUninitialize();
        m_bInitialized = false;
    }
}

bool WMICommInterface::ExecQuery(const wchar_t* pszWQL)
{
    if (!pszWQL || wcslen(pszWQL) <= 0)
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Param null or emprt!");
        return false;
    }

    if (!m_pSvc)
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Not initialized! m_pSvc null!");
        return false;
    }

    if (m_pEnumerator)
    {
        m_pEnumerator->Release();
        m_pEnumerator = nullptr;
    }
    // Step 6: Execute WQL query to get GPO information
    HRESULT hr = m_pSvc->ExecQuery(
        bstr_t(L"WQL"),
        bstr_t(pszWQL),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        nullptr,
        &m_pEnumerator
    );
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Failed to execute WMI query! ErrorCode:%lu", GetLastError());
        return false;
    }

    return true;
}

int WMICommInterface::GetNext(_variant_t& varResult, const std::wstring& strField)
{
    if (!m_pEnumerator)
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"No query excuted! m_pEnumerator null!");
        return -1;
    }

    // Step 7: Enumerate the RSOP_GPO instances and print the details
    IWbemClassObject* pClsObj = nullptr;
    ULONG uReturn = 0;
    if (m_pEnumerator->Next(WBEM_INFINITE, 1, &pClsObj, &uReturn) != S_OK)
    {
        uReturn = 0;
    }
    if (uReturn == 0)
    {
        if (pClsObj)
        {
            pClsObj->Release();
            pClsObj = nullptr;
        }
        return 0;
    }

    HRESULT hr = pClsObj->Get(strField.c_str(), 0, &varResult, nullptr, nullptr);
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Failed to get field:%s! ErrorCode:%lu", strField.c_str(), GetLastError());
        if (pClsObj)
        {
            pClsObj->Release();
            pClsObj = nullptr;
        }
        return -1;
    }

    if (pClsObj)
    {
        pClsObj->Release();
        pClsObj = nullptr;
    }
    return 1;
}

int WMICommInterface::GetNext(std::map<std::wstring, _variant_t>& mapResult, const std::set<std::wstring>& setField)
{
    if (!m_pEnumerator)
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"No query excuted! m_pEnumerator null!");
        return -1;
    }

    // Step 7: Enumerate the RSOP_GPO instances and print the details
    IWbemClassObject* pClsObj = nullptr;
    ULONG uReturn = 0;
    if (m_pEnumerator->Next(WBEM_INFINITE, 1, &pClsObj, &uReturn) != S_OK)
    {
        uReturn = 0;
    }
    if (uReturn == 0)
    {
        if (pClsObj)
        {
            pClsObj->Release();
            pClsObj = nullptr;
        }
        return 0;
    }

    mapResult.clear();
    for (std::set<std::wstring>::const_iterator it = setField.begin(); setField.end() != it; ++it)
    {
        _variant_t varField;
        HRESULT hr = pClsObj->Get(it->c_str(), 0, &varField, nullptr, nullptr);
        if (FAILED(hr))
        {
            _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Failed to get field:%s! ErrorCode:%lu", it->c_str(), GetLastError());
            if (pClsObj)
            {
                pClsObj->Release();
                pClsObj = nullptr;
            }
            return -1;
        }

        mapResult.insert(std::map<std::wstring, _variant_t>::value_type(*it, varField));
    }

    if (pClsObj)
    {
        pClsObj->Release();
        pClsObj = nullptr;
    }
    return 1;
}

const wchar_t* WMICommInterface::GetErrorMsg()
{
    return m_szErrorMsg;
}

bool WMICommInterface::InitWMI(const wchar_t* pszNameSpace)
{
    if (!pszNameSpace || wcslen(pszNameSpace) <= 0)
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t), L"Param null or emprt!");
        return false;
    }

    // 如果初始化过，那要先反初始化
    Uninitialize();

    // Step 1: Initialize COM
    HRESULT hr = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t),
                     L"Failed to initialize COM library! ErrorCode:%lu", GetLastError());
        return false;
    }
    m_bInitialized = true;

    // Step 2: Initialize security
    hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                              nullptr, EOAC_NONE, nullptr);
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t),
                     L"Failed to initialize security! ErrorCode:%lu", GetLastError());
        Uninitialize();
        return false;
    }

    // Step 3: Obtain the initial locator to WMI
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                          reinterpret_cast<LPVOID*>(&m_pLoc));
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t),
                     L"Failed to create IWbemLocator instance! ErrorCode:%lu", GetLastError());
        Uninitialize();
        return false;
    }

    // Step 4: Connect to WMI through the IWbemLocator::ConnectServer method
    hr = m_pLoc->ConnectServer(bstr_t(pszNameSpace), nullptr, nullptr, nullptr, 0, nullptr, nullptr, &m_pSvc);
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t),
                     L"Failed to connect to WMI! NameSpcace:%s, ErrorCode:%lu", pszNameSpace, GetLastError());
        Uninitialize();
        return false;
    }

    // Step 5: Set the security levels on the proxy
    hr = CoSetProxyBlanket(m_pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr, RPC_C_AUTHN_LEVEL_CALL,
                           RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr))
    {
        _snwprintf_s(m_szErrorMsg, sizeof(m_szErrorMsg) / sizeof(wchar_t),
                     L"Failed to set proxy blanket! ErrorCode:%lu", GetLastError());
        Uninitialize();
        return false;
    }
    return true;
}
