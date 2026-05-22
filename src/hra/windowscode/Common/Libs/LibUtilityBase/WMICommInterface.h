#pragma once
#include <string>
#include <set>
#include <map>
//#include <variant>
#include <Wbemidl.h>
#include <comutil.h>

class WMICommInterface
{
public:
    WMICommInterface();
    virtual ~WMICommInterface();

public:
    bool Initialize(const wchar_t* pszNameSpace);
    void Uninitialize();
    bool ExecQuery(const wchar_t* pszWQL);
    int GetNext(_variant_t& varResult, const std::wstring& strField);
    int GetNext(std::map<std::wstring, _variant_t>& mapResult, const std::set<std::wstring>& setField);
    const wchar_t* GetErrorMsg();
private:
    bool InitWMI(const wchar_t* pszNameSpace);

private:
    wchar_t m_szErrorMsg[4096];
    IWbemLocator* m_pLoc;
    IWbemServices* m_pSvc;
    IEnumWbemClassObject* m_pEnumerator;
    bool m_bInitialized;
};

