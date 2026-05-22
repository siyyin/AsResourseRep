#pragma once
#include <wbemidl.h>
#include <comdef.h>
#include <string>
#include "comm.h"

HRA_UTILITY_EXPORT int UtilsInitWMI(HRESULT& hres, IWbemLocator** pLoc, IWbemServices** pSvc);
HRA_UTILITY_EXPORT int UtilsUninitWMI(HRESULT& hres, IWbemLocator* pLoc, IWbemServices* pSvc);
HRA_UTILITY_EXPORT std::wstring UtilsGetWMIInfo(HRESULT hres, IWbemLocator* pLoc, IWbemServices* pSvc,
                                                const std::wstring& wql, const std::wstring& field,
                                                const std::wstring& dataType);

HRA_UTILITY_EXPORT int UtilsGetWMIInfoOnce(std::wstring& out, const std::wstring& wql, const std::wstring& field,
                                           const std::wstring& dataType);

