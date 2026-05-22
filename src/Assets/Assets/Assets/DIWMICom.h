#pragma once
#include <wbemidl.h>
#include <comdef.h>
#include <string>

namespace di_rest_client
{
std::string GetWMIInfo(HRESULT hres, IWbemLocator *pLoc, IWbemServices *pSvc, std::string wql, std::wstring field, const std::string& dataType);
int InitWmi(HRESULT &hres, IWbemLocator **pLoc, IWbemServices **pSvc);
int UnInitWmi(HRESULT &hres, IWbemLocator *pLoc, IWbemServices *pSvc);
}
