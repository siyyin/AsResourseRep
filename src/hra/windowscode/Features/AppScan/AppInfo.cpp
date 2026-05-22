#include "AppInfo.h"
#include <iostream>
#include <string>
#include <tchar.h>
#include <time.h>
#include <process.h>
#include <Psapi.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <algorithm>
#include <regex>
#include "json/json.h"
#include "utility/RegistryQuery.h"
#include "utility/comm.h"
#include "utility/HraJson.h"

#include <sstream>


#pragma comment(lib, "Psapi.lib")

AppInfo *gpAppInfo = NULL;
BOOL g_IsWinXP = false;

std::string WcharToString(std::wstring& src)
{
  int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src.c_str(), -1, NULL, 0, NULL, NULL);
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_UTF8, 0, src.c_str(), -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
}

std::string WcharToString(const wchar_t* src)
{
  int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_UTF8, 0, src, -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
}


std::wstring StringToWchar(const char* src)
{
  int unicodeLen = ::MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_UTF8, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
}

AppInfo::AppInfo( )
{
    memset(m_szSystemRootPath, 0, sizeof(m_szSystemRootPath));
    DWORD dwRet = GetEnvironmentVariableA("SystemRoot", m_szSystemRootPath, MAX_PATH - 1);
    if (dwRet == 0 || dwRet == MAX_PATH - 1) {
        strncpy_s(m_szSystemRootPath, MAX_PATH - 1, "C:\\Windows", -1);
    }
    gpAppInfo = this;
    m_bxp = true;
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion > 5) {
        m_bxp = false;
    }

	m_psapiDll = NULL;
	m_isLoad = false;
    if (!LoadLibraryVersion()) {
        exit(0);
    }
	if (!InitLibrary())
	{
		exit(0);
	}
    //m_pBuff = new char[FILE_INFO_SIZE];
    m_pBuff = (char*)malloc(FILE_INFO_SIZE);
    memset(m_pBuff, 0, FILE_INFO_SIZE);

    memset(&m_stSystemInfo, 0, sizeof(m_stSystemInfo));
}

AppInfo::~AppInfo(void)
{
    //if (m_pBuff != NULL) {
    //    delete[] m_pBuff;
    //}
    if (m_pBuff)
    {
        free(m_pBuff);
        m_pBuff = NULL;
    }

    if (m_hdll != NULL) {
        FreeLibrary(m_hdll);
        m_hdll = NULL;
    }

	if (m_psapiDll != NULL && m_isLoad)
	{
		FreeLibrary(m_psapiDll);
		m_psapiDll = NULL;
	}
}

bool AppInfo::LoadLibraryVersion()
{

    if (m_bxp) {
        m_hdll = LoadLibraryA("version.dll");
        if (m_hdll == NULL)
            return false;

        m_pGetFileVersionInfoSizeWfun = (GetFileVersionInfoSizeWfun)GetProcAddress(m_hdll,
                                                                                   "GetFileVersionInfoSizeW");
        if (m_pGetFileVersionInfoSizeWfun == NULL) {
            FreeLibrary(m_hdll);
            m_hdll = NULL;
            return false;
        }

        m_pGetFileVersionInfoWfun = (GetFileVersionInfoWfun)GetProcAddress(m_hdll,
                                                                           "GetFileVersionInfoW");
        if (m_pGetFileVersionInfoWfun == NULL) {
            FreeLibrary(m_hdll);
            m_hdll = NULL;
            return false;
        }
    } else {
        //m_hdll = LoadLibraryA("Api-ms-win-core-version-l1-1-0.dll");
        m_hdll = LoadLibraryA("version.dll");
        if (m_hdll == NULL)
            return false;

        m_pGetFileVersionInfoSizeExWfun = (GetFileVersionInfoSizeExWfun)GetProcAddress(m_hdll,
                                                                                       "GetFileVersionInfoSizeExW");
        if (m_pGetFileVersionInfoSizeExWfun == NULL) {
            FreeLibrary(m_hdll);
            m_hdll = NULL;
            return false;
        }

        m_pGetFileVersionInfoExWfun = (GetFileVersionInfoExWfun)GetProcAddress(m_hdll,
                                                                               "GetFileVersionInfoExW");
        if (m_pGetFileVersionInfoExWfun == NULL) {
            FreeLibrary(m_hdll);
            m_hdll = NULL;
            return false;
        }
    }

    return true;
}

char *AppInfo::GetFileInfoSub(const wchar_t *pSubblock, DWORD dwLangCharset)
{
    LPVOID lpData = NULL;
    UINT nQuerySize;
    wchar_t tmpstr[MAX_PATH] = {0};
    swprintf_s(tmpstr, MAX_PATH, L"\\StringFileInfo\\%08lx\\%s", dwLangCharset, pSubblock);
    if (::VerQueryValueW((void *)m_pBuff, tmpstr, &lpData, &nQuerySize))
        return (char *)lpData;
    return NULL;
}

DWORD AppInfo::GetFileInfo(const char *pFileName)
{
    DWORD m_dwLangCharset = 0;
    DWORD dwHandle;
    DWORD *pTransTable;
    UINT nQuerySize;
    DWORD dwDataSize;

    std::wstring filepath = StringToWchar(pFileName);
    if (pFileName == NULL)
        return 0;

    memset(m_pBuff, 0, FILE_INFO_SIZE);
    if (m_bxp) {
        dwDataSize = m_pGetFileVersionInfoSizeWfun(filepath.c_str(), &dwHandle);
        if (dwDataSize == 0 || dwDataSize > FILE_INFO_SIZE) {
            return 0;
        }

        if (!m_pGetFileVersionInfoWfun(filepath.c_str(), dwHandle, dwDataSize,
                                       (void *)m_pBuff)) {
            return 0;
        }
    } else {
        dwDataSize = m_pGetFileVersionInfoSizeExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), &dwHandle);
        if (dwDataSize == 0 || dwDataSize > FILE_INFO_SIZE) {
            return 0;
        }
        if (!m_pGetFileVersionInfoExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), dwHandle, dwDataSize,
                                         (void *)m_pBuff)) {
            return 0;
        }
    }

    if (!::VerQueryValueW(m_pBuff, L"\\VarFileInfo\\Translation", (void **)&pTransTable, &nQuerySize)) {
        return 0;
    }

    m_dwLangCharset = MAKELONG(HIWORD(pTransTable[0]), LOWORD(pTransTable[0]));
    return m_dwLangCharset;
}

int UnicodeToUtf8(char *pSrc, UINT32 uCodepage, char *pOut, int Outlen)
{
    int length = 0;
    if (pSrc == NULL || pOut == NULL) {
        return -1;
    }

    if (65001 == uCodepage) {
        length = (int)(strlen(pSrc));
        if (length >= Outlen - 1) {
            return -1;
        } else {
            strncpy_s(pOut, Outlen - 1, pSrc, length);
        }
    } else {
        length = WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)pSrc, -1, NULL, 0, NULL, NULL);
        if (length >= Outlen - 1) {
            return -1;
        }
        WideCharToMultiByte(CP_UTF8, 0, (wchar_t *)pSrc, -1, pOut, length, NULL, NULL);
    }

    return length;
}

int AnsiToUtf8(char *pSrc, UINT32 uCodepage, char *pOut, int Outlen)
{
    wchar_t wchartmp[1024] = {0};
    int length = 0;
    if (pSrc == NULL || pOut == NULL) {
        return -1;
    }

    if (65001 == uCodepage) {
        length = (int)(strlen(pSrc));
        if (length >= Outlen - 1) {
            return -1;
        } else {
            strncpy_s(pOut, Outlen - 1, pSrc, length);
        }
    } else {
        length = MultiByteToWideChar(CP_ACP, 0, pSrc, -1, NULL, NULL);
        if (length >= 1023) {
            return -1;
        }

        MultiByteToWideChar(CP_ACP, 0, pSrc, -1, wchartmp, length);

        length = WideCharToMultiByte(CP_UTF8, 0, wchartmp, -1, NULL, 0, NULL, NULL);
        if (length >= Outlen - 1) {
            return -1;
        }
        WideCharToMultiByte(CP_UTF8, 0, wchartmp, -1, pOut, length, NULL, NULL);
    }

    return length;
}

void AppInfo::EnrichApplication(APPINFO_APPLICATION &application, DWORD dLangCharset, const char *pPath)
{
    char buff[FILE_INFO_SIZE] = {0};
    if (dLangCharset > 0) {
        UINT32 uCodepage = LOWORD(dLangCharset);
        char *pTemp = NULL;

        pTemp = GetFileInfoSub(L"CompanyName", dLangCharset);
        if (pTemp != NULL) {
            UnicodeToUtf8(pTemp, uCodepage, application.vendor, sizeof(application.vendor) - 1);
        }

        size_t ilen = strlen(application.vendor);
        for (size_t i = 0; i < ilen; i++) {
            if (application.vendor[i] == '"') {
                application.vendor[i] = ' ';
            }
        }

        if (_strnicmp(application.vendor, "trend_company_name", strlen("trend_company_name")) == 0 || _strnicmp(application.vendor, "Trend Micro inc.", strlen("Trend Micro inc.")) == 0) {
            strcpy_s(application.vendor, "Asiainfo Security");
        }

        pTemp = GetFileInfoSub(L"ProductName", dLangCharset);
        if (pTemp != NULL) {
            UnicodeToUtf8(pTemp, uCodepage, application.strApplication, sizeof(application.strApplication) - 1);
        }

        ilen = strlen(application.strApplication);
        for (size_t i = 0; i < ilen; i++) {
            if (application.strApplication[i] == '"') {
                application.strApplication[i] = ' ';
            }
        }

        std::string strApplication = application.strApplication;
        if (_strnicmp(strApplication.c_str(), "Trend Micro", strlen("Trend Micro")) == 0) {
            strApplication = strApplication.replace(0, strlen("Trend Micro"), "Asiainfo Security");
            strcpy_s(application.strApplication, strApplication.c_str());
        }

        if (_strnicmp(strApplication.c_str(), "trend_product_name", strlen("trend_product_name")) == 0) {
            strApplication = strApplication.replace(0, strlen("trend_product_name"), "Asiainfo Security");
            strcpy_s(application.strApplication, strApplication.c_str());
        }

        pTemp = GetFileInfoSub(L"ProductVersion", dLangCharset);
        if (pTemp != NULL) {
            UnicodeToUtf8(pTemp, uCodepage, application.strApplicationversion, sizeof(application.strApplicationversion) - 1);
        }

        ilen = strlen(application.strApplicationversion);
        for (size_t i = 0; i < ilen; i++) {
            if (application.strApplicationversion[i] == '"') {
                application.strApplicationversion[i] = ' ';
            }
        }
    } 
}

void AppInfo::GetApplicationinfo(void)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 proc;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        return;
    }

    proc.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &proc)) {
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        if (proc.th32ProcessID == 0 || proc.th32ProcessID == 4) {
            continue;
        }

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.th32ProcessID);
        if (process == NULL) {
            continue;
        }

        wchar_t filepath[MAX_PATH] = {0};
        char file_path[MAX_PATH] = {0};
        if (m_pGetModuleFileNameEx(process, NULL, filepath, MAX_PATH) != 0) {
            strncpy_s(file_path, sizeof(file_path) - 1, WcharToString(filepath).c_str(), -1);
            static const char *s_pSystemRootPrefix = "\\SystemRoot\\";
            size_t nTextLen = strlen(file_path);
            size_t nPrefixLen = strlen(s_pSystemRootPrefix);
            if (nTextLen >= nPrefixLen && _strnicmp(file_path, s_pSystemRootPrefix, nPrefixLen) == 0) {
                char szTempPath[MAX_PATH] = {0};
                strcpy_s(szTempPath, file_path + nPrefixLen);
                _snprintf_s(file_path, MAX_PATH-1, "%s\\%s", m_szSystemRootPath, szTempPath);
            }

            std::map<std::string, APPINFO_APPLICATION>::iterator iter = m_Application.find(file_path);
            if (iter != m_Application.end()) {
                CloseHandle(process);
                continue;
            }

            DWORD dLangCharset = GetFileInfo(file_path);
            APPINFO_APPLICATION application = {0};
            EnrichApplication(application, dLangCharset, file_path);
            strncpy_s(application.strFilename, sizeof(application.strFilename) - 1, WcharToString(proc.szExeFile).c_str(), -1);    
            m_Application[file_path] = application;
        }
        CloseHandle(process);
    } while (Process32Next(hProcessSnap, &proc));

    CloseHandle(hProcessSnap);
    
    return;
}

bool AppInfo::InitLibrary(void)
{
	m_psapiDll = GetModuleHandle(_T("PSAPI.DLL"));
	if (NULL == m_psapiDll)
	{        
		m_psapiDll = ::LoadLibrary(_T("PSAPI.DLL"));
		m_isLoad = true;
	}

	if (NULL != m_psapiDll)
	{                

		m_pGetModuleFileNameEx  = reinterpret_cast<PFN_GETMODULEFILENAMEEX>( ::GetProcAddress(m_psapiDll, "GetModuleFileNameExW" ) );
		if (!m_pGetModuleFileNameEx)
		{
			::FreeLibrary(m_psapiDll);
			m_psapiDll = NULL;
			return false;
		}
	}
	else
	{
		return false;
	}
	return true;
}

std::string EscapeValue(std::string raw)
{
    for (size_t i = 0; i < raw.size(); i++) {
        if (raw[i] == '\\') {
            raw.replace(i, 1, "\\\\");
            i++;
            continue;
        }
    }
    return raw;
}

std::string EscapeValue2(std::string raw)
{
    for (size_t i = 0; i < raw.size(); i++) {
        if (raw[i] == '"') {
            raw.replace(i, 1, "");
            i--;
        }
    }
    return raw;
}

std::string EscapeValue3(std::string raw)
{
    for (size_t i = 0; i < raw.size(); i++) {
        if (raw[i] == '"') {
            raw.replace(i, 1, "\\\"");
            i++;
        }
    }
    return raw;
}

std::string EscapeValue4(std::string raw)
{
    for (size_t i = 0; i < raw.size(); i++) {
        if (raw[i] == '"') {
            raw.replace(i, 1, "'");
            i++;
        }
    }
    return raw;
}

std::map<std::string, APPINFO_SOFTWARE> g_mapAppInfo;
void GetSoftWare(HKEY RootKey, LPCTSTR lpSubKey)
{
    HKEY hkResult;
    HKEY hkRKey;
    LONG lReturn;
    std::wstring strBuffer;
    std::wstring strMidReg;

    DWORD index = 0;
    WCHAR szKeyName[MAX_LEN_256] = {0};
    WCHAR szBuffer[MAX_LEN_256] = {0};
    DWORD dwKeyLen = MAX_LEN_256;
    DWORD dwBuffLen = MAX_LEN_256;
    DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
    FILETIME ftLastWriteTime;

    lReturn = RegOpenKeyEx(RootKey, lpSubKey, 0, KEY_ALL_ACCESS, &hkResult);
    if (lReturn == ERROR_SUCCESS) {
        while (ERROR_NO_MORE_ITEMS != RegEnumKeyEx(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime)) {
            Sleep(1);
            index++;
            strBuffer = szKeyName;
            auto mIter = g_mapAppInfo.find(WcharToString(szKeyName));
            if (mIter != g_mapAppInfo.end()) {
                continue;
            }
            if (strBuffer.size() != 0) {
                APPINFO_SOFTWARE software = {0};
                std::wstring strMidReg = lpSubKey;
                strMidReg = strMidReg + L"\\" + strBuffer;
                if (RegOpenKeyEx(RootKey, strMidReg.c_str(), 0, KEY_ALL_ACCESS, &hkRKey) == ERROR_SUCCESS) {
                    WCHAR szParentKeyName[MAX_LEN_256] = {0};
                    DWORD dwParentKeyNameLen = MAX_LEN_256;
                    WCHAR szSystemComponent[MAX_LEN_256] = {0};
                    DWORD dwSystemComponentLen = MAX_LEN_256;
                    RegQueryValueEx(hkRKey, L"ParentKeyName", 0, &dwType, (LPBYTE)szParentKeyName, &dwParentKeyNameLen);
                    if (szParentKeyName[0] == 0) {
                        RegQueryValueEx(hkRKey, L"SystemComponent", 0, &dwType, (LPBYTE)szSystemComponent, &dwSystemComponentLen);
                    }

                    if (szParentKeyName[0] == 0 && szSystemComponent[0] != 1) {
                        if (RegQueryValueEx(hkRKey, L"DisplayVersion", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string Softversion = WcharToString(szBuffer).c_str();
                            Softversion = EscapeValue2(Softversion);
                            strncpy_s(software.strSoftversion, sizeof(software.strSoftversion) - 1, Softversion.c_str(), -1);
                        }
                        dwBuffLen = MAX_LEN_256;

                        if (RegQueryValueEx(hkRKey, L"Publisher", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string vendor = WcharToString(szBuffer).c_str();
                            vendor = EscapeValue2(vendor);
                            strncpy_s(software.vendor, sizeof(software.vendor) - 1, vendor.c_str(), -1);
                        }
                        dwBuffLen = MAX_LEN_256;

                        if (RegQueryValueEx(hkRKey, L"InstallLocation", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string path = WcharToString(szBuffer).c_str();
                            path = EscapeValue2(path);
                            strncpy_s(software.strInstalllocation, sizeof(software.strInstalllocation) - 1, path.c_str(), -1);
                        }

                        dwBuffLen = MAX_LEN_256;
                        if (RegQueryValueEx(hkRKey, L"DisplayName", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string Softname = WcharToString(szBuffer).c_str();
                            Softname = EscapeValue2(Softname);
                            strncpy_s(software.strSoftname, sizeof(software.strSoftname) - 1, Softname.c_str(), -1);
                            g_mapAppInfo[WcharToString(szKeyName)] = software;
                        }
                        dwBuffLen = MAX_LEN_256;
                    }
                    RegCloseKey(hkRKey);
                }
            }
            dwKeyLen = MAX_LEN_256;
        }
        RegCloseKey(hkResult);
    }
}

void GeRegUserWare(HKEY RootKey)
{
	HKEY hkResult;
	LONG lReturn;
	std::wstring strBuffer;
	std::wstring strMidReg;

	DWORD index = 0;
	WCHAR szKeyName[MAX_LEN_256] = {0};
	WCHAR szBuffer[MAX_LEN_256] = {0};
	DWORD dwKeyLen = MAX_LEN_256;
	DWORD dwBuffLen = MAX_LEN_256;
	DWORD dwType = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
	FILETIME ftLastWriteTime;

	lReturn = RegOpenKeyEx(RootKey, NULL, 0, KEY_ALL_ACCESS, &hkResult);
	if (lReturn == ERROR_SUCCESS) {
		while (ERROR_NO_MORE_ITEMS != RegEnumKeyEx(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime)) {
			Sleep(1);
			index++;
			strBuffer = szKeyName;
			strBuffer = strBuffer + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
			GetSoftWare(HKEY_USERS, strBuffer.c_str());
			dwKeyLen = MAX_LEN_256;
		}
		RegCloseKey(hkResult);
	}
}

void AppInfo::GetSoftware(void)
{
    GetSoftWare(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GeRegUserWare(HKEY_USERS);
}

static bool SplitVersion(const std::string& strOriginVersion,
						 std::string& strMajor,
						 std::string& strMin,
						 std::string& strReserve,
						 std::string& strBuildNum)
{
	std::vector<std::string> vecVersionComp;
	std::stringstream f(strOriginVersion);
	std::string strComponent;

	while (std::getline(f, strComponent, '.')) 
	{
		vecVersionComp.push_back(strComponent);	
	}

	if (vecVersionComp.size() == 4)
	{
		strMajor = vecVersionComp[0];
		strMin = vecVersionComp[1];
		strReserve = vecVersionComp[2];
		strBuildNum = vecVersionComp[3];

		return true;
	}

	return false;
}

static bool CompareStringCaseInsensitive(const std::string& strA, const std::string& strB)
{
	std::string strALower = strA;
	std::transform(strALower.begin(), strALower.end(), strALower.begin(), ::tolower);

	std::string strBLower = strB;
	std::transform(strBLower.begin(), strBLower.end(), strBLower.begin(), ::tolower);

	return strALower == strBLower;
}

static bool NormalizeMobaXCpeVersion(const std::string& strOriginVersion, 
									 std::string& strCpeVersion, 
									 std::string& strCpeUpdate)
{
	std::string strMajor;
	std::string strMin;
	std::string strReserve;
	std::string strBuildNum;

	if (SplitVersion(strOriginVersion, strMajor, strMin, strReserve, strBuildNum))
	{
		//split mobaxterm version into version and update
		strCpeUpdate = strBuildNum;
		strCpeVersion = strMajor + "." + strMajor;

		return true;
	}

	return false;
}

std::string AppInfo::GetAppInfo(void)
{
    std::string report;
    int cnt = 0;
    char buffer[MAX_LEN_512] = {0};
    bool  bfirst = true;
    report.reserve(1024 * 100);

    GetSoftware();
    GetApplicationinfo();
    GetSystemInfo();

    Json::Value jsRoot;
    Json::Value jsValue;
    for (auto iter = m_Application.begin(); iter != m_Application.end(); ++iter)
    {
		std::string strProductName = iter->second.strApplication;
		std::string strApplicationversion = iter->second.strApplicationversion;

		// default value
		std::string strCpeUpdate = "";

		// default value is display version or product version
		std::string strCpeVersion = strApplicationversion;

		//workaround for mobaxterm, we must add pattern in application vulnerability scan engine
		if (CompareStringCaseInsensitive(strProductName, "MobaXterm"))
		{
			std::string strMobaXVer;
			std::string strMobaXUpdate;
			bool bRet = NormalizeMobaXCpeVersion(strApplicationversion, strMobaXVer, strMobaXUpdate);

			if (bRet)
			{
				strCpeUpdate = strMobaXUpdate;
				strCpeVersion = strMobaXVer;
			}
		}
		
        jsValue["base_dir"] = iter->first.c_str();
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "a";
        jsValue["cpe_product"] = iter->second.strApplication;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = strCpeUpdate;
        jsValue["cpe_vendor"] = iter->second.vendor;
        jsValue["cpe_version"] = strCpeVersion;
        jsValue["file_name"] = iter->second.strFilename;
        jsRoot["cpe_items"].append(jsValue);
    }

    for (auto iter = g_mapAppInfo.begin(); iter != g_mapAppInfo.end(); ++iter)
    {
		std::string strProductName = iter->second.strSoftname;
		std::string strApplicationversion = iter->second.strSoftversion;

		// default value
		std::string strCpeUpdate = "";

		// default value is display version or product version
		std::string strCpeVersion = strApplicationversion;

		//workaround for mobaxterm, we must add pattern in application vulnerability in next version
		if (CompareStringCaseInsensitive(strProductName, "MobaXterm"))
		{
			std::string strMobaXVer;
			std::string strMobaXUpdate;
			bool bRet = NormalizeMobaXCpeVersion(strApplicationversion, strMobaXVer, strMobaXUpdate);

			if (bRet)
			{
				strCpeUpdate = strMobaXUpdate;
				strCpeVersion = strMobaXVer;
			}
		}

        jsValue["base_dir"] = iter->second.strInstalllocation;
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "a";
        jsValue["cpe_product"] = iter->second.strSoftname;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = strCpeUpdate;
        jsValue["cpe_vendor"] = iter->second.vendor;
        jsValue["cpe_version"] = strCpeVersion;
        jsValue["file_name"] = "";
        jsRoot["cpe_items"].append(jsValue);
    }

    //系统信息
    jsValue["base_dir"] = m_stSystemInfo.szSystemRoot;
    jsValue["cpe_edition"] = "";
    jsValue["cpe_language"] = "";
    jsValue["cpe_other"] = "";
    jsValue["cpe_part"] = "o";
    jsValue["cpe_product"] = "windows";
    jsValue["cpe_sw_edition"] = "";
    jsValue["cpe_target_hw"] = "";
    jsValue["cpe_target_sw"] = "";
    jsValue["cpe_update"] = "";
    jsValue["cpe_vendor"] = m_stSystemInfo.szVendor;
    jsValue["cpe_version"] = "0";
    jsValue["file_name"] = "";
    jsRoot["cpe_items"].append(jsValue);

    if (strlen(m_stSystemInfo.szCurrentBuild) > 0)
    {
        jsValue["base_dir"] = m_stSystemInfo.szSystemRoot;
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "o";
        jsValue["cpe_product"] = m_stSystemInfo.szSystemName;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = "";
        jsValue["cpe_vendor"] = m_stSystemInfo.szVendor;
        jsValue["cpe_version"] = m_stSystemInfo.szCurrentBuild;
        jsValue["file_name"] = "";
        jsRoot["cpe_items"].append(jsValue);
    }

    if (strlen(m_stSystemInfo.szCurrentVersion) > 0)
    {
        jsValue["base_dir"] = m_stSystemInfo.szSystemRoot;
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "o";
        jsValue["cpe_product"] = m_stSystemInfo.szSystemName;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = "";
        jsValue["cpe_vendor"] = m_stSystemInfo.szVendor;
        jsValue["cpe_version"] = m_stSystemInfo.szCurrentVersion;
        jsValue["file_name"] = "";
        jsRoot["cpe_items"].append(jsValue);
    }

    if (strlen(m_stSystemInfo.szDisplayVersion) > 0)
    {
        jsValue["base_dir"] = m_stSystemInfo.szSystemRoot;
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "o";
        jsValue["cpe_product"] = m_stSystemInfo.szSystemName;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = "";
        jsValue["cpe_vendor"] = m_stSystemInfo.szVendor;
        jsValue["cpe_version"] = m_stSystemInfo.szDisplayVersion;
        jsValue["file_name"] = "";
        jsRoot["cpe_items"].append(jsValue);
    }

    if (strlen(m_stSystemInfo.szReleaseId) > 0)
    {
        jsValue["base_dir"] = m_stSystemInfo.szSystemRoot;
        jsValue["cpe_edition"] = "";
        jsValue["cpe_language"] = "";
        jsValue["cpe_other"] = "";
        jsValue["cpe_part"] = "o";
        jsValue["cpe_product"] = m_stSystemInfo.szSystemName;
        jsValue["cpe_sw_edition"] = "";
        jsValue["cpe_target_hw"] = "";
        jsValue["cpe_target_sw"] = "";
        jsValue["cpe_update"] = "";
        jsValue["cpe_vendor"] = m_stSystemInfo.szVendor;
        jsValue["cpe_version"] = m_stSystemInfo.szReleaseId;
        jsValue["file_name"] = "";
        jsRoot["cpe_items"].append(jsValue);
    }
    report = JsonToString(jsRoot);

    m_Application.clear();
    std::map<std::string, APPINFO_APPLICATION>().swap(m_Application);
    g_mapAppInfo.clear();
    std::map<std::string, APPINFO_SOFTWARE>().swap(g_mapAppInfo);

    return report;
}

void AppInfo::GetSystemInfo()
{
    char szRegValueTmp[MAX_LEN_256];
    int nRegValueTmp = 0;

    memset(&m_stSystemInfo, 0, sizeof(m_stSystemInfo));
    _snprintf_s(m_stSystemInfo.szVendor, sizeof(m_stSystemInfo.szVendor), "microsoft");

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "SystemRoot"))
    {
        _snprintf_s(m_stSystemInfo.szSystemRoot, sizeof(m_stSystemInfo.szSystemRoot), "%s", szRegValueTmp);
    }

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentBuild"))
    {
        _snprintf_s(m_stSystemInfo.szCurrentBuild, sizeof(m_stSystemInfo.szCurrentBuild), "%s", szRegValueTmp);
    }

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "CurrentVersion"))
    {
        _snprintf_s(m_stSystemInfo.szCurrentVersion, sizeof(m_stSystemInfo.szCurrentVersion), "%s", szRegValueTmp);
    }

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "DisplayVersion"))
    {
        _snprintf_s(m_stSystemInfo.szDisplayVersion, sizeof(m_stSystemInfo.szDisplayVersion), "%s", szRegValueTmp);
    }

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ReleaseId"))
    {
        _snprintf_s(m_stSystemInfo.szReleaseId, sizeof(m_stSystemInfo.szReleaseId), "%s", szRegValueTmp);
    }

    memset(szRegValueTmp, 0, sizeof(szRegValueTmp));
    if (HRA_OK == RegQueryStrValue(szRegValueTmp, sizeof(szRegValueTmp),
        HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "ProductName"))
    {
        std::string strMatch;
        do
        {
            std::string strSystemName = szRegValueTmp;
            std::transform(strSystemName.begin(), strSystemName.end(), strSystemName.begin(), ::tolower);

            std::regex pattern("windows server [0-9]+");
            std::smatch retMatch;
            if (std::regex_search(strSystemName, retMatch, pattern))
            {
                pattern = " ";
                strMatch = std::regex_replace(retMatch.str(), pattern, "_");
                break;
            }

            pattern = std::regex("windows [0-9]+[\\.]?[0-9]+");
            if (std::regex_search(strSystemName, retMatch, pattern))
            {
                pattern = " ";
                strMatch = std::regex_replace(retMatch.str(), pattern, "_");
                break;
            }

            pattern = std::regex("windows vista");
            if (std::regex_search(strSystemName, retMatch, pattern))
            {
                pattern = " ";
                strMatch = std::regex_replace(retMatch.str(), pattern, "_");
                break;
            }

            pattern = std::regex("windows rt [0-9]+[\\.]?[0-9]+");
            if (std::regex_search(strSystemName, retMatch, pattern))
            {
                pattern = " ";
                strMatch = std::regex_replace(retMatch.str(), pattern, "_");
                break;
            }
        } while (false);

        if (!strMatch.empty())
        {
            _snprintf_s(m_stSystemInfo.szSystemName, sizeof(m_stSystemInfo.szSystemName), "%s", strMatch.c_str());
        }
    }

}