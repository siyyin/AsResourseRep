#include "Assetsinventory.h"
#include <iostream>
#include <string>
#include <tchar.h>
#include <LM.h>
#include <intrin.h>
#include <time.h>
#include <comdef.h>
#include <wbemidl.h>
#include <DSRole.h>
#include <dsgetdc.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <wtsapi32.h>
#include <process.h>
#include <Psapi.h>
#include <ntsecapi.h>
#include <openssl/sha.h>
#include "DIUtils.h"
#include "StringUtils.h"
#include "NetUtils.h"
#include "LogManager.h"
#include "DIWMICom.h"

#pragma comment(lib, "IPHLPAPI.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wtsapi32.lib")
//#pragma comment(lib, "Version.lib")
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Secur32.lib")

#define REGISTER_AGAIN_EVENT L"Global\\register_again_event"
HANDLE g_RegisterAgainEvent = NULL;

Assetsinventory *gpAssetsinventory = NULL;
BOOL g_IsWinXP = false;
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define INFO_BUFFER_SIZE 32767
#define MAX_BUFSIZE 1 * 1024 *1024

int UnicodeToUtf8(char *pSrc, UINT32 uCodepage, char *pOut, int Outlen);
int AnsiToUtf8(char *pSrc, UINT32 uCodepage, char *pOut, int Outlen);
Assetsinventory::Assetsinventory(char* pServerIp,char* pDeviceId,char* pAgentVersion)
{
	m_pDIAssetAutoRun = NULL;
	m_pDIAssetDB = NULL;
	m_pDIAssetPort = NULL;
	m_pDIAssetTask = NULL;
	m_pDIAssetWebService = NULL;

    memset(m_szSystemRootPath, 0, sizeof(m_szSystemRootPath));
    DWORD dwRet = GetEnvironmentVariableA("SystemRoot", m_szSystemRootPath, MAX_PATH - 1);
    if (dwRet == 0 || dwRet == MAX_PATH - 1) {
        strncpy_s(m_szSystemRootPath, MAX_PATH - 1, "C:\\Windows", -1);
    }

    gpAssetsinventory = this;
    m_uLastTime = 0;
    m_Userinfo.clear();
    std::vector<ASSETS_USER>().swap(m_Userinfo);
    InitializeCriticalSection(&m_cs);
    memset(&m_HostInfo, 0, sizeof(m_HostInfo));
    GetHostInfoInit();
    strncpy_s(m_HostInfo.strAgent_version, sizeof(m_HostInfo.strAgent_version) - 1, pAgentVersion, -1);

    m_bxp = true;
    OSVERSIONINFO osvi;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    if (osvi.dwMajorVersion > 5) {
        m_bxp = false;
    }

    if (!LoadLibraryVersion()) {
        DI_LOG_ERROR("LoadLibraryVersion erro ");
        exit(0);
    }

    m_pBuff = new char[FILE_INFO_SIZE];
    m_ServerIp = pServerIp;
    m_DeviceId = pDeviceId;
    m_bFirstUpLoadAsserts = TRUE;
}

Assetsinventory::~Assetsinventory(void)
{
    if (m_pBuff != NULL) {
        delete[] m_pBuff;
    }

    DeleteCriticalSection(&m_cs);
    if (m_hdll != NULL) {
        FreeLibrary(m_hdll);
        m_hdll = NULL;
    }

	if (m_pDIAssetAutoRun!= NULL){
		delete m_pDIAssetAutoRun;
		m_pDIAssetAutoRun = NULL;
	}
	if (m_pDIAssetDB != NULL){
		delete m_pDIAssetDB;
		m_pDIAssetDB = NULL;
	}
	if (m_pDIAssetPort != NULL){
		delete m_pDIAssetPort;
		m_pDIAssetPort= NULL;
	}
	if (m_pDIAssetTask != NULL){
		delete m_pDIAssetTask;
		m_pDIAssetTask = NULL;
	}
	if (m_pDIAssetWebService != NULL){
		delete m_pDIAssetWebService;
		m_pDIAssetWebService= NULL;
	}
}

bool Assetsinventory::LoadLibraryVersion()
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

void Assetsinventory::GetCpuInfo()
{
    int i = 0;
    HRESULT hres;
    IWbemLocator *pLoc;
    IWbemServices *pSvc;

    while (InitWmi(hres, &pLoc, &pSvc) != 0) {
        if (i < 3) {
            i++;
            continue;
        } else {
            return;
        }
    }

    IEnumWbemClassObject *pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Processor"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);

    if (FAILED(hres)) {
		DI_LOG_ERROR("InitWmi: ExecQuery failed: %x", hres);
        pSvc->Release();
        pLoc->Release();
        return;
    }

    IWbemClassObject *pclsObj = NULL;
    ULONG uReturn = 0;
    while (pEnumerator && i < MAX_CPU_NUM) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
                                       &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        m_HostInfo.CpuInfo[i].icore = 1;
        VARIANT vtProp;
        hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            strncpy_s(m_HostInfo.CpuInfo[i].strType, sizeof(m_HostInfo.CpuInfo[i].strType) - 1, WcharToString(vtProp.bstrVal).c_str(), -1);
        }

        hr = pclsObj->Get(L"NumberOfCores", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            m_HostInfo.CpuInfo[i].icore = vtProp.intVal;
        }

        hr = pclsObj->Get(L"NumberOfLogicalProcessors", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            m_HostInfo.CpuInfo[i].icore = m_HostInfo.CpuInfo[i].icore * vtProp.intVal;
        }

        ++i;
        m_HostInfo.CpuInfo[0].inum = i;
        VariantClear(&vtProp);
        pclsObj->Release();
    }
    pEnumerator->Release();

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

void Assetsinventory::GetDomain()
{
    HRESULT hres;
    IWbemLocator *pLoc;
    IWbemServices *pSvc;
    std::string data;
    int i = 0;

    while (InitWmi(hres, &pLoc, &pSvc) != 0) {
        if (i < 3) {
            i++;
            continue;
        } else {
            return;
        }
    }

    //查询域
    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT PartOfDomain FROM Win32_ComputerSystem", L"PartOfDomain", "bool");
    if (data == "true") {
        data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Domain FROM Win32_ComputerSystem", L"Domain", "string");
        strncpy_s(m_HostInfo.strDomain, sizeof(m_HostInfo.strDomain) - 1, data.c_str(), -1);
    } else {
        m_HostInfo.strDomain[0] = 0;
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();  //关闭该线程的COM库
}

void Assetsinventory::GetHostInfoInit()
{
    HRESULT hres;
    IWbemLocator *pLoc;
    IWbemServices *pSvc;
    std::string data;
    int i = 0;

    while (InitWmi(hres, &pLoc, &pSvc) != 0) {
        if (i < 3) {
            i++;
            continue;
        } else {
            return;
        }
    }

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Version FROM Win32_OperatingSystem", L"Version", "string");
    strncpy_s(m_HostInfo.strKernel, sizeof(m_HostInfo.strKernel) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Manufacturer FROM Win32_ComputerSystem", L"Manufacturer", "string");
    strncpy_s(m_HostInfo.strManufacturer, sizeof(m_HostInfo.strManufacturer) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Model FROM Win32_ComputerSystem", L"Model", "string");
    strncpy_s(m_HostInfo.strProduct_model, sizeof(m_HostInfo.strProduct_model) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Manufacturer FROM Win32_BIOS", L"Manufacturer", "string") + " " + GetWMIInfo(hres, pLoc, pSvc, "SELECT * FROM Win32_BIOS", L"Caption", "string");
    strncpy_s(m_HostInfo.strBios, sizeof(m_HostInfo.strBios) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT SerialNumber FROM Win32_OperatingSystem ", L"SerialNumber", "string");
    strncpy_s(m_HostInfo.strSerialnumber, sizeof(m_HostInfo.strSerialnumber) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT UUID FROM Win32_ComputerSystemProduct", L"UUID", "string");
    strncpy_s(m_HostInfo.strUuid, sizeof(m_HostInfo.strUuid) - 1, data.c_str(), -1);

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT InstallDate FROM Win32_OperatingSystem", L"InstallDate", "string");
    if (data.length() > 14) {
        struct tm sTime = {0};
        sscanf_s(data.c_str(), "%04d%02d%02d%02d%02d%02d", &sTime.tm_year, &sTime.tm_mon, &sTime.tm_mday, &sTime.tm_hour, &sTime.tm_min, &sTime.tm_sec);
        sTime.tm_year -= 1900;
        sTime.tm_mon -= 1;
        time_t t = mktime(&sTime);
        m_HostInfo.installtime = (unsigned int)t;
    }

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT LastBootUpTime FROM Win32_OperatingSystem", L"LastBootUpTime", "string");
    if (data.length() > 14) {
        struct tm sTime = {0};
        sscanf_s(data.c_str(), "%04d%02d%02d%02d%02d%02d", &sTime.tm_year, &sTime.tm_mon, &sTime.tm_mday, &sTime.tm_hour, &sTime.tm_min, &sTime.tm_sec);
        sTime.tm_year -= 1900;
        sTime.tm_mon -= 1;
        time_t t = mktime(&sTime);
        m_HostInfo.starttime = (unsigned int)t;
    }

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Caption FROM Win32_OperatingSystem", L"Caption", "string");
    std::string os = data;
    if (Is64BitOS()) {
        os = os + " 64";
    } else {
        os = os + " 32";
    }
    size_t pos = os.find("Windows");
    if (pos != std::string::npos) {
        os = os.erase(0, pos);
    }

    strncpy_s(m_HostInfo.strOs, sizeof(m_HostInfo.strOs) - 1, os.c_str(), -1);

    OSVERSIONINFOEX os_info = {0};
    os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);  
    GetVersionEx((OSVERSIONINFO *)&os_info);

    //操作系统类型
    if (os_info.wProductType != VER_NT_WORKSTATION) {
        m_HostInfo.iDeviceModel = 1;
    } else {
        m_HostInfo.iDeviceModel = 0;
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();  //关闭该线程的COM库

    GetCpuInfo();
    GetDomain();
}

__int64 Filetime2Int64(const FILETIME *ftime)
{
    LARGE_INTEGER li;
    li.LowPart = ftime->dwLowDateTime;
    li.HighPart = ftime->dwHighDateTime;
    return li.QuadPart;
}

__int64 CompareFileTime2(FILETIME preTime, FILETIME nowTime)
{
    return Filetime2Int64(&nowTime) - Filetime2Int64(&preTime);
}

std::string GetCpuUsage()
{
    char CpuUsage[100] = {0};
    FILETIME preIdleTime;
    FILETIME preKernelTime;
    FILETIME preUserTime;
    GetSystemTimes(&preIdleTime, &preKernelTime, &preUserTime);

    Sleep(3000);

    FILETIME idleTime;
    FILETIME kernelTime;
    FILETIME userTime;
    GetSystemTimes(&idleTime, &kernelTime, &userTime);

    __int64 idle = CompareFileTime2(preIdleTime, idleTime);
    __int64 kernel = CompareFileTime2(preKernelTime, kernelTime);
    __int64 user = CompareFileTime2(preUserTime, userTime);

    if (kernel + user == 0)
        return "";
    //（总的时间-空闲时间）/总的时间=占用cpu的时间就是使用率
    float temp = float(100.0 * (kernel + user - idle) / (kernel + user));
    _snprintf_s(CpuUsage, sizeof(CpuUsage)-1, "%.2f%%", temp);
    return CpuUsage;
}

std::string Assetsinventory::GetAdapter()
{
    PIP_ADAPTER_INFO pIPAdapterInfo = NULL;
    PIP_ADAPTER_INFO pIPAdapterInfoTmp = NULL;
    memset(&m_HostInfo.NetcardInfo, 0, sizeof(NETCARD_INFO) * MAX_NET_NUM);
    unsigned long ulSize = 0;
    int nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    if (ERROR_BUFFER_OVERFLOW == nRstCode) {
        pIPAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[(ulSize / 4096 + 1) * 4096];
        nRstCode = GetAdaptersInfo(pIPAdapterInfo, &ulSize);
    }
    if (ERROR_SUCCESS == nRstCode) {
        pIPAdapterInfoTmp = pIPAdapterInfo;
        while (pIPAdapterInfoTmp != NULL && m_HostInfo.NetcardInfo[0].inum < MAX_NET_NUM) {
            std::string Adapter = pIPAdapterInfoTmp->Description;
            std::size_t pos = Adapter.find(" - ");
            if (pos != std::string::npos) {
                Adapter = Adapter.substr(0, pos);
            }
            AnsiToUtf8((char *)Adapter.c_str(), 0, m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strNetCard, MAX_LEN_256 - 1);
            _snprintf_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strMac, MAX_LEN_MAC-1, "%02X-%02X-%02X-%02X-%02X-%02X",
                      pIPAdapterInfoTmp->Address[0],
                      pIPAdapterInfoTmp->Address[1],
                      pIPAdapterInfoTmp->Address[2],
                      pIPAdapterInfoTmp->Address[3],
                      pIPAdapterInfoTmp->Address[4],
                      pIPAdapterInfoTmp->Address[5]);

            IP_ADDR_STRING *pIPAddrString = &(pIPAdapterInfoTmp->IpAddressList);
            bool bfirst = true;
            while (pIPAddrString != NULL && strcmp(pIPAddrString->IpAddress.String, "0.0.0.0") != 0) {
                if (!bfirst) {
                    strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strip, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strip) - 1, ",", -1);
                }
                strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strip, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].strip) - 1, pIPAddrString->IpAddress.String, -1);
                pIPAddrString = pIPAddrString->Next;
                bfirst = false;
            }

            pIPAddrString = &(pIPAdapterInfoTmp->GatewayList);
            bfirst = true;
            while (pIPAddrString != NULL && strcmp(pIPAddrString->IpAddress.String, "0.0.0.0") != 0) {
                if (!bfirst) {
                    strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].gateway, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].gateway) - 1, ",", -1);
                }
                strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].gateway, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].gateway) - 1, pIPAddrString->IpAddress.String, -1);
                pIPAddrString = pIPAddrString->Next;
                bfirst = false;
            }

            //Dns
            bfirst = true;
            strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 2, "[", -1);
            IP_PER_ADAPTER_INFO *pPerAdapt = NULL;
            ULONG ulLen = 0;
            int err = GetPerAdapterInfo(pIPAdapterInfoTmp->Index, pPerAdapt, &ulLen);
            if (err == ERROR_BUFFER_OVERFLOW) {
                pPerAdapt = (PIP_PER_ADAPTER_INFO) new BYTE[(ulLen / 4096 + 1) * 4096];
                if (pPerAdapt != NULL) {
                    err = GetPerAdapterInfo(pIPAdapterInfoTmp->Index, pPerAdapt, &ulLen);
                    if (err == ERROR_SUCCESS) {
                        IP_ADDR_STRING *pNext = &(pPerAdapt->DnsServerList);
                        while (pNext && strcmp(pNext->IpAddress.String, "") != 0)  //手动DNS
                        {
                            if (!bfirst) {
                                strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 2, ",", -1);
                            }
                            strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 2, "\"", -1);
                            strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 2, pNext->IpAddress.String, -1);
                            strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 2, "\"", -1);
                            pNext = pNext->Next;
                            bfirst = false;
                        }
                    }
                    delete[] pPerAdapt;
                    pPerAdapt = NULL;
                }
            }

            strncat_s(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns, sizeof(m_HostInfo.NetcardInfo[m_HostInfo.NetcardInfo[0].inum].dns) - 1, "]", -1);

            m_HostInfo.NetcardInfo[0].inum++;
            pIPAdapterInfoTmp = pIPAdapterInfoTmp->Next;
        }
    }
    // 释放内存空间
    if (pIPAdapterInfo != NULL) {
        delete[] pIPAdapterInfo;
        pIPAdapterInfo = NULL;
    }
    return "";
}

void Assetsinventory::GetMemoryInfo()
{
    char info[100] = {0};
    const int GBYTES = 1073741824;
    const int MBYTES = 1048576;
    const int DKBYTES = 1024;
    MEMORYSTATUSEX statusex;
    statusex.dwLength = sizeof(statusex);
    if (GlobalMemoryStatusEx(&statusex)) {
        unsigned long long total = 0, remain_total = 0, avl = 0, remain_avl = 0;
        double decimal_total = 0, decimal_avl = 0;
        remain_total = statusex.ullTotalPhys % GBYTES;
        total = statusex.ullTotalPhys / GBYTES;
        avl = statusex.ullAvailPhys / GBYTES;
        remain_avl = statusex.ullAvailPhys % GBYTES;
        if (remain_total > 0)
            decimal_total = (remain_total / MBYTES) / (double)DKBYTES;
        if (remain_avl > 0)
            decimal_avl = (remain_avl / MBYTES) / (double)DKBYTES;

        decimal_total += (double)total;
        decimal_avl += (double)avl;

        _snprintf_s(info, sizeof(info)-1, "%.0f", decimal_total);
        strncpy_s(m_HostInfo.strMemory, sizeof(m_HostInfo.strMemory) - 1, info, -1);
        _snprintf_s(info, sizeof(info)-1, "%.2f", decimal_total - decimal_avl);
        strncpy_s(m_HostInfo.strMemory_use, sizeof(m_HostInfo.strMemory_use) - 1, info, -1);
    }
}

char *Assetsinventory::GetFileInfoSub(const wchar_t *pSubblock, DWORD dwLangCharset)
{
    LPVOID lpData = NULL;
    UINT nQuerySize;
    wchar_t tmpstr[MAX_PATH] = {0};
    swprintf_s(tmpstr, MAX_PATH, L"\\StringFileInfo\\%08lx\\%s", dwLangCharset, pSubblock);
    if (::VerQueryValueW((void *)m_pBuff, tmpstr, &lpData, &nQuerySize))
        return (char *)lpData;
    return NULL;
}

DWORD Assetsinventory::GetFileInfo(const char *pFileName)
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
            DI_LOG_ERROR("GetFileVersionInfo erro %s %d ", pFileName, dwDataSize);
            return 0;
        }
    } else {
        dwDataSize = m_pGetFileVersionInfoSizeExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), &dwHandle);
        if (dwDataSize == 0 || dwDataSize > FILE_INFO_SIZE) {
            return 0;
        }
        if (!m_pGetFileVersionInfoExWfun(FILE_VER_GET_NEUTRAL, filepath.c_str(), dwHandle, dwDataSize,
                                         (void *)m_pBuff)) {
            DI_LOG_ERROR("GetFileVersionInfo erro %s %d", pFileName, dwDataSize);
            return 0;
        }
    }

    if (!::VerQueryValueW(m_pBuff, L"\\VarFileInfo\\Translation", (void **)&pTransTable, &nQuerySize)) {
        DI_LOG_ERROR("VerQueryValueA erro %s", pFileName);
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

void Assetsinventory::EnrichApplication(ASSETS_APPLICATION &application, DWORD dLangCharset, const char *pPath)
{
	char buff[FILE_INFO_SIZE] = {0};
    if (dLangCharset > 0) {
        UINT32 uCodepage = LOWORD(dLangCharset);
        char *pTemp = NULL;
        VS_FIXEDFILEINFO *pVsInfo;
        UINT nQuerySize;
        if (VerQueryValueW(buff, L"\\", (void **)&pVsInfo, &nQuerySize)) {
            _snprintf_s(application.strFileversion, MAX_LEN_32-1, "%d.%d.%d.%d", HIWORD(pVsInfo->dwFileVersionMS), LOWORD(pVsInfo->dwFileVersionMS), HIWORD(pVsInfo->dwFileVersionLS), LOWORD(pVsInfo->dwFileVersionLS));
        }

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

    SHA_CTX ctx;
    SHA1_Init(&ctx);
    DWORD bytesRead = 0;
    HANDLE hFile = ::CreateFileW(StringToWchar(pPath).c_str(), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                 OPEN_EXISTING, NULL, NULL);
    if (hFile != NULL) {
        do {
            if (!::ReadFile(hFile, buff, FILE_INFO_SIZE, &bytesRead, NULL)) {
                memset(&ctx, 0, sizeof(SHA_CTX));
                break;
            } else {
                //Sleep(1);
                SHA1_Update(&ctx, buff, bytesRead);
            }
			Sleep(0);
        } while (bytesRead != 0);

        SHA1_Final(application.sha1, &ctx);
        CloseHandle(hFile);
    }
}

void Assetsinventory::UpdateApplicationinfo(bool bCreate, UINT64 pid, UINT64 uUseTime, wchar_t *pPath)
{
    std::string path = WcharToString(pPath);
    char *pchar = (char *)path.c_str();
    char filename[MAX_PATH] = {0};
    for (size_t i = path.length() - 1; i > 0; i--) {
        if (pchar[i] == L'\\' || pchar[i] == L'/') {
            strcpy_s(filename, &pchar[i + 1]);
            break;
        }
    }

    if (bCreate)  //创建
    {
        EnterCriticalSection(&m_cs);
        std::map<std::string, ASSETS_APPLICATION>::iterator iter = m_Application.find(path);
        if (iter != m_Application.end()) {
            iter->second.uUseTime = (UINT32)uUseTime;
            iter->second.bupload = true;
            iter->second.bdelete = false;
            std::map<std::string, std::vector<UINT64>>::iterator iter2 = m_ProcPathPid.find(path);
            if (iter2 != m_ProcPathPid.end()) {
                iter2->second.push_back(pid);
            }
            LeaveCriticalSection(&m_cs);
            return;
        }
        //LeaveCriticalSection(&m_cs);

        DWORD dLangCharset = GetFileInfo(path.c_str());
        ASSETS_APPLICATION application = {0};
        application.uUseTime = (UINT32)uUseTime;
        application.bupload = true;
        application.bdelete = false;
        EnrichApplication(application, dLangCharset, path.c_str());

        strncpy_s(application.strFilename, sizeof(application.strFilename) - 1, filename, -1);

        //EnterCriticalSection(&m_cs);
        m_Application[path] = application;
        vector<UINT64> tmp;
        tmp.push_back(pid);
        m_ProcPathPid[path] = tmp;
        LeaveCriticalSection(&m_cs);

    } else  //终止
    {
        EnterCriticalSection(&m_cs);
        std::map<std::string, ASSETS_APPLICATION>::iterator iter = m_Application.find(path);
        if (iter != m_Application.end()) {
            std::map<std::string, std::vector<UINT64>>::iterator iter2 = m_ProcPathPid.find(path);
            if (iter2 != m_ProcPathPid.end()) {
                for (std::vector<UINT64>::iterator it = iter2->second.begin(); it != iter2->second.end(); ++it) {
                    if (*it == pid) {
                        iter2->second.erase(it);
                        break;
                    }
                }
                if (iter2->second.size() == 0) {
                    iter->second.uUseTime = (UINT32)uUseTime;
                    iter->second.bdelete = true;
                    iter->second.bupload = true;
                }
            } else {
                iter->second.uUseTime = (UINT32)uUseTime;
                iter->second.bdelete = true;
                iter->second.bupload = true;
            }
            LeaveCriticalSection(&m_cs);
            return;
        }

        //LeaveCriticalSection(&m_cs);

        DWORD dLangCharset = GetFileInfo(path.c_str());
        ASSETS_APPLICATION application = {0};
        application.uUseTime = (UINT32)uUseTime;
        application.bdelete = true;
        application.bupload = true;
        EnrichApplication(application, dLangCharset, path.c_str());

        strncpy_s(application.strFilename, sizeof(application.strFilename) - 1, filename, -1);

        //EnterCriticalSection(&m_cs);
        m_Application[path] = application;
        LeaveCriticalSection(&m_cs);
    }
}

void Assetsinventory::GetApplicationinfo(void)
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

    if (!m_bFirstUpLoadAsserts) {
      for (auto iter = m_Application.begin(); iter != m_Application.end();iter++) {
        iter->second.bdelete = true;
      }
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
        if (GetModuleFileNameExW(process, NULL, filepath, MAX_PATH) != 0) {
            strncpy_s(file_path, sizeof(file_path) - 1, WcharToString(filepath).c_str(), -1);
            static const char *s_pSystemRootPrefix = "\\SystemRoot\\";
            size_t nTextLen = strlen(file_path);
            size_t nPrefixLen = strlen(s_pSystemRootPrefix);
            if (nTextLen >= nPrefixLen && _strnicmp(file_path, s_pSystemRootPrefix, nPrefixLen) == 0) {
                char szTempPath[MAX_PATH] = {0};
                strcpy_s(szTempPath, file_path + nPrefixLen);
                _snprintf_s(file_path, MAX_PATH-1, "%s\\%s", m_szSystemRootPath, szTempPath);
            }

            std::map<std::string, ASSETS_APPLICATION>::iterator iter = m_Application.find(file_path);
            if (iter != m_Application.end()) {
                iter->second.bdelete = false;
                iter->second.uUseTime = (UINT32)time(NULL);
                CloseHandle(process);
                continue;
            }

            EnterCriticalSection(&m_cs);
            DWORD dLangCharset = GetFileInfo(file_path);
            ASSETS_APPLICATION application = {0};
            application.uUseTime = (unsigned int)time(NULL);
            EnrichApplication(application, dLangCharset, file_path);

            strncpy_s(application.strFilename, sizeof(application.strFilename) - 1, WcharToString(proc.szExeFile).c_str(), -1);
            application.bupload = true;
            
            m_Application[file_path] = application;
            LeaveCriticalSection(&m_cs);
        }
        CloseHandle(process);
		//Sleep(1000);
    } while (Process32Next(hProcessSnap, &proc));

    CloseHandle(hProcessSnap);
    
    return;
}

void Assetsinventory::GetDiskCapacity()
{
    char info[100] = {0};
    wchar_t szDevice[MAX_PATH] = {0};
    BOOL fResult;
    unsigned _int64 i64FreeBytesToCaller;
    unsigned _int64 i64TotalBytes;
    unsigned _int64 i64FreeBytes;
    unsigned _int64 total = 0;
    unsigned _int64 free = 0;
    std::vector<std::wstring> vDevice;
    int i = 0;
    DWORD dwLen = GetLogicalDriveStrings(0, NULL);
    if (dwLen >= MAX_PATH) {
        return;
    }
    GetLogicalDriveStrings(dwLen, szDevice);

    while (*(szDevice + i) != '\0') {
        vDevice.push_back(szDevice + i);
        i = i + (int)wcslen(szDevice + i) + 1;
    }

    for (unsigned int i = 0; i < vDevice.size() && i < MAX_DISK_NUM; ++i) {
        i64FreeBytesToCaller = 0;
        i64TotalBytes = 0;
        i64FreeBytes = 0;
        fResult = GetDiskFreeSpaceEx(
            vDevice[i].c_str(),
            (PULARGE_INTEGER)&i64FreeBytesToCaller,
            (PULARGE_INTEGER)&i64TotalBytes,
            (PULARGE_INTEGER)&i64FreeBytes);

        DWORD FileAttributes = GetFileAttributesW(vDevice[i].c_str());
        if (FileAttributes & FILE_ATTRIBUTE_ENCRYPTED)
            m_HostInfo.DiskInfo[i].strencrypt[0] = '1';
        else
            m_HostInfo.DiskInfo[i].strencrypt[0] = '0';

        DWORD dwVolumeSerialNum;
        DWORD dwMaxComponentLength;
        DWORD dwSysFlags;
        char szVolumeNameBuf[MAX_PATH] = {0};

        GetVolumeInformationA(WcharToString(vDevice[i]).c_str(), szVolumeNameBuf, MAX_PATH, &dwVolumeSerialNum, &dwMaxComponentLength, &dwSysFlags, m_HostInfo.DiskInfo[i].filetype, sizeof(m_HostInfo.DiskInfo[i].filetype));

        strncpy_s(m_HostInfo.DiskInfo[i].strDiskname, 3, WcharToString(vDevice[i]).c_str(), -1);
        m_HostInfo.DiskInfo[i].ftotal = (float)i64TotalBytes / 1024 / 1024 / 1024;
        m_HostInfo.DiskInfo[i].fuse = (float)(i64TotalBytes - i64FreeBytes) / 1024 / 1024 / 1024;

        m_HostInfo.DiskInfo[0].inum = i + 1;
    }
}

void Assetsinventory::GetHostinfo(void)
{
    strncpy_s(m_HostInfo.strHostName, sizeof(m_HostInfo.strHostName) - 1, GetDeviceName().c_str(), -1);
    strncpy_s(m_HostInfo.strCpu_usage, sizeof(m_HostInfo.strCpu_usage) - 1, GetCpuUsage().c_str(), -1);
    GetAdapter();
    GetMemoryInfo();
    GetDiskCapacity();
    GetDomain();
}

BOOL Assetsinventory::CheckProcessUserIsDomain(DWORD &dwPID)
{
    HANDLE hToken = NULL;
    PTOKEN_USER pTokenUser = NULL;
    DWORD dwSize = 0;
    TCHAR szUserName[MAX_PATH];
    DWORD dwUserNameSize;
    TCHAR szDomainName[MAX_PATH];
    DWORD dwDomainNameSize;
    SID_NAME_USE snu;
    if (dwPID > 0) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPID);
        if (OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken)) {
            if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                if (GetLastError() == 122) {
                    pTokenUser = NULL;
                    if (dwSize >= MAX_BUFSIZE){
                      DI_LOG_WARN("CheckProcessUserIsDomain malloc a large buffer.");
                    }
                    pTokenUser = (PTOKEN_USER)malloc(dwSize);
                    if (GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
                        std::vector<std::wstring>::iterator it = m_strDomainUserName.begin();
                        for (; it != m_strDomainUserName.end(); it++) {
                            BOOL bRet = LookupAccountSid(NULL, pTokenUser->User.Sid,
                                                         szUserName, &dwUserNameSize,
                                                         szDomainName, &dwDomainNameSize,
                                                         &snu);
                            if (*it == (std::wstring)szUserName)
                            {
                              CloseHandle(hToken);
                              CloseHandle(hProcess);
                              return TRUE;
                            }
                                
                        }
                    }
                    free(pTokenUser);
                }
            }
            CloseHandle(hToken);
        }
        CloseHandle(hProcess);
    }
    return FALSE;
}

DWORD Assetsinventory::FindProcessPIDByName(LPCTSTR szProcessName)
{
    DWORD dwPID = 0;
    HANDLE hProcessSnap = NULL;
    PROCESSENTRY32 pe32 = {0};
    if (szProcessName) {
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcessSnap != INVALID_HANDLE_VALUE) {
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hProcessSnap, &pe32)) {
                do {
                    if (!_wcsicmp(pe32.szExeFile, szProcessName)) {
                        // 检测是否为域账户
                        dwPID = pe32.th32ProcessID;
                        if (CheckProcessUserIsDomain(dwPID))
                            break;
                    }
                } while (Process32Next(hProcessSnap, &pe32));
            }
            CloseHandle(hProcessSnap);
        }
    }
    return dwPID;
}

void GetGroups(WCHAR *name, std::wstring &gruop, WCHAR *servername = NULL)
{
    LPLOCALGROUP_USERS_INFO_0 pBuf = NULL;
    DWORD dwLevel = 0;
    DWORD dwPrefMaxLen = MAX_PREFERRED_LENGTH;
    DWORD dwEntriesRead = 0;
    DWORD dwTotalEntries = 0;
    NET_API_STATUS nStatus;

    nStatus = NetUserGetLocalGroups(servername,
                                    name,
                                    dwLevel,
                                    LG_INCLUDE_INDIRECT,
                                    (LPBYTE *)&pBuf,
                                    dwPrefMaxLen,
                                    &dwEntriesRead,
                                    &dwTotalEntries);
    if (nStatus == NERR_Success) {
        LPLOCALGROUP_USERS_INFO_0 pTmpBuf;
        DWORD i;
        DWORD dwTotalCount = 0;

        if ((pTmpBuf = pBuf) != NULL) {
            for (i = 0; i < dwEntriesRead; i++) {
                if (pTmpBuf == NULL) {
                    break;
                }

                if (i > 0) {
                    gruop.append(L";");
                }
                gruop.append(pTmpBuf->lgrui0_name);

                pTmpBuf++;
                dwTotalCount++;
            }
        }
    }

    if (pBuf != NULL)
        NetApiBufferFree(pBuf);

    return;
}

void Assetsinventory::GetUser(void)
{
    PLUID sessions;
    ULONG count;
    NTSTATUS retval;
    PSECURITY_LOGON_SESSION_DATA sessionData = NULL;
    ASSETS_USER assetsUser;
    retval = LsaEnumerateLogonSessions(&count, &sessions);
    wchar_t szUserName[256] = {0};
    HANDLE hDupToken = NULL;
    DWORD dwUserNameLen = 256;
    BOOL bIsImpersonate = FALSE;
    if (retval != STATUS_SUCCESS) {
        DI_LOG_ERROR("LsaEnumerate failed %lu", LsaNtStatusToWinError(retval));
        return;
    }

    m_strDomainUserName.clear();
    std::vector<std::wstring>().swap(m_strDomainUserName);
    for (int i = 0; i < (int)count; i++) {
        retval = LsaGetLogonSessionData(&sessions[i], &sessionData);
        if (retval != STATUS_SUCCESS) {
            DI_LOG_ERROR("LsaGetLogonSessionData failed %lu", LsaNtStatusToWinError(retval));
            if (sessionData)
                LsaFreeReturnBuffer(sessionData);
            LsaFreeReturnBuffer(sessions);
            return;
        }
        if (!sessionData) {
            DI_LOG_ERROR("Invalid logon session data");
            LsaFreeReturnBuffer(sessions);
            return;
        }

        if (sessionData->UserName.Length != 0)
            if (sessionData->DnsDomainName.Length != 0)
                m_strDomainUserName.push_back(sessionData->UserName.Buffer);

        LsaFreeReturnBuffer(sessionData);
    }

    for (int i = 0; i < (int)count; i++) {
        retval = LsaGetLogonSessionData(&sessions[i], &sessionData);
        if (retval != STATUS_SUCCESS) {
            DI_LOG_ERROR("LsaGetLogonSessionData failed %lu", LsaNtStatusToWinError(retval));
            if (sessionData)
                LsaFreeReturnBuffer(sessionData);
            LsaFreeReturnBuffer(sessions);
            return;
        }
        if (!sessionData) {
            DI_LOG_ERROR("Invalid logon session data");
            LsaFreeReturnBuffer(sessions);
            return;
        }
        if (sessionData->UserName.Length != 0) {
            memset(&assetsUser, 0, sizeof(assetsUser));
            strncpy_s(assetsUser.strUserName, sizeof(assetsUser.strUserName) - 1, WcharToString((sessionData->UserName).Buffer).c_str(), -1);

            if (sessionData->DnsDomainName.Length != 0)  //域账号
            {
                assetsUser.strType[0] = '1';
                assetsUser.strLocalAdmin[0] = '0';
                LPUSER_INFO_2 bufptr = NULL;
                NET_API_STATUS t2;
                {
                    //if current process user is system,we need impersonate to current logon user
                    GetUserName(szUserName, &dwUserNameLen);
                    if (_wcsicmp(szUserName, _T("system")) == 0) {
                        DWORD dwProcessID = FindProcessPIDByName(_T("explorer.exe"));
                        if (dwProcessID > 0) {
                            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwProcessID);
                            OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hDupToken);
                            CloseHandle(hProcess);
                            if (hDupToken) {
                                bIsImpersonate = ImpersonateLoggedOnUser(hDupToken);
                                if (bIsImpersonate) {
                                    t2 = NetUserGetInfo(sessionData->DnsDomainName.Buffer, (sessionData->UserName).Buffer, 2, (LPBYTE *)&bufptr);
                                    std::wstring group;
                                    GetGroups((sessionData->UserName).Buffer, group, sessionData->DnsDomainName.Buffer);
                                    strncpy_s(assetsUser.strGroup, sizeof(assetsUser.strGroup) - 1, WcharToString(group).c_str(), -1);
                                    if (bIsImpersonate)
                                        RevertToSelf();
                                }
                                CloseHandle(hDupToken);
                            }
                        }
                    }
                }
                if (bufptr != NULL) {
                    strncpy_s(assetsUser.strChpswtime, sizeof(assetsUser.strChpswtime) - 1, to_string(time(NULL) - bufptr->usri2_password_age).c_str(), -1);
                    assetsUser.uStatus = bufptr->usri2_flags;
                    if (bufptr != NULL) {
                        NetApiBufferFree(bufptr);
                        bufptr = NULL;
                    }
                } else {
                    DI_LOG_DEBUG("NetUserGetInfo: last=%d,return=%d\n", GetLastError(), t2);
                }
            } else {
                LPUSER_INFO_3 bufptr = NULL;
                NET_API_STATUS t3;
                t3 = NetUserGetInfo(0, (sessionData->UserName).Buffer, 3, (LPBYTE *)&bufptr);
                std::wstring group;
                GetGroups((sessionData->UserName).Buffer, group);
                strncpy_s(assetsUser.strGroup, sizeof(assetsUser.strGroup) - 1, WcharToString(group).c_str(), -1);

                if (bufptr == NULL) {
                    assetsUser.strType[0] = '0';
                    assetsUser.strLocalAdmin[0] = '0';
                } else {
                    assetsUser.uStatus = bufptr->usri3_flags;
                    if (bufptr->usri3_flags & UF_NORMAL_ACCOUNT)
                        assetsUser.strType[0] = '0';
                    else
                        assetsUser.strType[0] = '1';
                    strncpy_s(assetsUser.strChpswtime, sizeof(assetsUser.strChpswtime) - 1, to_string(time(NULL) - bufptr->usri3_password_age).c_str(), -1);
                    if (bufptr->usri3_priv == USER_PRIV_ADMIN)
                        assetsUser.strLocalAdmin[0] = '1';
                    else
                        assetsUser.strLocalAdmin[0] = '0';
                    if (bufptr != NULL) {
                        NetApiBufferFree(bufptr);
                        bufptr = NULL;
                    }
                }
            }
        }
        if (sessionData->LogonType >= 0 && sessionData->LogonType <= 13)
            assetsUser.uLogonType = (unsigned int)((SECURITY_LOGON_TYPE)sessionData->LogonType);
        if (sessionData->LogonTime.QuadPart > 0)
            assetsUser.uLoginTime = (LONGLONG)(sessionData->LogonTime.QuadPart - 116444736000000000) / 10000000;
        if (sessionData->LogonDomain.Length != 0) {
            strncpy_s(assetsUser.strDomain, sizeof(assetsUser.strDomain) - 1, WcharToString((sessionData->LogonDomain).Buffer).c_str(), -1);
        }
        assetsUser.lSessionID = sessionData->Session;

        memcpy(assetsUser.strHostName, m_HostInfo.strHostName, sizeof(m_HostInfo.strHostName));
        _snprintf_s(assetsUser.strUser, MAX_LEN_512-1, "%s\\%s", assetsUser.strDomain, assetsUser.strUserName);
        if (assetsUser.strUserName[0] != 0) {
            m_Userinfo.push_back(assetsUser);
        }
        LsaFreeReturnBuffer(sessionData);
    }
    LsaFreeReturnBuffer(sessions);
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

std::map<std::string, ASSETS_SOFTWARE> g_mapSoftInfo;
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
            auto mIter = g_mapSoftInfo.find(WcharToString(szKeyName));
            if (mIter != g_mapSoftInfo.end()) {
                continue;
            }
            if (strBuffer.size() != 0) {
                ASSETS_SOFTWARE software = {0};
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

                        if (RegQueryValueEx(hkRKey, L"InstallDate", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string installtime = WcharToString(szBuffer).c_str();
                            if (installtime.length() == 8) {
                                struct tm sTime = {0};
                                sscanf_s(installtime.c_str(), "%04d%02d%02d", &sTime.tm_year, &sTime.tm_mon, &sTime.tm_mday);
                                sTime.tm_year -= 1900;
                                sTime.tm_mon -= 1;
                                time_t t = mktime(&sTime);
                                _snprintf_s(software.strInstallTime, MAX_LEN_32-1, sizeof(software.strInstallTime) - 1, "%d", t);
                                if (strlen(software.strInstallTime) != 10) {
                                    software.strInstallTime[0] = 0;
                                }
                            }
                        }

                        if (software.strInstallTime[0] == 0) {
                            time_t t = FileTimeToUnixTime(ftLastWriteTime);
                            _snprintf_s(software.strInstallTime, MAX_LEN_32-1, sizeof(software.strInstallTime) - 1, "%d", t);
                            if (strlen(software.strInstallTime) != 10) {
                                software.strInstallTime[0] = 0;
                            }
                        }

                        dwBuffLen = MAX_LEN_256;

                        if (RegQueryValueEx(hkRKey, L"EstimatedSize", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            software.uSize = *(unsigned int *)szBuffer;
                        }
                        dwBuffLen = MAX_LEN_256;

                        if (RegQueryValueEx(hkRKey, L"DisplayName", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen) == ERROR_SUCCESS) {
                            std::string Softname = WcharToString(szBuffer).c_str();
                            Softname = EscapeValue2(Softname);
                            strncpy_s(software.strSoftname, sizeof(software.strSoftname) - 1, Softname.c_str(), -1);
                            g_mapSoftInfo[WcharToString(szKeyName)] = software;
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

void Assetsinventory::GetSoftware(void)
{
    m_mapLastSoftInfoAdd.clear();
    std::map<std::string, ASSETS_SOFTWARE>().swap(m_mapLastSoftInfoAdd);
    m_mapLastSoftInfoDel.clear();
    std::map<std::string, ASSETS_SOFTWARE>().swap(m_mapLastSoftInfoDel);
    m_mapLastSoftInfo.clear();
    std::map<std::string, ASSETS_SOFTWARE>().swap(m_mapLastSoftInfo);
    if (!m_bFirstUpLoadAsserts) {
        m_mapLastSoftInfo = g_mapSoftInfo;
    }
    g_mapSoftInfo.clear();
    std::map<std::string, ASSETS_SOFTWARE>().swap(g_mapSoftInfo);

    GetSoftWare(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
    GetSoftWare(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall");
	GeRegUserWare(HKEY_USERS);

    //和上次比较，添加新安装的
    for (auto gIter = g_mapSoftInfo.begin(); gIter != g_mapSoftInfo.end(); gIter++) {
        auto mIter = m_mapLastSoftInfo.find(gIter->first);
        if (mIter == m_mapLastSoftInfo.end())
            m_mapLastSoftInfoAdd.insert(make_pair(gIter->first, gIter->second));
        else {
            if (strcmp(gIter->second.vendor, mIter->second.vendor) || strcmp(gIter->second.strSoftversion, mIter->second.strSoftversion) || strcmp(gIter->second.strSoftname, mIter->second.strSoftname) || strcmp(gIter->second.strInstalllocation, mIter->second.strInstalllocation) || strcmp(gIter->second.strInstallTime, mIter->second.strInstallTime) || (gIter->second.uSize != mIter->second.uSize))
                m_mapLastSoftInfoAdd.insert(make_pair(gIter->first, gIter->second));
        }
    }

    //和上次比较，添加卸载的
    for (auto mIter = m_mapLastSoftInfo.begin(); mIter != m_mapLastSoftInfo.end(); mIter++) {
        auto gIter = g_mapSoftInfo.find(mIter->first);
        if (gIter == g_mapSoftInfo.end())
            m_mapLastSoftInfoDel.insert(make_pair(mIter->first, mIter->second));
        else {
            if (strcmp(gIter->second.vendor, mIter->second.vendor) || strcmp(gIter->second.strSoftversion, mIter->second.strSoftversion) || strcmp(gIter->second.strSoftname, mIter->second.strSoftname) || strcmp(gIter->second.strInstalllocation, mIter->second.strInstalllocation) || strcmp(gIter->second.strInstallTime, mIter->second.strInstallTime) || (gIter->second.uSize != mIter->second.uSize))
                m_mapLastSoftInfoDel.insert(make_pair(mIter->first, mIter->second));
        }
    }
}

std::string Assetsinventory::ConvertToJson(void)
{
    std::string report;
    bool bfirst = true;
    int cnt = 0;
    char buffer[MAX_LEN_512] = {0};
    report.reserve(1024 * 1000);
    //report.append("{\"X-DI-CUSTOMERID\": \"");
    //report.append(WcharToString(g_LocalConfig.strCustomerIDValue));
    //report.append("\",\"hostinfo\": {");   //此处需要增加X-DI-CUSTOMERID
    report.append("{\"company\": \"ASIA\",\"hostinfo\": {");  //此处需要增加X-DI-CUSTOMERID

    _snprintf_s(buffer, MAX_LEN_512-1, "\"hostname\":\"%s\",", m_HostInfo.strHostName);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"domain\":\"%s\",", m_HostInfo.strDomain);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"os\":\"%s\",", m_HostInfo.strOs);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"mac\":\"%s\",", m_HostInfo.strMac);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"netcard\":\"%s\",", m_HostInfo.strNetCard);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"local_ip\":\"%s\",", m_HostInfo.strip);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"gateway\":\"%s\",", m_HostInfo.gateway);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"serialnumber\":\"%s\",", m_HostInfo.strSerialnumber);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"uuid\":\"%s\",", m_HostInfo.strUuid);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"starttime\":%d,", m_HostInfo.starttime);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"installtime\":%d,", m_HostInfo.installtime);
    report.append(buffer);

    if (m_HostInfo.dns[0] == 0) {
        report.append("\"dns\":[],");
    } else {
        _snprintf_s(buffer, MAX_LEN_512-1, "\"dns\":%s,", m_HostInfo.dns);
        report.append(buffer);
    }

    //_snprintf_s(buffer, MAX_LEN_512-1, "\"external_ip\":\"%s\",", m_HostInfo.strip);
    report.append("\"external_ip\":\"\",");

    report.append("\"net\":[");

    for (int i = 0; i < m_HostInfo.NetcardInfo[0].inum; i++) {
        if (i == m_HostInfo.NetcardInfo[1].inum) {
            continue;
        }
        if (!bfirst) {
            report.append(",");
        }
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"name\":\"%s\",", m_HostInfo.NetcardInfo[i].strNetCard);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"local_ip\":\"%s\",", m_HostInfo.NetcardInfo[i].strip);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"gateway\":\"%s\",", m_HostInfo.NetcardInfo[i].gateway);
        report.append(buffer);
        if (m_HostInfo.dns[0] == 0) {
            report.append("\"dns\":[],");
        } else {
            _snprintf_s(buffer, MAX_LEN_512-1, "\"dns\":%s,", m_HostInfo.NetcardInfo[i].dns);
            report.append(buffer);
        }
        report.append("\"external_ip\":\"\",");
        _snprintf_s(buffer, MAX_LEN_512-1, "\"mac\":\"%s\"}", m_HostInfo.NetcardInfo[i].strMac);
        report.append(buffer);
        bfirst = false;
    }
    report.append("],");

    _snprintf_s(buffer, MAX_LEN_512-1, "\"device_model\":%d,", m_HostInfo.iDeviceModel);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"kernel\":\"%s\",", m_HostInfo.strKernel);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"manufacturer\":\"%s\",", m_HostInfo.strManufacturer);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"product_model\":\"%s\",", m_HostInfo.strProduct_model);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"bios\":\"%s\",", m_HostInfo.strBios);
    report.append(EscapeValue(buffer));
    _snprintf_s(buffer, MAX_LEN_512-1, "\"agent_version\":\"%s\",", m_HostInfo.strAgent_version);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"agent_id\":\"%s\",", m_HostInfo.strAgent_id);
    report.append(buffer);

    report.append("\"cpu_type\":[");
    for (int i = 0; i < m_HostInfo.CpuInfo[0].inum; i++) {
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"name\":\"%s\",", m_HostInfo.CpuInfo[i].strType);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"core\":%d}", m_HostInfo.CpuInfo[i].icore);
        report.append(buffer);
        if (i != m_HostInfo.CpuInfo[0].inum - 1) {
            report.append(",");
        }
    }
    report.append("],");

    _snprintf_s(buffer, MAX_LEN_512-1, "\"cpu_usage\":\"%s\",", m_HostInfo.strCpu_usage);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"memory\":\"%s\",", m_HostInfo.strMemory);
    report.append(buffer);
    _snprintf_s(buffer, MAX_LEN_512-1, "\"memory_use\":\"%s\",", m_HostInfo.strMemory_use);
    report.append(buffer);

    report.append("\"disk\":[");
    float ftotal = 0;
    float fuse = 0;
    for (int i = 0; i < m_HostInfo.DiskInfo[0].inum; i++) {
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"name\":\"%s\",", m_HostInfo.DiskInfo[i].strDiskname);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"total\":\"%0.2f\",", m_HostInfo.DiskInfo[i].ftotal);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"use\":\"%0.2f\",", m_HostInfo.DiskInfo[i].fuse);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"filesystype\":\"%s\",", m_HostInfo.DiskInfo[i].filetype);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"encrypt\":%s}", m_HostInfo.DiskInfo[i].strencrypt);
        report.append(buffer);
        if (i != m_HostInfo.DiskInfo[0].inum - 1) {
            report.append(",");
        }
        ftotal = ftotal + m_HostInfo.DiskInfo[i].ftotal;
        fuse = fuse + m_HostInfo.DiskInfo[i].fuse;
    }
    report.append("],");

    _snprintf_s(buffer, MAX_LEN_512-1, "\"disktotal\":{\"total\":\"%0.2f\",\"use\":\"%0.2f\"}", ftotal, fuse);
    report.append(buffer);
    report.append("},");

    report.append("\"user\":[");
    cnt = 0;
    for (auto iter = m_Userinfo.begin(); iter != m_Userinfo.end() && cnt<MAX_USER_NUM; iter++,cnt++) {
        if (iter != m_Userinfo.begin()) {
            report.append(",");
        }
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"user\":\"%s\",", iter->strUser);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"username\":\"%s\",", iter->strUserName);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"type\":\"%s\",", iter->strType);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"logontype\":\"%d\",", iter->uLogonType);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"localadmin\":\"%s\",", iter->strLocalAdmin);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"chpswtime\":\"%s\",", iter->strChpswtime);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"hostname\":\"%s\",", iter->strHostName);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"domain\":\"%s\",", iter->strDomain);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"sessionid\":\"%d\",", iter->lSessionID);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"status\":%d,", iter->uStatus);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"group\":\"%s\",", iter->strGroup);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"logon_time\":\"%lld\",", iter->uLoginTime);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"logoff_time\":\"%lld\"}", iter->uLoginOutTime);
        report.append(buffer);
    }
    report.append("],");

    report.append("\"software\":[{");
    if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
    report.append("\"add\":[");

    bfirst = true;
    for (auto iter = m_mapLastSoftInfoAdd.begin(); iter != m_mapLastSoftInfoAdd.end(); iter++) {
        if (iter->second.strSoftname[0] == 0) {
            continue;
        }
        if (!bfirst) {
            report.append(",");
        }
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"vendor\":\"%s\",", iter->second.vendor);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"softname\":\"%s\",", iter->second.strSoftname);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"softversion\":\"%s\",", iter->second.strSoftversion);
        report.append(EscapeValue(buffer));
        if (iter->second.uSize > 0) {
            _snprintf_s(buffer, MAX_LEN_512-1, "\"softwaresize\":\"%u\",", iter->second.uSize);
            report.append(buffer);
        } else {
            report.append("\"softwaresize\":\"\",");
        }

        _snprintf_s(buffer, MAX_LEN_512-1, "\"installtime\":\"%s\",", iter->second.strInstallTime);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"installlocation\":\"%s\"}", iter->second.strInstalllocation);
        report.append(EscapeValue(buffer));
        bfirst = false;
    }

    report.append("],");
    report.append("\"del\":[");
    for (auto iter = m_mapLastSoftInfoDel.begin(); iter != m_mapLastSoftInfoDel.end(); iter++) {
        if (iter != m_mapLastSoftInfoDel.begin()) {
            report.append(",");
        }
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"vendor\":\"%s\",", iter->second.vendor);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"softname\":\"%s\",", iter->second.strSoftname);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"softversion\":\"%s\",", iter->second.strSoftversion);
        report.append(EscapeValue(buffer));
        if (iter->second.uSize > 0) {
            _snprintf_s(buffer, MAX_LEN_512-1, "\"softwaresize\":\"%u\",", iter->second.uSize);
            report.append(buffer);
        } else {
            report.append("\"softwaresize\":\"\",");
        }
        _snprintf_s(buffer, MAX_LEN_512-1, "\"installtime\":\"%s\",", iter->second.strInstallTime);
        report.append(buffer);
        _snprintf_s(buffer, MAX_LEN_512-1, "\"installlocation\":\"%s\"}", iter->second.strInstalllocation);
        report.append(EscapeValue(buffer));
    }
    report.append("]}],");

    report.append("\"application\":[");
    bfirst = true;

    EnterCriticalSection(&m_cs);
    for (auto iter = m_Application.begin(); iter != m_Application.end(); iter++) {
        if (!iter->second.bupload) {
            continue;
        }

        if (!bfirst) {
            report.append(",");
        }
        bfirst = false;
        _snprintf_s(buffer, MAX_LEN_512-1, "{\"vendor\":\"%s\",", iter->second.vendor);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"application\":\"%s\",", iter->second.strApplication);
        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"applicationversion\":\"%s\",", iter->second.strApplicationversion);

        report.append(EscapeValue(buffer));
        _snprintf_s(buffer, MAX_LEN_512-1, "\"filename\":\"%s\",", iter->second.strFilename);
        report.append(buffer);
        if (iter->second.strFileversion[0] != 0) {
            _snprintf_s(buffer, MAX_LEN_512-1, "\"fileversion\":\"%s\",", iter->second.strFileversion);
        } else {
            _snprintf_s(buffer, MAX_LEN_512-1, "\"fileversion\":\"%s\",", iter->second.strApplicationversion);
        }

        report.append(buffer);

        report.append("\"sha1\":\"");
        bool bHasSHA1 = false;
        for (int i = 0; i < 20; ++i) {
            if (iter->second.sha1[i] != '\0') {
                bHasSHA1 = true;
                break;
            }
        }
        if (bHasSHA1) {
            for (int i = 0; i < 20; ++i) {
                _snprintf_s(buffer, MAX_LEN_512-1, "%02x", (unsigned char)iter->second.sha1[i]);
                report.append(buffer);
            }
        }
        report.append("\",");

        _snprintf_s(buffer, MAX_LEN_512-1, "\"lastuse\":\"%d\"}", iter->second.uUseTime);
        report.append(buffer);

        if (!m_bFirstUpLoadAsserts) {
            iter->second.bupload = false;
        }
    }

    report.append("],");

    if (!m_bFirstUpLoadAsserts) {
        for (auto iter = m_Application.begin(); iter != m_Application.end();) {
            if (iter->second.bdelete) {
                std::map<std::string, std::vector<UINT64>>::iterator iter2 = m_ProcPathPid.find(iter->first);
                if (iter2 != m_ProcPathPid.end()) {
                    m_ProcPathPid.erase(iter2);
                }
                m_Application.erase(iter);
                iter = m_Application.begin();
                continue;
            }
            iter++;
        }
    }

	// 计划任务
    report.append("\"croninfo\":{");
	if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
	report.append("\"add\":[");
	{
		auto itTaskEnd = m_map_tasks_table_add.end();
		auto itTask = m_map_tasks_table_add.begin();
		bfirst = true;
		for (; itTask != itTaskEnd; itTask++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"cronname\":\"%s\",", itTask->second.strTaskName.data());
			report.append(EscapeValue(buffer));

			_snprintf_s(buffer, MAX_LEN_512-1, "\"cmd\":\"%s\",", EscapeValue3(EscapeValue(itTask->second.strTaskStartProcessCmd)).data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"status\":\"%s\",", itTask->second.strTaskState.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"enable\":\"%s\",", itTask->second.strEnabled.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"type\":\"%s\",", itTask->second.strType.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"startboundary\":\"%s\",", itTask->second.strStartBoundary.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"id\":\"%s\",", itTask->second.strID.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"endboundary\":\"%s\",", itTask->second.strEndBoundary.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"detailMsg\":\"%s\",", EscapeValue(itTask->second.strDetailMsg).data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"exetimelimit\":\"%s\",", itTask->second.strExecutionTimeLimit.data());
			report.append(buffer);

			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itTask->second.strTaskCreator.data());
			report.append(EscapeValue(buffer));

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"nextruntime\":\"%s\",", itTask->second.strTaskNextRunTime.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"lastruntime\":\"%s\",", itTask->second.strTaskLastRunTime.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"lastrunresult\":\"%s\",", itTask->second.strTaskLastRunResult.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"createtime\":\"%s\"}", itTask->second.strTaskCreateTime.data());
			report.append(buffer);

			report.append("}");
		}
	}
    report.append("],");

	report.append("\"del\":[");
	{
		auto itTaskEnd = m_map_tasks_table_del.end();
		auto itTask = m_map_tasks_table_del.begin();
		bfirst = true;
		for (; itTask != itTaskEnd; itTask++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"cronname\":\"%s\",", itTask->second.strTaskName.data());
			report.append(buffer);

      _snprintf_s(buffer, MAX_LEN_512-1, "\"detailMsg\":\"%s\"", EscapeValue(itTask->second.strDetailMsg).data());
			report.append(buffer);

			report.append("}");
		}
	}
	report.append("]");
	report.append("},");

	// 端口
    report.append("\"portinfo\":{");
	if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
	report.append("\"add\":[");
	{
		auto itPortEnd = m_map_all_ports_table_add.end();
		auto itPort = m_map_all_ports_table_add.begin();
		bfirst = true;
		for (; itPort != itPortEnd; itPort++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"port\":\"%s\",", itPort->second.m_strPort.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"protocol\":\"%s\",", itPort->second.m_strProtocol.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"bindip\":\"%s\",", itPort->second.m_strBindIP.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"processname\":\"%s\",", itPort->second.m_strProcessName.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"processpath\":\"%s\",", EscapeValue3(EscapeValue(itPort->second.m_strProcessPath)).data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itPort->second.m_strUser.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"sha1\":\"%s\",", itPort->second.m_strSHA1.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"starttime\":\"%s\",", itPort->second.m_strStartTime.data());
			report.append(buffer);

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"remoteIP\":\"%s\",", itPort->second.m_strRemoteAddr.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"remotePort\":\"%s\",", itPort->second.m_strRemotePort.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"status\":\"%s\",", itPort->second.m_strState.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"pid\":\"%s\"}", itPort->second.m_strPid.data());
			report.append(buffer);

			report.append("}");
		}
	}
    report.append("],");
	report.append("\"del\":[");
	{
		auto itPortEnd = m_map_all_ports_table_del.end();
		auto itPort = m_map_all_ports_table_del.begin();
		bfirst = true;
		for (; itPort != itPortEnd; itPort++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"port\":\"%s\",", itPort->second.m_strPort.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"protocol\":\"%s\",", itPort->second.m_strProtocol.data());
			report.append(buffer);
      _snprintf_s(buffer, MAX_LEN_512-1, "\"bindip\":\"%s\",", itPort->second.m_strBindIP.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"processname\":\"%s\"", itPort->second.m_strProcessName.data());
			report.append(buffer);
			report.append("}");
		}
	}

	report.append("]");
	report.append("},");

	// 自启动项
	report.append("\"autoruninfo\":{");
	if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
	report.append("\"add\":[");
	{
		auto itAutoRunEnd = m_map_autorun_table_add.end();
		auto itAutoRun = m_map_autorun_table_add.begin();
		bfirst = true;
		for (; itAutoRun != itAutoRunEnd; itAutoRun++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"name\":\"%s\",", itAutoRun->second.strAutoRunName.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"status\":\"%s\",", itAutoRun->second.strAutoRunState.data());
			report.append(buffer);
			int iRet = _snprintf_s(buffer, MAX_LEN_512-1, "\"regvalue\":\"%s\",", EscapeValue3(EscapeValue(itAutoRun->second.strRegValue)).data());
      if (iRet < 0){
        buffer[MAX_LEN_512-3] = '\"';
        buffer[MAX_LEN_512-2] = ',';
      }
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"binpath\":\"%s\",", EscapeValue3(EscapeValue(itAutoRun->second.strBinPath)).data());
			report.append(buffer);
			iRet = _snprintf_s(buffer, MAX_LEN_512-1, "\"regpath\":\"'%s',%s\",", itAutoRun->second.strRegPath.data(), EscapeValue4(itAutoRun->second.strRegValue).data());
      if (iRet < 0){
        buffer[MAX_LEN_512-3] = '\"';
        buffer[MAX_LEN_512-2] = ',';
      }
			report.append(EscapeValue(buffer));

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"publisher\":\"%s\",", itAutoRun->second.strPublisher.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"regtype\":\"%s\",", itAutoRun->second.strRegType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itAutoRun->second.strUser.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"pid\":\"%s\"}", itAutoRun->second.strPid.data());
			report.append(buffer);

			report.append("}");
		}
	}
	report.append("],");

	report.append("\"del\":[");
	{
		auto itAutoRunEnd = m_map_autorun_table_del.end();
		auto itAutoRun = m_map_autorun_table_del.begin();
		bfirst = true;
		for (; itAutoRun != itAutoRunEnd; itAutoRun++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"name\":\"%s\",", itAutoRun->second.strAutoRunName.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"status\":\"%s\",", itAutoRun->second.strAutoRunState.data());
			report.append(buffer);
			int iRet = _snprintf_s(buffer, MAX_LEN_512-1, "\"regvalue\":\"%s\",", EscapeValue3(EscapeValue(itAutoRun->second.strRegValue)).data());
      if (iRet < 0){
        buffer[MAX_LEN_512-3] = '\"';
        buffer[MAX_LEN_512-2] = ',';
      }
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"binpath\":\"%s\",", EscapeValue3(EscapeValue(itAutoRun->second.strBinPath)).data());
			report.append(buffer);

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"publisher\":\"%s\",", itAutoRun->second.strPublisher.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"regtype\":\"%s\",", itAutoRun->second.strRegType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itAutoRun->second.strUser.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"pid\":\"%s\",", itAutoRun->second.strPid.data());
			report.append(buffer);
			iRet = _snprintf_s(buffer, MAX_LEN_512-1, "\"regpath\":\"'%s',%s\"}", itAutoRun->second.strRegPath.data(), EscapeValue4(itAutoRun->second.strRegValue).data());
      if (iRet < 0){
        buffer[MAX_LEN_512-3] = '\"';
        buffer[MAX_LEN_512-2] = ',';
      }
			report.append(EscapeValue(buffer));

			report.append("}");
		}
	}
	report.append("]");
	report.append("},");

	// 数据库
	report.append("\"dbinfo\":{");
	if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
	report.append("\"add\":[");
	{
		auto itDBEnd = m_map_database_table_add.end();
		auto itDB = m_map_database_table_add.begin();
		bfirst = true;
		for (; itDB != itDBEnd; itDB++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"runstatus\":\"%s\",", itDB->second.strStatus.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itDB->second.strUser.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"type\":\"%s\",", itDB->second.strType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"version\":\"%s\",", itDB->second.strVersion.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"bindip\":\"%s\",", itDB->second.strBindIP.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"port\":\"%s\",", itDB->second.strPort.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"datapath\":\"%s\",", EscapeValue3(EscapeValue(itDB->second.strDataPath)).data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"confpath\":\"%s\",", EscapeValue3(EscapeValue(itDB->second.strConfPath)).data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"logpath\":\"%s\",", EscapeValue3(EscapeValue(itDB->second.strLogPath)).data());
			report.append(buffer);

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"binpath\":\"%s\"}", EscapeValue3(EscapeValue(itDB->second.strDBBinaryFilePath)).data());
			report.append(buffer);

			report.append("}");
		}
	}
	report.append("],");

	report.append("\"del\":[");
	{
		auto itDBEnd = m_map_database_table_del.end();
		auto itDB = m_map_database_table_del.begin();
		bfirst = true;
		for (; itDB != itDBEnd; itDB++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"type\":\"%s\",", itDB->second.strType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"port\":\"%s\",", itDB->second.strPort.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"version\":\"%s\"", itDB->second.strVersion.data());
			report.append(buffer);
			report.append("}");
		}
	}
	report.append("]");
	report.append("},");

	// Web Service
	report.append("\"webserviceinfo\":{");
	if (m_bFirstUpLoadAsserts) {
        report.append("\"reset\":\"1\",");
    } else
        report.append("\"reset\":\"0\",");
	report.append("\"add\":[");
	{
		auto itWebSrvEnd = m_list_webservice_table_add.end();
		auto itWebSrv = m_list_webservice_table_add.begin();
		bfirst = true;
		for (; itWebSrv != itWebSrvEnd; itWebSrv++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"type\":\"%s\",", itWebSrv->second.strServiceType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"version\":\"%s\",", itWebSrv->second.strVersion.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"sha1\":\"%s\",", itWebSrv->second.strSha1.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"user\":\"%s\",", itWebSrv->second.strUser.data());
			report.append(EscapeValue(buffer));
			_snprintf_s(buffer, MAX_LEN_512-1, "\"binpath\":\"%s\",", EscapeValue3(EscapeValue(itWebSrv->second.strBinPath)).data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"confpath\":\"%s\",", EscapeValue3(EscapeValue(itWebSrv->second.strConfPath)).data());
			report.append(buffer);

			report.append("\"details\":{");
			_snprintf_s(buffer, MAX_LEN_512-1, "\"port\":\"%s\"}", itWebSrv->second.strPort.data());
			report.append(buffer);

			report.append("}");
		}
	}
	report.append("],");

	report.append("\"del\":[");
	{
		auto itWebSrvEnd = m_list_webservice_table_del.end();
		auto itWebSrv = m_list_webservice_table_del.begin();
		bfirst = true;
		for (; itWebSrv != itWebSrvEnd; itWebSrv++) {
			if (!bfirst)
				report.append(",");
			bfirst = false;

			_snprintf_s(buffer, MAX_LEN_512-1, "{\"type\":\"%s\",", itWebSrv->second.strServiceType.data());
			report.append(buffer);
			_snprintf_s(buffer, MAX_LEN_512-1, "\"version\":\"%s\"", itWebSrv->second.strVersion.data());
			report.append(buffer);
			report.append("}");
		}
	}
	report.append("]");
	report.append("}");

    LeaveCriticalSection(&m_cs);
    report.append("}");


    EmptyWorkingSet(GetCurrentProcess());

    return report;
}

#define SLEEP_SECONDS 2000
void Assetsinventory::GetAssetInfor(void)
{
    m_Userinfo.clear();
    std::vector<ASSETS_USER>().swap(m_Userinfo);
    GetHostinfo();
	Sleep(SLEEP_SECONDS);

    //获取deviceid
    strncpy_s(m_HostInfo.strAgent_id, sizeof(m_HostInfo.strAgent_id) - 1, m_DeviceId.c_str(), -1);
    GetUser();
	Sleep(SLEEP_SECONDS);
    GetSoftware();
	Sleep(SLEEP_SECONDS);

    //找到与黑匣子通信的网卡
    std::string strLocalIp = "127.0.0.1";
    GetLocalIp(m_ServerIp.c_str(), strLocalIp);
    for (int i = 0; i < m_HostInfo.NetcardInfo[0].inum; i++) {
        std::string ip = m_HostInfo.NetcardInfo[i].strip;
        if (ip.find(strLocalIp) != std::string::npos) {
            m_HostInfo.NetcardInfo[1].inum = i;
            strncpy_s(m_HostInfo.strNetCard, MAX_LEN_256 - 1, m_HostInfo.NetcardInfo[i].strNetCard, -1);
            strncpy_s(m_HostInfo.strip, sizeof(m_HostInfo.strip) - 1, m_HostInfo.NetcardInfo[i].strip, -1);
            strncpy_s(m_HostInfo.strMac, MAX_LEN_MAC, m_HostInfo.NetcardInfo[i].strMac, -1);
            strncpy_s(m_HostInfo.gateway, MAX_LEN_IP * 10, m_HostInfo.NetcardInfo[i].gateway, -1);
            strncpy_s(m_HostInfo.dns, MAX_LEN_128, m_HostInfo.NetcardInfo[i].dns, -1);
        }
    }

	if (!IsWinVerGreaterThan(6, 0))
		g_IsWinXP = true;

	// 获取web服务信息
	m_pDIAssetWebService = new DIAssetWebService;
	m_pDIAssetWebService->InitAssetWebService();
	auto map_webservice_table_tmp = m_pDIAssetWebService->GetWebServiceList();
	m_list_webservice_table_add.clear();
	m_list_webservice_table_del.clear();

  if (m_bFirstUpLoadAsserts)
    m_list_webservice_table_pre.clear();

	// web add
	for (auto iter = map_webservice_table_tmp.begin(); iter != map_webservice_table_tmp.end(); iter++) {
		auto mIter = m_list_webservice_table_pre.find(iter->first);
		if (mIter == m_list_webservice_table_pre.end())
			m_list_webservice_table_add.insert(make_pair(iter->first, iter->second));
		else if (mIter->second.strVersion.compare(iter->second.strVersion) || mIter->second.strSha1.compare(iter->second.strSha1) || 
			mIter->second.strUser.compare(iter->second.strUser) || mIter->second.strBinPath.compare(iter->second.strBinPath) || 
			mIter->second.strConfPath.compare(iter->second.strConfPath))                                                           // 服务端以服务类型和版本控制唯一
			m_list_webservice_table_add.insert(make_pair(iter->first, iter->second));
		Sleep(0);
	}

	// web del
	for (auto mIter = m_list_webservice_table_pre.begin(); mIter != m_list_webservice_table_pre.end(); mIter++) {
		auto iter = map_webservice_table_tmp.find(mIter->first);
		if (iter == map_webservice_table_tmp.end())
			m_list_webservice_table_del.insert(make_pair(mIter->first, mIter->second));
		else if (iter->second.strVersion.compare(mIter->second.strVersion) || iter->second.strSha1.compare(mIter->second.strSha1) || 
			iter->second.strUser.compare(mIter->second.strUser) || iter->second.strBinPath.compare(mIter->second.strBinPath) || 
			iter->second.strConfPath.compare(mIter->second.strConfPath))
			m_list_webservice_table_del.insert(make_pair(mIter->first, mIter->second));
		Sleep(0);
	}

	m_list_webservice_table_pre.clear();
	m_list_webservice_table_pre = map_webservice_table_tmp;
	map_webservice_table_tmp.clear();
	if (m_pDIAssetWebService != NULL){
		delete m_pDIAssetWebService;
		m_pDIAssetWebService = NULL;
	}

	Sleep(SLEEP_SECONDS);

	// 获取数据库信息
	m_pDIAssetDB= new DIAssetDB;
	m_pDIAssetDB->InitAssetDataBase();
	auto map_database_table_tmp = m_pDIAssetDB->GetDataBaseList();
	m_map_database_table_add.clear();
	m_map_database_table_del.clear();

  if (m_bFirstUpLoadAsserts)
    m_map_database_table_pre.clear();

	// db add
	for (auto iter = map_database_table_tmp.begin(); iter != map_database_table_tmp.end(); iter++) {
		auto mIter = m_map_database_table_pre.find(iter->first);
		if (mIter == m_map_database_table_pre.end())
			m_map_database_table_add.insert(make_pair(iter->first, iter->second));    
		else if (mIter->second.strVersion.compare(iter->second.strVersion) || mIter->second.strStatus.compare(iter->second.strStatus) ||
			mIter->second.strUser.compare(iter->second.strUser) || mIter->second.strBindIP.compare(iter->second.strBindIP) ||
			mIter->second.strPort.compare(iter->second.strPort) || mIter->second.strDataPath.compare(iter->second.strDataPath) ||
			mIter->second.strConfPath.compare(iter->second.strConfPath) || mIter->second.strLogPath.compare(iter->second.strLogPath))       // 服务端以服务类型和版本控制唯一
			m_map_database_table_add.insert(make_pair(iter->first, iter->second));
		Sleep(0);
	}

	// db del
	for (auto mIter = m_map_database_table_pre.begin(); mIter != m_map_database_table_pre.end(); mIter++) {
		auto iter = map_database_table_tmp.find(mIter->first);
		if (iter == map_database_table_tmp.end())
			m_map_database_table_del.insert(make_pair(mIter->first, mIter->second));
		else if (iter->second.strVersion.compare(mIter->second.strVersion) || iter->second.strStatus.compare(mIter->second.strStatus) ||
			iter->second.strUser.compare(mIter->second.strUser) || iter->second.strBindIP.compare(mIter->second.strBindIP) ||
			iter->second.strPort.compare(mIter->second.strPort) || iter->second.strDataPath.compare(mIter->second.strDataPath) ||
			iter->second.strConfPath.compare(mIter->second.strConfPath) || iter->second.strLogPath.compare(mIter->second.strLogPath))
			m_map_database_table_del.insert(make_pair(mIter->first, mIter->second));
		Sleep(0);
	}

	m_map_database_table_pre.clear();
	m_map_database_table_pre = map_database_table_tmp;
	map_database_table_tmp.clear();
	if (m_pDIAssetDB != NULL){
		delete m_pDIAssetDB;
		m_pDIAssetDB = NULL;
	}

	Sleep(SLEEP_SECONDS);

	// 获取自启动信息
	m_pDIAssetAutoRun = new DIAssetAutoRun;
	m_pDIAssetAutoRun->InitDIAssetAutoRun();
	auto map_autorun_table_tmp = m_pDIAssetAutoRun->GetDIAssetAutoRunList();
	m_map_autorun_table_add.clear();
	m_map_autorun_table_del.clear();

  if (m_bFirstUpLoadAsserts)
    m_map_autorun_table_pre.clear();

	// autorun add
	for (auto iter = map_autorun_table_tmp.begin(); iter != map_autorun_table_tmp.end(); iter++) {
		auto mIter = m_map_autorun_table_pre.find(iter->first);
		if (mIter == m_map_autorun_table_pre.end())
			m_map_autorun_table_add.insert(make_pair(iter->first, iter->second));
		else if (mIter->second.strRegValue.compare(iter->second.strRegValue) || mIter->second.strPublisher.compare(iter->second.strPublisher) ||
			mIter->second.strRegType.compare(iter->second.strRegType) || mIter->second.strBinPath.compare(iter->second.strBinPath))
			m_map_autorun_table_add.insert(make_pair(iter->first, iter->second));
		Sleep(0);
	}

	// autorun del
	for (auto mIter = m_map_autorun_table_pre.begin(); mIter != m_map_autorun_table_pre.end(); mIter++) {
		auto iter = map_autorun_table_tmp.find(mIter->first);
		if (iter == map_autorun_table_tmp.end())
			m_map_autorun_table_del.insert(make_pair(mIter->first, mIter->second));
		else if (iter->second.strRegValue.compare(mIter->second.strRegValue)  || iter->second.strPublisher.compare(mIter->second.strPublisher) ||
			iter->second.strRegType.compare(mIter->second.strRegType) || iter->second.strBinPath.compare(mIter->second.strBinPath))      // 以启动项名称和命令行作为唯一控制
			m_map_autorun_table_del.insert(make_pair(mIter->first, mIter->second));
		Sleep(0);
	}

	m_map_autorun_table_pre.clear();
	m_map_autorun_table_pre = map_autorun_table_tmp;
	map_autorun_table_tmp.clear();
	if (m_pDIAssetAutoRun != NULL){
		delete m_pDIAssetAutoRun;
		m_pDIAssetAutoRun = NULL;
	}

	Sleep(SLEEP_SECONDS);

	// 获取端口信息
	m_pDIAssetPort = new DIAssetPort;
	m_pDIAssetPort->InitDIAssetPort();
	auto map_all_ports_table = m_pDIAssetPort->GetAllPortList();
	m_map_all_ports_table_add.clear();
	m_map_all_ports_table_del.clear();

  if (m_bFirstUpLoadAsserts)
    m_map_all_ports_table_pre.clear();

	// port add
	auto itEnd = map_all_ports_table.end();
	for (auto iter = map_all_ports_table.begin(); iter != itEnd; iter++) {
		auto mIter = m_map_all_ports_table_pre.find(iter->first);
		if (mIter == m_map_all_ports_table_pre.end())
			m_map_all_ports_table_add.insert(make_pair(iter->first, iter->second));
		else if (mIter->second.m_strProtocol.compare(iter->second.m_strProtocol) || mIter->second.m_strBindIP.compare(iter->second.m_strBindIP) ||
			mIter->second.m_strProcessName.compare(iter->second.m_strProcessName)  || mIter->second.m_strProcessPath.compare(iter->second.m_strProcessPath) ||
			mIter->second.m_strUser.compare(iter->second.m_strUser)  || mIter->second.m_strSHA1.compare(iter->second.m_strSHA1) ||
			mIter->second.m_strStartTime.compare(iter->second.m_strStartTime))
			m_map_all_ports_table_add.insert(make_pair(iter->first, iter->second));
		Sleep(0);
	}

	// port del
	for (auto mIter = m_map_all_ports_table_pre.begin(); mIter != m_map_all_ports_table_pre.end(); mIter++) {
		auto iter = map_all_ports_table.find(mIter->first);
		if (iter == map_all_ports_table.end())
			m_map_all_ports_table_del.insert(make_pair(mIter->first, mIter->second));
		else if (iter->second.m_strProtocol.compare(mIter->second.m_strProtocol) || iter->second.m_strBindIP.compare(mIter->second.m_strBindIP) ||
			iter->second.m_strProcessName.compare(mIter->second.m_strProcessName)  || iter->second.m_strProcessPath.compare(mIter->second.m_strProcessPath) ||
			iter->second.m_strUser.compare(mIter->second.m_strUser)  || iter->second.m_strSHA1.compare(mIter->second.m_strSHA1) ||
			iter->second.m_strStartTime.compare(mIter->second.m_strStartTime))                              // 端口号，协议，进程名称作为唯一性控制
			m_map_all_ports_table_del.insert(make_pair(mIter->first, mIter->second));
		Sleep(0);
	}

	m_map_all_ports_table_pre.clear();
	m_map_all_ports_table_pre = map_all_ports_table;
	map_all_ports_table.clear();

	if (m_pDIAssetPort != NULL){
		delete m_pDIAssetPort;
		m_pDIAssetPort = NULL;
	}

	Sleep(SLEEP_SECONDS);

	// 获取计划任务信息
	m_pDIAssetTask = new DIAssetTask;
	m_pDIAssetTask->InitTasksList();
	auto map_tasks_table_tmp = m_pDIAssetTask->GetTasksList();
	m_map_tasks_table_add.clear();
	m_map_tasks_table_del.clear();

  if (m_bFirstUpLoadAsserts)
    m_map_tasks_table_pre.clear();

	// task add
  for (auto iter = map_tasks_table_tmp.begin(); iter != map_tasks_table_tmp.end(); iter++) {
    auto mIter = m_map_tasks_table_pre.find(iter->first);
    if (mIter == m_map_tasks_table_pre.end())
      m_map_tasks_table_add.insert(make_pair(iter->first, iter->second));    // 任务名称作为唯一性控制
    else if(mIter->second.strTaskStartProcessCmd.compare(iter->second.strTaskStartProcessCmd) || mIter->second.strTaskCreator.compare(iter->second.strTaskCreator) || 
      mIter->second.strEnabled != iter->second.strEnabled || mIter->second.strDetailMsg != iter->second.strDetailMsg || mIter->second.strTaskNextRunTime != iter->second.strTaskNextRunTime) 
      m_map_tasks_table_add.insert(make_pair(iter->first, iter->second));   
    Sleep(0);
  }

	// task del
  for (auto mIter = m_map_tasks_table_pre.begin(); mIter != m_map_tasks_table_pre.end(); mIter++) {
    auto iter = map_tasks_table_tmp.find(mIter->first);
    if (iter == map_tasks_table_tmp.end())
      m_map_tasks_table_del.insert(make_pair(mIter->first, mIter->second));
    else if (iter->second.strTaskStartProcessCmd.compare(mIter->second.strTaskStartProcessCmd) || iter->second.strTaskCreator.compare(mIter->second.strTaskCreator) || 
      iter->second.strEnabled != mIter->second.strEnabled || iter->second.strDetailMsg != mIter->second.strDetailMsg || mIter->second.strTaskNextRunTime != iter->second.strTaskNextRunTime) 
      m_map_tasks_table_add.insert(make_pair(iter->first, iter->second));   
    Sleep(0);
  }

	m_map_tasks_table_pre.clear();
	m_map_tasks_table_pre = map_tasks_table_tmp;
	map_tasks_table_tmp.clear();
	if (m_pDIAssetTask != NULL){
		delete m_pDIAssetTask;
		m_pDIAssetTask = NULL;
	}
}
