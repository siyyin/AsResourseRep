#include "DIUtils.h"
#include "LogManager.h"
#include <LM.h>
#include <algorithm>
#include <assert.h>
#include <fstream>
#include <intrin.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <sddl.h>
#include <Winternl.h>
#include <Shlwapi.h>
#include <io.h>
#include "DIWMICom.h"
#include "StringUtils.h"
#include <openssl/sha.h>
#pragma warning( disable: 4995)
#ifdef _WIN32
extern BOOL g_IsWinXP;
#endif
#include <strsafe.h>
#include "StringUtils.h"
#define ZLIB_CHUNK 16384
#define FILE_INFO_SIZE 4096

#define MAX_BUFSIZE 1 * 1024 *1024

#define  IOA_PATTERN_NAME   L"akg$*"

namespace di_rest_client
{

UINT16 hashMacAddress(PIP_ADAPTER_INFO info)
{
    UINT16 hash = 0;
    for (UINT32 i = 0; i < info->AddressLength; i++) {
        hash += (info->Address[i] << ((i & 1) * 8));
    }
    return hash;
}

void getMacHash(UINT16& mac1, UINT16& mac2)
{
    IP_ADAPTER_INFO AdapterInfo[32];
    DWORD dwBufLen = sizeof(AdapterInfo);

    DWORD dwStatus = GetAdaptersInfo(AdapterInfo, &dwBufLen);
    if (dwStatus != ERROR_SUCCESS) return;  // no adapters.

    PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
    mac1 = hashMacAddress(pAdapterInfo);
    if (pAdapterInfo->Next) mac2 = hashMacAddress(pAdapterInfo->Next);

    // sort the mac addresses. We don't want to invalidate
    // both macs if they just change order.
    if (mac1 > mac2) {
        UINT16 tmp = mac2;
        mac2 = mac1;
        mac1 = tmp;
    }
}

UINT16 getVolumeHash(void)
{
    DWORD serialNum = 0;

    TCHAR strDriverName[MAX_PATH] = {0};
    DWORD dwRet = GetEnvironmentVariable(_T("SystemDrive"), strDriverName, MAX_PATH - 1);
    if (dwRet == 0 || dwRet == MAX_PATH - 1) StringCchCopyW(strDriverName, MAX_PATH - 1, _T("C:"));
    wcsncat_s(strDriverName, _T("\\"), 1);
    DI_LOG_DEBUG("Trying to get volume information from:%s", WcharToString(strDriverName).c_str());
    // Determine if this volume uses an NTFS file system.
    GetVolumeInformation(strDriverName, NULL, 0, &serialNum, NULL, NULL, NULL, 0);
    UINT16 hash = (UINT16)((serialNum + (serialNum >> 16)) & 0xFFFF);

    return hash;
}

UINT16 getCpuHash(void)
{
    int cpuinfo[4] = {0, 0, 0, 0};
    __cpuid(cpuinfo, 0);
    UINT16 hash = 0;
    UINT16* ptr = (UINT16*)(&cpuinfo[0]);
    for (UINT32 i = 0; i < 8; i++) hash += ptr[i];

    return hash;
}

UINT16 smear_mask[5] = {0x4e25, 0xf4a1, 0x5437, 0xab41, 0x0000};

static void smear(UINT16* id)
{
    for (UINT32 i = 0; i < 5; i++)
        for (UINT32 j = i; j < 5; j++)
            if (i != j) id[i] ^= id[j];

    for (UINT32 i = 0; i < 5; i++) id[i] ^= smear_mask[i];
}

static void unsmear(UINT16* id)
{
    for (UINT32 i = 0; i < 5; i++) id[i] ^= smear_mask[i];

    for (UINT32 i = 0; i < 5; i++)
        for (UINT32 j = 0; j < i; j++)
            if (i != j) id[4 - i] ^= id[4 - j];
}
static UINT16* computeSystemUniqueId(void)
{
    static UINT16 id[5] = {0};
    static bool computed = false;

    if (computed) return id;

    // produce a number that uniquely identifies this system.
    id[0] = getCpuHash();

    id[1] = getVolumeHash();
    getMacHash(id[2], id[3]);

    // fifth block is some checkdigits
    id[4] = 0;
    for (UINT32 i = 0; i < 4; i++) id[4] += id[i];

    smear(id);

    computed = true;
    return id;
}

std::string getSystemUniqueId(void)
{
    // get the name of the computer
    std::string buf;
    // buf << getMachineName();

    UINT16* id = computeSystemUniqueId();
    for (UINT32 i = 0; i < 5; i++) {
        char num[16];
        _snprintf_s(num, sizeof(num)-1, "%x", id[i]);
        /*
    if (i != 0) {
    buf += "-";
    }
    */
        switch (strlen(num)) {
            case 1:
                buf += "000";
                break;
            case 2:
                buf += "00";
                break;
            case 3:
                buf += "0";
                break;
            default:
                break;
        }
        buf += num;
    }

    std::transform(buf.begin(), buf.end(), buf.begin(), ::toupper);
    return buf;
}

std::string GetASCTime(void)
{
    time_t current_timestamp;
    time(&current_timestamp);
    struct tm temp_tm;
    localtime_s(&temp_tm, &current_timestamp);
    char temp_time_str[32];
    asctime_s(temp_time_str, &temp_tm);
    temp_time_str[strlen(temp_time_str) - 1] = '\0';
    return temp_time_str;
}

std::string GetLocalDateTime(void)
{
    time_t current_timestamp;
    time(&current_timestamp);
    return GetLocalDateTime(current_timestamp);
}

std::string GetLocalDateTime(time_t& timestamp)
{
    struct tm temp_tm;
    localtime_s(&temp_tm, &timestamp);
    char temp_time_str[32];
    strftime(temp_time_str, 32, "%Y-%m-%d %H:%M:%S", &temp_tm);
    return temp_time_str;
}

std::string GetFileName(std::string& filePath)
{
    std::string::size_type pos = filePath.rfind("\\");
    if (pos == std::string::npos) {
        return filePath;
    }
    return filePath.substr(pos + 1, filePath.length());
}

std::string GetNameFromPath(char* pFilePath)
{
	std::string sName;
	char* pTem = NULL;
	sName.clear();
	int iLen = 0;

	if (NULL == pFilePath || strlen(pFilePath) < 1)
	{
		return sName;
	}

	pTem = strrchr(pFilePath, '/');
	iLen = (int)(strlen(pFilePath) - (pTem - pFilePath));

	if (iLen > 0)
	{
		sName = sName.append(pTem+1, iLen);
	}
	return sName;
}

DWORD GetTimestamp()
{
	time_t t;
	DWORD lTime = 0;

	t = time(NULL);

	lTime = (DWORD)time(&t);

	return lTime;
}

int ExecuteShell(const char * fmt, ...)
{
	char	buff[4096] = { 0 };
	int		nSize = sizeof(buff) - 1;
	int		nRet = 0;
	va_list va;

	//Get text		
	va_start(va, fmt);
	nSize = vsnprintf_s(buff, nSize, fmt, va);
	va_end(va);

	nRet = system(buff);

	return nRet;
}

bool GetVer4PartFromVer2Part(const std::string sVer2Part, std::string& sOut)
{
	std::string sAfter, sBefore, sVer4Part, sPart1, sPart2;

	if (sVer2Part.empty())
	{
		return false;
	}

	if (!SplitString(sVer2Part, ".", sBefore, sAfter))
	{
		return false;
	}

	sPart1 = sBefore.substr(0, 1);
	sPart2 = sBefore.substr(2, 2);
	if (sPart2.at(0) == '0')
	{
		sPart2 = sPart2.substr(1, 1);
	}

	sVer4Part = sPart1 + std::string(".") + sPart2 + std::string(".0.") + sAfter;

	sOut = sVer4Part;

	return true;
}

bool GetVer4PartFromVer3Part(const std::string sVer3Part, std::string& sOut)
{
	std::string sData, sAfter, sBefore, sVer4Part, sPart1, sPart2, sPart4;

	sData = sVer3Part;

	if (sData.empty())
	{
		return false;
	}

	if (!SplitString(sData, ".", sBefore, sAfter))
	{
		return false;
	}

	sPart1 = sBefore;
	sData = sAfter;

	if (!SplitString(sData, ".", sBefore, sAfter))
	{
		return false;
	}

	sPart2 = sBefore;

	if (sAfter.length() != 4)
	{
		return false;
	}

	sPart4 = sAfter.substr(1, 3);

	sVer4Part = sPart1 + "." + sPart2 + ".0." + sPart4;
	sOut = sVer4Part;

	return true;
}

bool SafeCopyFile(const std::string sSrcFile, const std::string sDesFile)
{
	std::string srcFile = sSrcFile;

	if (sSrcFile.empty() || sDesFile.empty())
	{
		return false;
	}

	std::string strDesFile = sDesFile;
	if (!CopyFile(StringToWchar(srcFile).c_str(), StringToWchar(strDesFile).c_str(),false))
	{
		return false;
	}

	return true;
}

bool CopyFileToDir(const std::string sSrcFile, const std::string sDesDir)
{
	bool bRet = true;
	std::string sName, sDesFile;

	sName = GetNameFromPath((char*)sSrcFile.c_str());

	if (sName.empty())
	{
		return false;
	}

	sDesFile = sDesDir + "/" + sName;

	bRet = SafeCopyFile(sSrcFile, sDesFile);

	return bRet;
}

void GetDirectoryFiles(std::string path, std::vector<std::string>& files)
{
	long  hFile = 0;
	struct _finddata_t fileinfo;
	std::string p;
	if ((hFile = (long)_findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			//如果是目录,迭代之 //如果不是,加入列表  
			if ((fileinfo.attrib &  _A_SUBDIR)){
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					GetDirectoryFiles(p.assign(path).append("\\").append(fileinfo.name), files);
			}
			else{
				//files.push_back(p.assign(path).append("\\").append(fileinfo.name));
				files.push_back(p.assign(path).append(fileinfo.name));
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

std::string GetClientVersion()
{
    std::string versionNumber = GetProductVersionNumber();
    std::string version = "|AsiaInfo Security|Deep Inspector|" + versionNumber + "|";
    return version;
}

std::string GetClientVersionNumber()
{
    std::string number;
    wchar_t pFilePath[MAX_PATH + 1];
    DWORD dwPathLength = GetModuleFileName(NULL, pFilePath, MAX_PATH + 1);

    DWORD dwInfoSize, dwHandle;
    VS_FIXEDFILEINFO* pFileInfo;
    UINT nSize = 0;
    dwInfoSize = ::GetFileVersionInfoSize(pFilePath, &dwHandle);
    if (!dwInfoSize) {
        return number;
    }

    if (dwInfoSize >= MAX_BUFSIZE){
      DI_LOG_WARN("GetClientVersionNumber malloc a large buffer.");
    }
    BYTE* pData = new BYTE[dwInfoSize];

    if (!pData) {
        return number;
    }

    if (!::GetFileVersionInfo(pFilePath, NULL, dwInfoSize, (LPVOID)pData)) {
        delete[] pData;
        return number;
    }
    /*
  LPTSTR lpBuffer;
  if (VerQueryValue(pData, _T("\\StringFileInfo\\080404b0\\CompanyName"),
  (LPVOID*) &lpBuffer, (PUINT) &nSize)) { version += _T("|"); std::wstring
  companyName(lpBuffer); version += companyName; version += _T("|");
  }

  if (VerQueryValue(pData, _T("\\StringFileInfo\\080404b0\\ProductName"),
  (LPVOID*) &lpBuffer, (PUINT) &nSize)) { std::wstring productName(lpBuffer);
  version += productName;
  version += _T("|");
  }
  */

    if (VerQueryValue(pData, _T("\\"), (LPVOID*)&pFileInfo, (PUINT)&nSize)) {
        char szVersionNumber[128];
        _snprintf_s(szVersionNumber, sizeof(szVersionNumber)-1, "%d.%d.%d.%d", HIWORD(pFileInfo->dwFileVersionMS),
                  LOWORD(pFileInfo->dwFileVersionMS), HIWORD(pFileInfo->dwFileVersionLS),
                  LOWORD(pFileInfo->dwFileVersionLS));
        number = szVersionNumber;
    }
    delete[] pData;
    return number;
}

std::string GetProductVersionNumber()
{
    HKEY hKey;
    LSTATUS lStatus = RegOpenKeyEx(HKEY_LOCAL_MACHINE, PRODUCT_REGISTRY_SUBKEY, 0, KEY_READ, &hKey);
    if (lStatus == ERROR_SUCCESS) {
        wchar_t szProductVersion[32];
        DWORD dwType;
        DWORD dwSizeBuff = sizeof(szProductVersion);
        lStatus = RegQueryValueEx(hKey, PRODUCT_REGISTRY_VERSION_KEY, 0, &dwType, (BYTE*)szProductVersion, &dwSizeBuff);
        if (lStatus == ERROR_SUCCESS) {
            DI_LOG_DEBUG("Load Product Version from registry successfully, ProductVersion:%s",
                         WcharToString(szProductVersion).c_str());
            RegCloseKey(hKey);
            return WcharToString(szProductVersion);
        } else {
            DI_LOG_ERROR("Load Product Version failed, cannot read key(%ld).", lStatus);
        }
        RegCloseKey(hKey);
    } else {
        DI_LOG_ERROR("Load Product Version failed, cannot open key(%ld).", lStatus);
    }
    return "unknown";
}

DWORD CalcFileSize(std::string filePath)
{
	WIN32_FIND_DATA fileInfo; 
	HANDLE hFind; 
	DWORD fileSize = 0; 
	hFind = FindFirstFile(StringToWchar(filePath).c_str(),&fileInfo); 
	if(hFind != INVALID_HANDLE_VALUE)
	{
		fileSize = fileInfo.nFileSizeLow;
	}
	FindClose(hFind);
	return fileSize;
}

std::string GetDeviceName()
{
  std::string hostname = "UNKNOWN_HOSTNAME";
  DWORD nResult=0;
  DWORD nLength=0;
  nResult=GetNetworkParams(NULL,&nLength);
  if(nResult!=ERROR_BUFFER_OVERFLOW) 
  {
    return hostname;
  } 
  char* pFixedInfo = new char[nLength];
  if (pFixedInfo==NULL)
  {
    return hostname;
  }
  nResult = GetNetworkParams((FIXED_INFO*)pFixedInfo,&nLength); 
  if(nResult!=ERROR_SUCCESS)
  {
    delete[] pFixedInfo; 
    return hostname;
  }

  hostname = WcharToString(StringToUnicode(((FIXED_INFO*)pFixedInfo)->HostName));

  delete[] pFixedInfo; 

  return hostname;
}

bool IsClientVersionGreaterThan(std::string versionA, std::string versionB)
{
    size_t foundA = versionA.find('.', 0);
    size_t foundB = versionB.find('.', 0);
    UINT16 valueA = 0;
    UINT16 valueB = 0;
    while (foundA != std::string::npos || foundB != std::string::npos) {
        if (foundA != std::string::npos) {
            valueA = atoi(versionA.c_str() + foundA + 1);
            foundA = versionA.find('.', foundA + 1);
        } else {
            valueA = 0;
        }
        if (foundB != std::string::npos) {
            valueB = atoi(versionB.c_str() + foundB + 1);
            foundB = versionB.find('.', foundB + 1);
        } else {
            valueB = 0;
        }
        if (valueA > valueB) return true;
        if (valueA < valueB) return false;
    }
    return false;
}


BOOL IsWinVerGreaterThan(DWORD dwMajorVersion, DWORD dwMinorVersion)
{
    OSVERSIONINFOEXW osvi = {0};
    DWORDLONG dwlConditionMask = 0;

    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwMajorVersion = dwMajorVersion;
    osvi.dwMinorVersion = dwMinorVersion;

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER);
    if (::VerifyVersionInfo(&osvi, VER_MAJORVERSION, dwlConditionMask)) return TRUE;

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER);

    return ::VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}

BOOL IsWinVerEqualTo(DWORD dwMajorVersion, DWORD dwMinorVersion)
{
    OSVERSIONINFOEXW osvi = {0};
    DWORDLONG dwlConditionMask = 0;

    ZeroMemory(&osvi, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwMajorVersion = dwMajorVersion;
    osvi.dwMinorVersion = dwMinorVersion;

    VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_EQUAL);
    VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_EQUAL);

    return ::VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION, dwlConditionMask);
}

BOOL IsProductType(BYTE wProductType)
{
    OSVERSIONINFOEX osvi = {0};
    DWORDLONG dwlConditionMask = 0;
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.wProductType = wProductType;

    VER_SET_CONDITION(dwlConditionMask, VER_PRODUCT_TYPE, VER_EQUAL);

    return ::VerifyVersionInfo(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
}

bool IsDesktopSystem()
{
	bool bIsDesk;

	OSVERSIONINFOEX os_info = {0};
	os_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);  
	GetVersionEx((OSVERSIONINFO *)&os_info);

	//操作系统类型
	if (os_info.wProductType != VER_NT_WORKSTATION) {
		bIsDesk = false;

	} else {
		bIsDesk = true;
	}
	return bIsDesk;
}

OS_VERSION_MAP s_osVersionMap[] = {{10, 0, TRUE, "Windows 10"},
                                   {10, 0, FALSE, "Windows Server 2016"},
                                   {6, 3, TRUE, "Windows 8.1"},
                                   {6, 3, FALSE, "Windows Server 2012 R2"},
                                   {6, 2, TRUE, "Windows 8"},
                                   {6, 2, FALSE, "Windows Server 2012"},
                                   {6, 1, TRUE, "Windows 7"},
                                   {6, 1, FALSE, "Windows Server 2008 R2"},
                                   {6, 0, FALSE, "Windows Server 2008"},
                                   {6, 0, TRUE, "Windows Vista"},
                                   {5, 2, FALSE, "Windows Server 2003"},
                                   {5, 2, TRUE, "Windows XP Professional x64 Edition"},
                                   {5, 1, TRUE, "Windows XP"},
                                   {5, 0, TRUE, "Windows 2000"}};

std::string GetOSVersion(void)
{
    for (OS_VERSION_MAP os_version_map : s_osVersionMap) {
        if (IsWinVerEqualTo(os_version_map.dwMajorVersion, os_version_map.dwMinorVersion)) {
            BOOL bIsWorkstation = IsProductType(VER_NT_WORKSTATION);
            if (bIsWorkstation == os_version_map.bIsWorkstation) return os_version_map.szName;
        }
    }
    DWORD dwVersion = 0;
    WKSTA_INFO_100* wkstaInfo = NULL;
    NET_API_STATUS netStatus = NetWkstaGetInfo(NULL, 100, (BYTE**)&wkstaInfo);
    if (netStatus == NERR_Success) {
        DWORD dwMajVer = wkstaInfo->wki100_ver_major;
        DWORD dwMinVer = wkstaInfo->wki100_ver_minor;
        dwVersion = (DWORD)MAKELONG(dwMinVer, dwMajVer);
        NetApiBufferFree(wkstaInfo);
        char szName[64];
        _snprintf_s(szName, sizeof(szName)-1, "Windows Unknown %lu.%lu", dwMajVer, dwMinVer);
        return szName;
    }
    DI_LOG_DEBUG("NetWkstaGetInfo failed, NET_API_STATUS=%lu", netStatus);
    return "Windows Unknown";
}

std::string GetOSVersionWMI(void)
{
    HRESULT hres;
    IWbemLocator *pLoc;
    IWbemServices *pSvc;
    std::string data;
    int i = 0;
    std::string os = "Windows Unknown";

    while (InitWmi(hres, &pLoc, &pSvc) != 0) {
        if (i < 3) {
            i++;
            continue;
        } else {
            return os;
        }
    }

    data = GetWMIInfo(hres, pLoc, pSvc, "SELECT Caption FROM Win32_OperatingSystem", L"Caption", "string");
    os = data;
    if (Is64BitOS()) {
        os = os + " 64";
    } else {
        os = os + " 32";
    }
    size_t pos = os.find("Windows");
    if (pos != std::string::npos) {
        os = os.erase(0, pos);
    }

    UnInitWmi(hres, pLoc, pSvc);

    DI_LOG_DEBUG("NetWkstaGetInfo failed, NET_API_STATUS=%lu", );
    return os;
}

BOOL Is64BitOS()
{
    typedef void(WINAPI * GetSystemInfoFunc)(LPSYSTEM_INFO);
    HMODULE handle = ::GetModuleHandle(_T("kernel32"));
    if (!handle) return FALSE;
    GetSystemInfoFunc get_native_system_info =
        reinterpret_cast<GetSystemInfoFunc>(::GetProcAddress(handle, "GetNativeSystemInfo"));
    DWORD dwProcessorArch = PROCESSOR_ARCHITECTURE_UNKNOWN;
    if (get_native_system_info != NULL) {
        SYSTEM_INFO sys_info = {0};
        get_native_system_info(&sys_info);
        dwProcessorArch = sys_info.wProcessorArchitecture;
    } else {
        dwProcessorArch = PROCESSOR_ARCHITECTURE_INTEL;
    }
    if (PROCESSOR_ARCHITECTURE_AMD64 == dwProcessorArch || PROCESSOR_ARCHITECTURE_IA64 == dwProcessorArch)
        return TRUE;
    else
        return FALSE;
}

BOOL EnablePrivilege(LPTSTR lpszPrivilege, BOOL bEnable)
{
    BOOL bResult;
    LUID luid;
    HANDLE hToken;
    TOKEN_PRIVILEGES tokenPrivileges;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return FALSE;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tokenPrivileges.PrivilegeCount = 1;
    tokenPrivileges.Privileges[0].Luid = luid;
    tokenPrivileges.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    bResult = AdjustTokenPrivileges(hToken, FALSE, &tokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL);

    CloseHandle(hToken);

    return bResult && GetLastError() == ERROR_SUCCESS;
}

bool ExtractProcessMandatory(unsigned long processId, UINT64& Mandatory)
{
  HANDLE hProcess_i = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
    if (hProcess_i == NULL) {
        DI_LOG_DEBUG("OpenProcess failed %lu", processId);
        return false;
    }
    // Get process token
    HANDLE hProcessToken = NULL;
    if ((::OpenProcessToken(hProcess_i, TOKEN_QUERY, &hProcessToken) == FALSE) || !hProcessToken) {
        DI_LOG_DEBUG("OpenProcessToken failed %lu", GetLastError());
        return false;
    }

    // First get size needed, TokenUser indicates we want user information from
    // given token
    DWORD dwProcessTokenInfoAllocSize = 0;
    ::GetTokenInformation(hProcessToken, TokenIntegrityLevel, NULL, 0, &dwProcessTokenInfoAllocSize);

    // Call should have failed due to zero-length buffer.
    if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        // Allocate buffer for user information in the token.
        PTOKEN_MANDATORY_LABEL  pMandatory = reinterpret_cast<PTOKEN_MANDATORY_LABEL >(new BYTE[dwProcessTokenInfoAllocSize]);
        if (pMandatory != NULL) {
            // Now get user information in the allocated buffer
            if (::GetTokenInformation(hProcessToken, TokenIntegrityLevel, pMandatory, dwProcessTokenInfoAllocSize,
                                      &dwProcessTokenInfoAllocSize)) {
                      // End if
              PUCHAR plen = GetSidSubAuthorityCount(pMandatory->Label.Sid);
              if (plen!=NULL)
              {
                PDWORD pIntegrity = GetSidSubAuthority(pMandatory->Label.Sid,(DWORD)(UCHAR)(*plen-1));
                if (pIntegrity!=NULL)
                {
                  Mandatory =  *pIntegrity;
                }
              }

              delete[] pMandatory;
            }
        }  // End if
    }      // End if

    CloseHandle(hProcess_i);

    CloseHandle(hProcessToken);

    // Oops trouble
    return false;
}

bool ExtractProcessOwner(unsigned long processId, std::wstring& owner)
{
    HANDLE hProcess_i = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, processId);
    if (hProcess_i == NULL) {
        DI_LOG_DEBUG("OpenProcess failed %lu", processId);
        return false;
    }
    // Get process token
    HANDLE hProcessToken = NULL;
    if ((::OpenProcessToken(hProcess_i, TOKEN_QUERY, &hProcessToken) == FALSE) || !hProcessToken) {
        DI_LOG_DEBUG("OpenProcessToken failed %lu", GetLastError());
        CloseHandle(hProcess_i);
        return false;
    }

    // First get size needed, TokenUser indicates we want user information from
    // given token
    DWORD dwProcessTokenInfoAllocSize = 0;
    ::GetTokenInformation(hProcessToken, TokenUser, NULL, 0, &dwProcessTokenInfoAllocSize);

    // Call should have failed due to zero-length buffer.
    if (::GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        // Allocate buffer for user information in the token.
        PTOKEN_USER pUserToken = reinterpret_cast<PTOKEN_USER>(new BYTE[dwProcessTokenInfoAllocSize]);
        if (pUserToken != NULL) {
            // Now get user information in the allocated buffer
            if (::GetTokenInformation(hProcessToken, TokenUser, pUserToken, dwProcessTokenInfoAllocSize,
                                      &dwProcessTokenInfoAllocSize)) {
                // Some vars that we may need
                SID_NAME_USE snuSIDNameUse;
                TCHAR szUser[MAX_PATH] = {0};
                DWORD dwUserNameLength = MAX_PATH;
                TCHAR szDomain[MAX_PATH] = {0};
                DWORD dwDomainNameLength = MAX_PATH;

                // Retrieve user name and domain name based on user's SID.
                if (::LookupAccountSid(NULL, pUserToken->User.Sid, szUser, &dwUserNameLength, szDomain, &dwDomainNameLength,
                                       &snuSIDNameUse)) {
                    // Prepare user name string
                    /*
          owner.append(_T("\\\\"));
          owner.append(szDomain);
          owner.append(_T("\\"));
          owner.append(szUser);
          */
                    owner.append(szUser);
                    // We are done!
                    CloseHandle(hProcess_i);
                    CloseHandle(hProcessToken);
                    delete[] pUserToken;

                    // We succeeded
                    return true;
                }  // End if
            }      // End if

            delete[] pUserToken;
        }  // End if
    }      // End if

    CloseHandle(hProcess_i);

    CloseHandle(hProcessToken);

    // Oops trouble
    return false;
}  // End GetProcessOwner

void DeleteFolderRecursively(const wchar_t* szFolderPath)
{
    std::wstring strFileFilter;

    strFileFilter = szFolderPath;
    strFileFilter += L"\\*.*";

    WIN32_FIND_DATA win32FindData;  // struct to hold file information

    HANDLE hFile = FindFirstFile(strFileFilter.c_str(), &win32FindData);

    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        std::wstring strFilePath;  // full file path
        std::wstring strFileName;  // file name with extension only

        strFilePath = szFolderPath;
        strFilePath += L"\\";
        strFilePath += win32FindData.cFileName;
        strFileName = win32FindData.cFileName;

        // If is dots
        if (strFileName == L"." || strFileName == L"..") {
            continue;
        }

        int iFindDot = (int)strFileName.find(L".");

        // Assume it is a directory because no '.' was found
        if (iFindDot < 0)  // not extension
        {
            // Recursive call
            DeleteFolderRecursively(strFilePath.c_str());
        }

        DeleteFile(strFilePath.c_str());
    } while (FindNextFile(hFile, &win32FindData));

    FindClose(hFile);  // release handle otherwise dir cannot be removed

    RemoveDirectory(szFolderPath);
}

BOOL DeleteDirectory(const wchar_t * DirName)
{  
	if (DirName == NULL)
	{
		return FALSE;
	}

	std::wstring strFileFilter;
	strFileFilter = DirName;
	strFileFilter += L"\\*";

	WIN32_FIND_DATA FindFileData;
	ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));

	HANDLE hFind = FindFirstFile(strFileFilter.c_str(), &FindFileData);
	if (INVALID_HANDLE_VALUE == hFind) 
	{
		return FALSE;
	}

	do 
	{
		std::wstring strFileName = L"";
		strFileName = strFileName + DirName + L"\\" + FindFileData.cFileName;
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if ((wcscmp(FindFileData.cFileName, _T(".")) != 0) && (wcscmp(FindFileData.cFileName, _T("..")) !=0)) //如果不是"." ".."目录
			{
				DeleteDirectory(strFileName.c_str());
			}
		}
		else
		{
			DeleteFile(strFileName.c_str());
		}

	}while (FindNextFile(hFind, &FindFileData) != 0);

	FindClose(hFind);

	BOOL bRet = RemoveDirectory(DirName);
	if (bRet == 0) //删除目录
	{
		return FALSE;
	}
	return TRUE;
}

BOOL CleanFolderFile(const wchar_t * DirName)
{
	if (DirName == NULL)
	{
		return FALSE;
	}
	std::wstring strFileFilter;
	strFileFilter = DirName;
	strFileFilter += L"\\*";  //匹配格式为*即该目录下的所有文件

	WIN32_FIND_DATA FindFileData;
	ZeroMemory(&FindFileData, sizeof(WIN32_FIND_DATA));

	HANDLE hFind = FindFirstFile(strFileFilter.c_str(), &FindFileData);

	if (INVALID_HANDLE_VALUE == hFind) 
	{
		return FALSE;
	} 

	do
	{
		std::wstring strFileName = L"";
		strFileName = strFileName + DirName + L"\\" + FindFileData.cFileName;
		if (FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			if ((wcscmp(FindFileData.cFileName, _T(".")) != 0) && (wcscmp(FindFileData.cFileName, _T("..")) !=0)) //如果不是"." ".."目录
			{
				DeleteDirectory(strFileName.c_str());
			}
		}
		else
		{
			DeleteFile(strFileName.c_str());
		}
	}while (FindNextFile(hFind, &FindFileData) != 0);

	FindClose(hFind);

	return TRUE;
}

BOOL CreateFolder(const wchar_t* szFolderPath)
{
    return CreateDirectory(szFolderPath, NULL);
}

BOOL ExtractFileFromResource(TCHAR* szFileName, TCHAR* szResourceType, DWORD dwResourceID)
{
    BOOL bRet = FALSE;
    // Drop uninstall bat file
    HRSRC hResource = FindResourceEx(NULL, szResourceType, MAKEINTRESOURCE(dwResourceID),
                                     MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL));  // Load for current lang

    if (!hResource) return FALSE;
    if (hResource) {
        HGLOBAL hGlobalMem = LoadResource(NULL, hResource);
        if (hGlobalMem) {
            DWORD dwFileSize = SizeofResource(NULL, hResource);
            HANDLE hFile = CreateFile(szFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

            if (INVALID_HANDLE_VALUE != hFile) {
                DWORD dwBytesWritten = 0;
                WriteFile(hFile, hGlobalMem, dwFileSize, &dwBytesWritten, NULL);
                bRet = (dwBytesWritten == dwFileSize);
                CloseHandle(hFile);
            }
        }
        FreeResource(hGlobalMem);
    }
    return bRet;
}

HANDLE OpenShareRead(const wchar_t* szFilePath)
{
    return ::CreateFile(szFilePath, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                        OPEN_EXISTING, NULL, NULL);
}

BOOL GetFileTime(const TCHAR* szFileName, FILETIME& created, FILETIME& accessed, FILETIME& modified)
{
    if (!szFileName) return FALSE;
    HANDLE hFile = OpenShareRead(szFileName);
    BOOL bRet = GetFileTime(hFile, created, accessed, modified);
    CloseHandle(hFile);
    return bRet;
}

BOOL GetFileTime(HANDLE hFile, FILETIME& created, FILETIME& accessed, FILETIME& modified)
{
    if (!hFile) return FALSE;
    if (!::GetFileTime(hFile, &created, &accessed, &modified)) {
        return FALSE;
    }
    return TRUE;
}

time_t FileTimeToUnixTime(FILETIME& ft)
{
    ULARGE_INTEGER ull = {0};
    ull.LowPart = ft.dwLowDateTime;
    ull.HighPart = ft.dwHighDateTime;
    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

void ListFiles(const wchar_t* szPath, const wchar_t* szFileName, std::vector<std::wstring>& fileList)
{
    WIN32_FIND_DATA win32FindData;
    std::wstring pattern(szPath);
    pattern += L"\\";
    pattern += szFileName;
    HANDLE hFile = FindFirstFile(pattern.c_str(), &win32FindData);

    if (hFile != INVALID_HANDLE_VALUE) {
        wchar_t fullFilePath[MAX_PATH];
        int count = 0;
        do {
            swprintf_s(fullFilePath, sizeof(fullFilePath), L"%s\\%s", szPath, win32FindData.cFileName);
            fileList.push_back(fullFilePath);
        } while (FindNextFile(hFile, &win32FindData));
        FindClose(hFile);
    }
}

BOOL ExecuteCmd(LPCWSTR pFile, LPCWSTR pPara, LPCWSTR pDir)
{
	TCHAR strerro[MAX_PATH] = {0};
	DWORD erroid;
	SHELLEXECUTEINFO ShExecInfo = {0};
	memset(&ShExecInfo, 0, sizeof(ShExecInfo));
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb =  _T("open");
	ShExecInfo.lpFile = pFile;
	ShExecInfo.lpParameters = pPara;
	ShExecInfo.lpDirectory = pDir;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;
	ShellExecuteEx(&ShExecInfo);
	if (WaitForSingleObject(ShExecInfo.hProcess,30000) == WAIT_OBJECT_0)
		return TRUE;
	else
	{
		erroid = GetLastError();
		_sntprintf_s(strerro, MAX_PATH - 1, _T("ExecuteCmd fail %d"), erroid);
		return FALSE;
	}	
}

int FindFilesWithPrefix(std::string root, std::string prefix,std::vector<std::string> &fileVec)
{
	int Nums = 0;
	long long handle = 0;
	struct _finddata_t fileinfo;
	std::string temp_str;
	if ((handle = _findfirst(temp_str.assign(root).append("/*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib&_A_SUBDIR))
			{
				//不查找子目录--注释
				//if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
				//	FilesRead(temp_str.assign(root).append(fileinfo.name).c_str(), fileVec);
			}
			else
			{
				try
				{
					if (fileinfo.size == 0)
						throw - 1;
					else
					{
						std::string fileName = temp_str.assign(root).append("\\").append(fileinfo.name);
						if (fileName.find(prefix) != std::string::npos)
						{
							fileVec.push_back(fileName);
						}
					}

				}
				catch (int e)
				{
					if (e == -1)
					{
						;
					}
					//std::cout << "file is empty!" << std::endl;
				}
			}
		} while (_findnext((intptr_t)handle, &fileinfo) == 0);
		_findclose((intptr_t)handle);
	}

	Nums = (int)fileVec.size();
	if (Nums > 0)
		return Nums;
	else
		return 0;
}

std::vector<std::wstring> GetAllUserSids()
{
    std::vector<std::wstring> sids;
    HKEY hKey;
    if (::RegOpenKeyEx(HKEY_LOCAL_MACHINE, PROFILE_LIST_SUBKEY, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwNumSubkeys = 0;                      // number of values for key
        LONG res = ::RegQueryInfoKey(hKey,           // key handle
                                     NULL,           // buffer for class name
                                     NULL,           // size of class string
                                     NULL,           // reserved
                                     &dwNumSubkeys,  // number of subkeys
                                     NULL,           // longest subkey size
                                     NULL,           // longest class string
                                     NULL,           // number of values for this key
                                     NULL,           // longest value name
                                     NULL,           // longest value data
                                     NULL,           // security descriptor
                                     NULL);          // last write time
        if (res == ERROR_SUCCESS) {
            for (DWORD i = 0; i < dwNumSubkeys; ++i) {
                TCHAR szKeyNameBuffer[256] = {0};
                DWORD dwKeyNameBufferSize = lstrlen(szKeyNameBuffer) - 1;
                if (::RegEnumKeyEx(hKey, i, szKeyNameBuffer, &dwKeyNameBufferSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    sids.push_back(szKeyNameBuffer);
                }
            }
        }
        RegCloseKey(hKey);
    }
    return sids;
}

bool GetProfileImagePathBySid(const wchar_t* szSid, std::wstring& strProfileImagePath)
{
    HKEY hKey;
    wchar_t szSubkey[MAX_PATH] = {0};
    swprintf_s(szSubkey, L"%s\\%s", PROFILE_LIST_SUBKEY, szSid);
    if (::RegOpenKeyEx(HKEY_LOCAL_MACHINE, szSubkey, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD dwType;
        wchar_t szPath[MAX_PATH] = {0};
        DWORD dwSizeBuf = sizeof(szPath);
        LONG res = RegQueryValueEx(hKey, PROFILE_IMAGE_PATH_KEY, 0, &dwType, (BYTE*)szPath, &dwSizeBuf);
        RegCloseKey(hKey);
        if (res == ERROR_SUCCESS) {
            strProfileImagePath = szPath;
            return true;
        }
    }
    return false;
}

bool CalcFileSha1Entity(const char* pszFilePath, unsigned char* pFileSha1, DWORD& dwBufSize)
{
	if (dwBufSize < 20){
		return false;
	}
	SHA_CTX ctx;
	SHA1_Init(&ctx);
	DWORD bytesRead = 0;
	char *pBuff = new char[FILE_INFO_SIZE];
	HANDLE hFile = ::CreateFileW(StringToWchar(pszFilePath).c_str(), FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
		OPEN_EXISTING, NULL, NULL);
	if (hFile != NULL) {
		do {
			if (!::ReadFile(hFile, pBuff, FILE_INFO_SIZE, &bytesRead, NULL)) {
				memset(&ctx, 0, sizeof(SHA_CTX));
				break;
			} else {
				SHA1_Update(&ctx, pBuff, bytesRead);
			}
			Sleep(0);
		} while (bytesRead != 0);

		SHA1_Final(pFileSha1, &ctx);
		CloseHandle(hFile);
	}
	if (pBuff != NULL){
		delete []pBuff;
		pBuff = NULL;
	}
  
	return true;
}

std::string GetProcessStartTime(DWORD &dwPid)
{
	std::string strStartTime;
	FILETIME loadStartTime, exitTime, kernelTime, userTime;
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
	if (hProcess == NULL)
		return strStartTime;

	if (GetProcessTimes(hProcess, &loadStartTime, &exitTime, &kernelTime, &userTime)){
		SYSTEMTIME beginTime;
		FileTimeToSystemTime(&loadStartTime, &beginTime);
		char szBuffer[MAX_PATH] = {0};
		_snprintf_s(szBuffer, sizeof(szBuffer)-1, 
			"%04d-%02d-%02d %02d:%02d:%02d.%03d",
			beginTime.wYear, beginTime.wMonth, beginTime.wDay,
			beginTime.wHour, beginTime.wMinute, beginTime.wSecond, 
			beginTime.wMilliseconds);
		strStartTime = std::string(szBuffer);
	}

	CloseHandle(hProcess);
	return strStartTime;
}

std::string GetProcessStartTime1(DWORD &dwPid)
{
	std::string strStartTime;
	FILETIME loadStartTime, exitTime, kernelTime, userTime;
	HANDLE hProcess = NULL;
	if (!g_IsWinXP)
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
	if (hProcess == NULL)
		return strStartTime;

	if (GetProcessTimes(hProcess, &loadStartTime, &exitTime, &kernelTime, &userTime)){
		char szBuffer[MAX_PATH] = {0};
		time_t tm = FileTimeToUnixTime(loadStartTime);
		unsigned long long ulTime = static_cast<unsigned long long>(tm);
		_snprintf_s(szBuffer, sizeof(szBuffer)-1, "%lld", ulTime);
		strStartTime = std::string(szBuffer);
	}

	CloseHandle(hProcess);
	return strStartTime;
}

std::string oleTime2Str(double time) {
    //2209190400 :指的是1990年1月1日-1970年1月1日的时间秒数
    time_t t = (time_t)time * 24 * 3600 - 2209190400;
    struct tm tm1;
    localtime_s(&tm1, &t);

    char sz[64];
    memset(sz, 0, 64);
    _snprintf_s(sz, sizeof(sz)-1, "%04d-%02d-%02d %02d:%02d:%02d"
        , tm1.tm_year + 1900, 
        tm1.tm_mon + 1, 
        tm1.tm_mday, 
        tm1.tm_hour, 
        tm1.tm_min, 
        tm1.tm_sec);
    return std::string(sz);
}

std::string StringToDatetime(std::string& str)
{
	char *cha = (char*)str.data();             // 将string转换成char*。
	char szBuffer[MAX_PATH] = {0};
	tm tm_;                                    // 定义tm结构体。
	int year, month, day, hour, minute, second;// 定义时间的各个int临时变量。
	sscanf_s(cha, "%04d-%02d-%02d %02d:%02d:%02d", &year, &month, &day, &hour, &minute, &second);// 将string存储的日期时间，转换为int临时变量。
	tm_.tm_year = year - 1900;                 // 年，由于tm结构体存储的是从1900年开始的时间，所以tm_year为int临时变量减去1900。
	tm_.tm_mon = month - 1;                    // 月，由于tm结构体的月份存储范围为0-11，所以tm_mon为int临时变量减去1。
	tm_.tm_mday = day;                         // 日。
	tm_.tm_hour = hour;                        // 时。
	tm_.tm_min = minute;                       // 分。
	tm_.tm_sec = second;                       // 秒。
	tm_.tm_isdst = 0;                          // 非夏令时。
	time_t t_ = mktime(&tm_);                  // 将tm结构体转换成time_t格式。
	unsigned long long ulTime = static_cast<unsigned long long>(t_);
	_snprintf_s(szBuffer, sizeof(szBuffer)-1, "%lld", ulTime);
	return std::string(szBuffer); 
}

std::string oleTime2Str1(double time) {
    //2209190400 :指的是1990年1月1日-1970年1月1日的时间秒数
	unsigned long long t = static_cast<unsigned long long>(time * 24 * 3600  - 2209190400);

    char sz[64];
    memset(sz, 0, 64);
    _snprintf_s(sz, sizeof(sz)-1, "%lld", t);
    return std::string(sz);
}

std::string systemTime2Str(const SYSTEMTIME& st)
{
	char szBuffer[MAX_PATH] = {0};
	struct tm tm_ = {st.wSecond, st.wMinute, st.wHour, st.wDay, st.wMonth-1, st.wYear-1900, st.wDayOfWeek, 0, 0};
	time_t t_ = mktime(&tm_);                  // 将tm结构体转换成time_t格式。
	unsigned long long ulTime = static_cast<unsigned long long>(t_);
	_snprintf_s(szBuffer, sizeof(szBuffer)-1, "%lld", ulTime);
	return std::string(szBuffer); 
}

BOOL CheckProcessExist(LPCTSTR lpProcessName, DWORD& dwPid, BOOL bService)
{
	bool bRet = false;
	PROCESSENTRY32 pe32;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return false;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hProcessSnap, &pe32)){
        CloseHandle(hProcessSnap);
        return false;
    }

	do
    {
		if(_wcsicmp(pe32.szExeFile, lpProcessName) == 0){
			if (bService){
				if (CheckPIDIsServiceProcess(pe32.th32ProcessID)){
					dwPid = pe32.th32ProcessID;
					bRet = true;
					break;
				}
			}
			else{
				dwPid = pe32.th32ProcessID;
				bRet = true;
				break;
			}
		}
	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return bRet; 		
}

BOOL CheckProcessExist(LPCTSTR lpProcessName)
{
  bool bRet = false;
  PROCESSENTRY32 pe32;

  HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if( hProcessSnap == INVALID_HANDLE_VALUE )
    return false;

  pe32.dwSize = sizeof(PROCESSENTRY32);
  if(!Process32First(hProcessSnap, &pe32)){
    CloseHandle(hProcessSnap);
    return false;
  }

  do {
    if(_wcsicmp(pe32.szExeFile, lpProcessName) == 0){
      bRet = true;
      break;
    }
  } while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return bRet; 		
}

BOOL CheckProcessExist(LPCTSTR lpProcessName, LPCTSTR lpParam, DWORD& dwPid, LPCTSTR& lpCmd, BOOL bService)
{
	bool bRet = false;
	PROCESSENTRY32 pe32;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return false;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hProcessSnap, &pe32)){
        CloseHandle(hProcessSnap);
        return false;
    }

	do
    {
		if(_wcsicmp(pe32.szExeFile, lpProcessName) == 0){
			if (bService){
				if (CheckPIDIsServiceProcess(pe32.th32ProcessID)){
					// 判断命令行
					dwPid = pe32.th32ProcessID;
					lpCmd = GetProcessCommandLine(dwPid);
					if (lpCmd && std::wstring(lpCmd).find(lpParam) != std::wstring::npos){
						bRet = true;
						break;
					}
				}
			}
			else{
				// 判断命令行
				dwPid = pe32.th32ProcessID;
				lpCmd = GetProcessCommandLine(dwPid);
				if (lpCmd && std::wstring(lpCmd).find(lpParam) != std::wstring::npos){
					bRet = true;
					break;
				}
			}
		}
	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return bRet; 
}

std::vector<DWORD> GetPidListByProcessName(LPCTSTR lpProcessName, BOOL bService)
{
	bool bRet = false;
	PROCESSENTRY32 pe32;

	std::vector<DWORD> vecPID;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return vecPID;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hProcessSnap, &pe32)){
        CloseHandle(hProcessSnap);
        return vecPID;
    }

	do
    {
		if(_wcsicmp(pe32.szExeFile, lpProcessName) == 0){
			if (bService){
				if (CheckPIDIsServiceProcess(pe32.th32ProcessID))
					vecPID.push_back(pe32.th32ProcessID);
			}
			else
				vecPID.push_back(pe32.th32ProcessID);
		}
	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return vecPID; 	
}

std::vector<DWORD> GetPidListByProcessName(LPCTSTR lpProcessName, LPCTSTR lpParam, BOOL bService)
{
	bool bRet = false;
	PROCESSENTRY32 pe32;
	DWORD dwPid;
	wchar_t* lpCmd = NULL;

	std::vector<DWORD> vecPID;

	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if( hProcessSnap == INVALID_HANDLE_VALUE )
		return vecPID;

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Process32First(hProcessSnap, &pe32)){
        CloseHandle(hProcessSnap);
        return vecPID;
    }

	do
    {
		if(_wcsicmp(pe32.szExeFile, lpProcessName) == 0){
			if (bService){
				if (CheckPIDIsServiceProcess(pe32.th32ProcessID)){
					// 判断命令行
					dwPid = pe32.th32ProcessID;
					lpCmd = GetProcessCommandLine(dwPid);
          std::wstring strCmdLine;
          if (lpCmd){
            strCmdLine = lpCmd;
            delete []lpCmd;
            lpCmd = NULL;
          }

					if (strCmdLine.find(lpParam) != std::wstring::npos){
						vecPID.push_back(pe32.th32ProcessID);
						continue;
					}
				}
			}
			else{
				// 判断命令行
				dwPid = pe32.th32ProcessID;
				lpCmd = GetProcessCommandLine(dwPid);
        std::wstring strCmdLine;
        if (lpCmd){
          strCmdLine = lpCmd;
          delete []lpCmd;
          lpCmd = NULL;
        }

				if (strCmdLine.find(lpParam) != std::wstring::npos){
					vecPID.push_back(pe32.th32ProcessID);
					continue;
				}
			}
		}
	} while(Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return vecPID; 	
}

BOOL DosPathToNtPath(LPTSTR pszDosPath, LPTSTR pszNtPath)
{
    TCHAR            szDriveStr[500];
    TCHAR            szDrive[3];
    TCHAR            szDevName[100];
    INT                cchDevName;
    INT                i;
     
    //检查参数
    if(!pszDosPath || !pszNtPath )
        return FALSE;
 
    //获取本地磁盘字符串
    if(GetLogicalDriveStrings(sizeof(szDriveStr), szDriveStr))
    {
        for(i = 0; szDriveStr[i]; i += 4)
        {
            if(!lstrcmpi(&(szDriveStr[i]), _T("A:\\")) || !lstrcmpi(&(szDriveStr[i]), _T("B:\\")))
                continue;
 
            szDrive[0] = szDriveStr[i];
            szDrive[1] = szDriveStr[i + 1];
            szDrive[2] = '\0';
            if(!QueryDosDevice(szDrive, szDevName, 100))//查询 Dos 设备名
                return FALSE;
 
            cchDevName = lstrlen(szDevName);
            if(_tcsnicmp(pszDosPath, szDevName, cchDevName) == 0)//命中
            {
                lstrcpy(pszNtPath, szDrive);//复制驱动器
                lstrcat(pszNtPath, pszDosPath + cchDevName);//复制路径
 
                return TRUE;
            }           
        }
    }
 
    lstrcpy(pszNtPath, pszDosPath);
     
    return FALSE;
}

//获取进程完整路径
BOOL GetProcessFullPath(DWORD dwPID, TCHAR pszFullPath[MAX_PATH])
{
    TCHAR        szImagePath[MAX_PATH];
    HANDLE        hProcess;
    if(!pszFullPath)
        return FALSE;

	if (dwPID == 4 || dwPID == 0) {
		wcsncpy_s(pszFullPath, MAX_PATH, L"system", 6);
        return TRUE;
    }
 
    pszFullPath[0] = '\0';
	if (!g_IsWinXP)
		hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, dwPID);
	else
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, dwPID);
    if(!hProcess)
        return FALSE;
 
    if(!GetProcessImageFileName(hProcess, szImagePath, MAX_PATH))
    {
        CloseHandle(hProcess);
        return FALSE;
    }
 
    if(!DosPathToNtPath(szImagePath, pszFullPath))
    {
        CloseHandle(hProcess);
        return FALSE;
    }
 
    CloseHandle(hProcess);

    return TRUE;
}

void ConvertHexToString(byte * hex_buffer, int hex_size, char * out_buffer, int out_size)
{
	if (hex_size * 2 + 2 > out_size)return;
	memset(out_buffer, 0, out_size);
	for (int count = 0; count < hex_size; count++) {
		_snprintf_s(out_buffer, out_size, out_size-1, "%s%02x", out_buffer, hex_buffer[count] & 0xff);
	}
}

BOOL CheckFileExist(std::string &strFilePath)
{
	WIN32_FIND_DATA FindFileData;
	HANDLE hFind;

	hFind = FindFirstFile(StringToUnicode(strFilePath.data()).data(), &FindFileData);

	if (hFind == INVALID_HANDLE_VALUE) {
		return false;
	} else {
    FindClose(hFind);
		return true;
	}
}

DWORD FindProcessPIDByName(LPCTSTR szProcessName)
{
	DWORD dwPID = 0;
	HANDLE      hProcessSnap = NULL; 
    PROCESSENTRY32 pe32      = {0}; 

    if (szProcessName)
	{
        hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
        if (hProcessSnap != INVALID_HANDLE_VALUE) 
		{
    		pe32.dwSize = sizeof(PROCESSENTRY32); 
			if (Process32First(hProcessSnap, &pe32)) 
			{  
				do 
				{
					if (!_wcsicmp(pe32.szExeFile, szProcessName))
					{
						dwPID = pe32.th32ProcessID;
						break;
					}
				} 
				while (Process32Next(hProcessSnap, &pe32)); 
			} 
			CloseHandle(hProcessSnap);
		}
	}
	return dwPID;
}

BOOL GetAccountSid(LPTSTR AccountName, PSID *Sid)
{
	PSID pSID = NULL;
	DWORD cbSid = 0;
	LPTSTR DomainName = NULL;
	DWORD cbDomainName = 0;
	SID_NAME_USE SIDNameUse;
	BOOL bDone = FALSE;

	if (!LookupAccountName(NULL, AccountName, pSID, &cbSid, DomainName, &cbDomainName, &SIDNameUse)){
    if (cbSid >= MAX_BUFSIZE){
      DI_LOG_WARN("GetAccountSid malloc a large buffer.");
    }
		pSID = (PSID)malloc(cbSid);
    if (cbDomainName * sizeof(TCHAR) >= MAX_BUFSIZE){
      DI_LOG_WARN("GetAccountSid malloc a large buffer for DomainName.");
    }
		DomainName = (LPTSTR)malloc(cbDomainName * sizeof(TCHAR));
		if (pSID && DomainName){
			if (LookupAccountName(NULL, AccountName, pSID, &cbSid, DomainName, &cbDomainName, &SIDNameUse))
				bDone = TRUE;
		}
	}

	if (DomainName)
		free(DomainName);

	if (!bDone && pSID)
		free(pSID);

	if (bDone)
		*Sid = pSID;

	return bDone;
}

BOOL GetCurrentUserSid(LPWSTR *lpSid)
{
	BOOL bRetValue = false;
	DWORD pid = FindProcessPIDByName(L"explorer.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess != NULL){
		HANDLE hToken;
		BOOL bRet = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
		if (bRet && (hToken != NULL)){
			BOOL bIsImpersonate = ImpersonateLoggedOnUser(hToken);
			if (bIsImpersonate) {
				wchar_t szBuf[MAX_PATH] = L"";
				DWORD dwRet = MAX_PATH;
				bRet = GetUserName(szBuf, &dwRet);
				if (bRet){
					PSID pSid = NULL;
					LPWSTR sid;
					if (GetAccountSid(szBuf, &pSid)){
						if (ConvertSidToStringSid(pSid, &sid)){
							*lpSid = sid;
							bRetValue = true;
						}
						free(pSid);
					}
				}
				RevertToSelf();
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	return bRetValue;
}

BOOL GetCurrentUser(std::string &sUserName)
{
  BOOL bRetValue = false;
	DWORD pid = FindProcessPIDByName(L"explorer.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess != NULL){
		HANDLE hToken;
		BOOL bRet = OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_DUPLICATE, &hToken);
		if (bRet && (hToken != NULL)){
			BOOL bIsImpersonate = ImpersonateLoggedOnUser(hToken);
			if (bIsImpersonate) {
				wchar_t szBuf[MAX_PATH] = L"";
				DWORD dwRet = MAX_PATH;
				bRet = GetUserName(szBuf, &dwRet);
				if (bRet){
          sUserName = WcharToString(szBuf);
					bRetValue = true;
				}
				RevertToSelf();
			}
			CloseHandle(hToken);
		}
		CloseHandle(hProcess);
	}
	return bRetValue;
}

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    DWORD ProcessInformationLength,
    PDWORD ReturnLength
    );
TCHAR* GetProcessCommandLine(DWORD dwPID)
{
	HANDLE hproc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	WCHAR *buffer = NULL;
	if (INVALID_HANDLE_VALUE != hproc){
		HANDLE hnewdup = NULL;
		_NtQueryInformationProcess NtQuery = (_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
		if (DuplicateHandle(GetCurrentProcess(), hproc, GetCurrentProcess(), &hnewdup, 0, FALSE, DUPLICATE_SAME_ACCESS) && NtQuery) {
			PROCESS_BASIC_INFORMATION pbi;
			NTSTATUS isok = NtQuery(hnewdup, 0/*ProcessBasicInformation*/, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), 0);        
			if (BCRYPT_SUCCESS(isok)) {
				PEB peb;
				RTL_USER_PROCESS_PARAMETERS upps;
				if ( ReadProcessMemory(hnewdup, pbi.PebBaseAddress, &peb, sizeof(PEB), 0))
					if ( ReadProcessMemory(hnewdup, peb.ProcessParameters, &upps, sizeof(RTL_USER_PROCESS_PARAMETERS), 0) ) {
            if ((upps.CommandLine.Length + 1)*sizeof(WCHAR) >= MAX_BUFSIZE){
              DI_LOG_WARN("GetProcessCommandLine malloc a large buffer.");
            }
						buffer = new WCHAR[upps.CommandLine.Length + 1];
						ZeroMemory(buffer, (upps.CommandLine.Length + 1) * sizeof(WCHAR));
						ReadProcessMemory(hnewdup, upps.CommandLine.Buffer, buffer, upps.CommandLine.Length, 0);
					}
			}
			CloseHandle(hnewdup);
		}

		CloseHandle(hproc);
	}
	return buffer;
}

BOOL CheckPIDIsServiceProcess(DWORD processId)
{
	SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);

	if (hSCM == NULL) 
		return false;

	LPBYTE Buffer = NULL;
	BOOL bStatus = false;
	do {
		DWORD bufferSize = 0;
		DWORD requiredBufferSize = 0;
		DWORD totalServicesCount = 0;
		if (!EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, bufferSize, &requiredBufferSize, &totalServicesCount, nullptr, nullptr)) {
			if (GetLastError() != ERROR_MORE_DATA) {
				break;
			}
		}

		Buffer = (LPBYTE)VirtualAlloc(NULL, requiredBufferSize, MEM_COMMIT, PAGE_READWRITE);
		if (Buffer == NULL)
			break;

		if (!EnumServicesStatusEx(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, Buffer, requiredBufferSize, &requiredBufferSize, &totalServicesCount, nullptr, nullptr))
			break;

		LPENUM_SERVICE_STATUS_PROCESS services =
			reinterpret_cast<LPENUM_SERVICE_STATUS_PROCESS>(Buffer);
		for (unsigned int i = 0; i < totalServicesCount; ++i){
			ENUM_SERVICE_STATUS_PROCESS service = services[i];
			if ( service.ServiceStatusProcess.dwProcessId == processId){
				bStatus = true;
				break;
			}
		}
	} while (false);

	if (Buffer != NULL)
		VirtualFree(Buffer, 0, MEM_RELEASE);

	CloseServiceHandle(hSCM);

	return bStatus;
}

std::wstring GetFileVersion(std::wstring strExePath)
{
  DWORD dwVerInfoSize = 0;
  DWORD dwVerHnd = 0;
  char *pBuf = NULL;
  std::wstring strVer;
  VS_FIXEDFILEINFO   *pVsInfo;
  unsigned int iFileInfoSize = sizeof(VS_FIXEDFILEINFO);
  dwVerInfoSize = GetFileVersionInfoSize(strExePath.data(), NULL);
  if (dwVerInfoSize)
  {
    if (dwVerInfoSize+1 >= MAX_BUFSIZE){
      DI_LOG_WARN("GetFileVersion malloc a large buffer.");
    }
    pBuf = new char[dwVerInfoSize+1];
    if (pBuf == NULL)
      return L"";
    memset(pBuf, 0, dwVerInfoSize+1);
    if (GetFileVersionInfo(strExePath.data(), dwVerHnd, dwVerInfoSize, pBuf)){
      struct LANGANDCODEPAGE
      {
        WORD    wLanguage;
        WORD    wCodePage;
      }*lpTranslate;

      if (VerQueryValue(pBuf, _T("\\VarFileInfo\\Translation"), (void**)&lpTranslate, &iFileInfoSize)){
        unsigned int version_len = 0;
        if (VerQueryValue(pBuf, _T("\\"), (void**)&pVsInfo, &version_len)){
          wchar_t szBuf[32] = {0};
          StringCbPrintf(szBuf, 32, L"%d.%d.%d.%d", HIWORD(pVsInfo->dwProductVersionMS),
            LOWORD(pVsInfo->dwProductVersionMS),
            HIWORD(pVsInfo->dwProductVersionLS),
            LOWORD(pVsInfo->dwProductVersionLS));
          strVer = szBuf;
        }
      }
    }
    delete[] pBuf;
  }
  return strVer;
}

std::wstring GetLargerVerIOAPatternName(void)
{
  std::wstring strPatternName;
  int maxPatternNum = 0, curPatternNum = 0;
  std::wstring tempPatternFile;
  HANDLE hFile = INVALID_HANDLE_VALUE; 
	WIN32_FIND_DATA pNextInfo;  
 
	hFile = FindFirstFile(IOA_PATTERN_NAME, &pNextInfo); 
	if(INVALID_HANDLE_VALUE == hFile){  
		return strPatternName;  
	}  
 
	WCHAR infPath[MAX_PATH] = {0};
	if(pNextInfo.cFileName[0] != '.'){
    strPatternName = pNextInfo.cFileName;
	}
 
	maxPatternNum = GetPatternNumberFromPatternFile(strPatternName);

	while(FindNextFile(hFile, &pNextInfo))  
	{  
		if(pNextInfo.cFileName[0] != '.'){
			tempPatternFile = pNextInfo.cFileName;
			curPatternNum = GetPatternNumberFromPatternFile(tempPatternFile);
			if (maxPatternNum < curPatternNum)
			{
				maxPatternNum = curPatternNum;
				strPatternName = tempPatternFile;
			}

     /* if (strPatternName.compare(pNextInfo.cFileName) < 0){
        strPatternName = pNextInfo.cFileName;
      }*/
		}
	}
 
  FindClose(hFile);
	return strPatternName;
}

int GetPatternNumberFromPatternFile(std::wstring &fileName)
{
	int szPart[2] = {0x0};
	int patternVerNum = 0;
	std::string strPatternNumberBefor, strPatternNumberAfter;
	if (fileName.empty() || !PathFileExists(fileName.c_str()))
	{
		return patternVerNum;
	}

	std::wstring strPatternFileName = fileName;
	std::string strPatternNumber = WcharToString(strPatternFileName.substr(4,strPatternFileName.length()));
	if (SplitString(strPatternNumber, ".", strPatternNumberBefor, strPatternNumberAfter))
	{
		szPart[0] = atoi(strPatternNumberBefor.c_str());
		szPart[1] = atoi(strPatternNumberAfter.c_str());
		szPart[1] = szPart[1] % 1000;

		patternVerNum = szPart[0] * 1000 + szPart[1];
	}

	return patternVerNum;
}

std::wstring GetLargerVerIOAPatternName(std::wstring &Dir)
{
	std::wstring strPatternName;
	HANDLE hFile = INVALID_HANDLE_VALUE; 
	WIN32_FIND_DATA pNextInfo;  
	std::wstring patternPath;
	int maxPatternNum = 0, curPatternNum = 0;
	std::wstring tempPatternFile;
	patternPath = patternPath.assign(Dir);

	if (patternPath[patternPath.length()-1] != '/')
	{
		patternPath += '/';
	}
	hFile = FindFirstFile(patternPath.append(IOA_PATTERN_NAME).c_str(), &pNextInfo); 
	if(INVALID_HANDLE_VALUE == hFile){  
		return strPatternName;  
	}  

	WCHAR infPath[MAX_PATH] = {0};
	if(pNextInfo.cFileName[0] != '.'){
		strPatternName = pNextInfo.cFileName;
	}

	maxPatternNum = GetPatternNumberFromPatternFile(strPatternName);

	while(FindNextFile(hFile, &pNextInfo))  
	{  
		if(pNextInfo.cFileName[0] != '.'){
			tempPatternFile = pNextInfo.cFileName;
			curPatternNum = GetPatternNumberFromPatternFile(tempPatternFile);
			if (maxPatternNum < curPatternNum)
			{
				maxPatternNum = curPatternNum;
				strPatternName = tempPatternFile;
			}
			/*if (strPatternName.compare(pNextInfo.cFileName) < 0){
				strPatternName = pNextInfo.cFileName;
			}*/
		}
	}
	FindClose(hFile);
	return strPatternName;
}

std::string GetStrFromRandom(int iLen /*= 8*/)
{
	std::string sStr;
	sStr.clear();
	char* pData = NULL;
	int iLoop, flag;
	static bool bSrandInit = false;

	if (iLen < 0)
	{
		return sStr;
	}

  if (iLen + 1 >= MAX_BUFSIZE){
		DI_LOG_WARN("GetStrFromRandom malloc a large buffer.");
	}
	pData = new char[iLen + 1];

	if (!bSrandInit)
	{
		srand(GetTickCount());
		bSrandInit = true;
	}
	
	for (iLoop = 0; iLoop < iLen; iLoop++)
	{
		flag = rand() % 3;
		switch (flag)
		{
		case 0:
			pData[iLoop] = rand() % 26 + 'a';
			break;
		case 1:
			pData[iLoop] = rand() % 26 + 'A';
			break;
		case 2:
			pData[iLoop] = rand() % 10 + '0';
			break;
		}
	}

	pData[iLoop] = '\0';

	sStr = pData;

	delete[] pData;

	return sStr;
}

std::string GetFileDir(std::string& filePath)
{
	std::string::size_type pos = filePath.rfind("/");
	if (pos == std::string::npos)
	{
		return filePath;
	}
	return filePath.substr(0, pos);
}

std::string GetStrFromInt(int iData)
{
	char szBuf[12];
	_snprintf_s(szBuf, sizeof(szBuf)-1, "%d", iData);
	return szBuf;
}

std::string GetStrFromUInt(unsigned int iData)
{
	char szBuf[12];
	_snprintf_s(szBuf, sizeof(szBuf)-1, "%u", iData);
	return szBuf;
}
}  // namespace di_rest_client