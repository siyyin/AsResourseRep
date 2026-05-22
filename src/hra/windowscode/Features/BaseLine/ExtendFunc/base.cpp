#ifdef _WIN32
#include "base.h"
#include <stdio.h>
#include <time.h>
#include <winsock2.h>
#include <Windows.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include "utility/Logger.h"
#include "utility/HraUtils.h"
#include "openssl/sha.h"


#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "Iphlpapi.lib")

#ifdef _WIN32
#ifdef _WIN64
#pragma comment(lib, "libcrypto64MT.lib")
#pragma comment(lib, "libssl64MT.lib")
#else
#pragma comment(lib, "libcrypto32MT.lib")
#pragma comment(lib, "libssl32MT.lib")
#endif
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#endif

#define FILE_INFO_SIZE 4096

LPWSTR ConverStringToUnicode(const char* Str)
{
    int BufferSize = 0;

    LPWSTR UnicodeStr = NULL;
    if (Str == NULL)
        return NULL;

    BufferSize = MultiByteToWideChar(CP_UTF8, 0, Str, (int)strlen(Str), NULL, 0);
    if (BufferSize == 0)
        return NULL;

    UnicodeStr = (LPWSTR)VirtualAlloc(NULL, (BufferSize + 1) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
    if (UnicodeStr == NULL)
        return NULL;

    BufferSize = MultiByteToWideChar(CP_UTF8, 0, Str, (int)strlen(Str), UnicodeStr, (BufferSize + 1) * sizeof(WCHAR));
    if (BufferSize == 0)
    {
        //
        VirtualFree(UnicodeStr, 0, MEM_RELEASE);
        return NULL;
    }

    return UnicodeStr;
}

LPSTR ConvertUnicodeString(WCHAR* Str)
{
    int BufferSize     = 0;
    LPSTR OutputBuffer = NULL;
    if (Str == NULL)
        return NULL;

    BufferSize = WideCharToMultiByte(GetACP(), 0, Str, (int)wcslen(Str), NULL, 0, NULL, NULL);
    if (BufferSize == 0)
        return NULL;

    OutputBuffer = (LPSTR)VirtualAlloc(NULL, BufferSize + 1, MEM_COMMIT, PAGE_READWRITE);
    if (OutputBuffer == NULL)
        return NULL;

    BufferSize = WideCharToMultiByte(GetACP(), 0, Str, (int)wcslen(Str), OutputBuffer, BufferSize + 1, NULL, NULL);
    if (GetLastError() == 0)
    {
        return OutputBuffer;
    }
    else
    {
        VirtualFree(OutputBuffer, 0, MEM_RELEASE);
        return NULL;
    }
}

void ConvertSlashSymbol(char* str)
{
    _strlwr_s(str, strlen(str) + 1);
    char* ptr = str;
    while (*ptr++)
    {
        if (*ptr == '\\')
            *ptr = '/';
    }
}

void ConvertBackSlashSymbol(char* str)
{
    char* ptr = str;
    while (*ptr++)
    {
        if (*ptr == '/')
            *ptr = '\\';
    }
}

/// <summary>
/// 时间转换
/// </summary>
/// <param name="ft"></param>
/// <returns></returns>
time_t FileTimeToUnixTime(FILETIME& ft)
{
    ULARGE_INTEGER ull = {0};
    ull.LowPart        = ft.dwLowDateTime;
    ull.HighPart       = ft.dwHighDateTime;
    return ull.QuadPart / 10000000ULL - 11644473600ULL;
}

/// <summary>
/// 获得注册表路径中的软件信息；
/// 参考资产，但是有区别，此处不能排重
/// </summary>
/// <param name="vctSoftware"></param>
/// <param name="RootKey"></param>
/// <param name="lpSubKey"></param>
void GetSoftWare(std::vector<BASELINE_SOFTWARE>& vctSoftware, HKEY RootKey, LPCTSTR lpSubKey)
{
    HKEY hkResult;
    HKEY hkRKey;
    LONG lReturn;
    //std::wstring strBuffer;
    //std::wstring strMidReg;

    DWORD index                  = 0;
    WCHAR szKeyName[MAX_LEN_256] = {0};
    WCHAR szBuffer[MAX_LEN_256]  = {0};
    DWORD dwKeyLen               = MAX_LEN_256;
    DWORD dwBuffLen              = MAX_LEN_256;
    DWORD dwType                 = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
    FILETIME ftLastWriteTime;

    lReturn = RegOpenKeyEx(RootKey, lpSubKey, 0, KEY_ALL_ACCESS, &hkResult);
    if (lReturn == ERROR_SUCCESS)
    {
        ZeroMemory(szKeyName, sizeof(szKeyName));
        while (ERROR_NO_MORE_ITEMS !=
               RegEnumKeyEx(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime))
        {
            Sleep(1);
            index++;
            if (wcslen(szKeyName) >= 0)
            {
                BASELINE_SOFTWARE software = {0};
                std::wstring strMidReg     = lpSubKey;
                strMidReg                  = strMidReg + L"\\" + szKeyName;
                _snprintf_s(software.szRegFullPath, sizeof(software.szRegFullPath), "%s\\%s",
                            UtilsUnicodeToString(GetRegRootKeyString(RootKey)).c_str(),
                            UtilsUnicodeToString(strMidReg).c_str());
                //LOG_DEBUG("RegFullPath:%s", software.szRegFullPath);

                lReturn = RegOpenKeyEx(RootKey, strMidReg.c_str(), 0, KEY_ALL_ACCESS, &hkRKey);
                if (lReturn == ERROR_SUCCESS)
                {
                    WCHAR szParentKeyName[MAX_LEN_256]   = {0};
                    DWORD dwParentKeyNameLen             = MAX_LEN_256;
                    WCHAR szSystemComponent[MAX_LEN_256] = {0};
                    DWORD dwSystemComponentLen           = MAX_LEN_256;
                    RegQueryValueEx(hkRKey, L"ParentKeyName", 0, &dwType, (LPBYTE)szParentKeyName, &dwParentKeyNameLen);
                    if (szParentKeyName[0] == 0)
                    {
                        RegQueryValueEx(hkRKey, L"SystemComponent", 0, &dwType, (LPBYTE)szSystemComponent,
                                        &dwSystemComponentLen);
                    }

                    if (szParentKeyName[0] == 0 && szSystemComponent[0] != 1)
                    {
                        lReturn = RegQueryValueEx(hkRKey, L"DisplayVersion", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        if (lReturn == ERROR_SUCCESS)
                        {
                            std::string Softversion = UtilsUnicodeToString(szBuffer).c_str();
                            Softversion             = UtilsTrim(Softversion, "\"");
                            strncpy_s(software.szSoftVersion, sizeof(software.szSoftVersion) - 1, Softversion.c_str(),
                                      -1);
                        }
                        else
                        {
                            LOG_DEBUG("RegKey:%s RegQueryValue: DisplayVersion error. %ld",
                                      UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        }
                        dwBuffLen = MAX_LEN_256;

                        lReturn = RegQueryValueEx(hkRKey, L"Publisher", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        if (lReturn == ERROR_SUCCESS)
                        {
                            std::string vendor = UtilsUnicodeToString(szBuffer).c_str();
                            vendor             = UtilsTrim(vendor, "\"");
                            strncpy_s(software.szVendor, sizeof(software.szVendor) - 1, vendor.c_str(), -1);
                        }
                        else
                        {
                            LOG_DEBUG("RegKey:%s RegQueryValue: Publisher error. %ld",
                                      UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        }
                        dwBuffLen = MAX_LEN_256;

                        lReturn = RegQueryValueEx(hkRKey, L"InstallLocation", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        if (lReturn == ERROR_SUCCESS)
                        {
                            std::string path = UtilsUnicodeToString(szBuffer).c_str();
                            path             = UtilsTrim(path, "\"");
                            strncpy_s(software.szInstallLocation, sizeof(software.szInstallLocation) - 1, path.c_str(),
                                      -1);
                        }
                        else
                        {
                            LOG_DEBUG("RegKey:%s RegQueryValue: InstallLocation error. %ld",
                                      UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        }
                        dwBuffLen = MAX_LEN_256;

                        lReturn = RegQueryValueEx(hkRKey, L"InstallDate", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        if (lReturn == ERROR_SUCCESS)
                        {
                            std::string installtime = UtilsUnicodeToString(szBuffer).c_str();
                            if (installtime.length() == 8)
                            {
                                struct tm sTime = {0};
                                sscanf_s(installtime.c_str(), "%04d%02d%02d", &sTime.tm_year, &sTime.tm_mon,
                                         &sTime.tm_mday);
                                sTime.tm_year -= 1900;
                                sTime.tm_mon -= 1;
                                time_t t = mktime(&sTime);
                                _snprintf_s(software.szInstallTime, MAX_LEN_32 - 1, sizeof(software.szInstallTime) - 1,
                                            "%lld", t);
                                if (strlen(software.szInstallTime) != 10)
                                {
                                    software.szInstallTime[0] = 0;
                                }
                            }
                            else
                            {
                                LOG_DEBUG("RegKey:%s InstallDate's length not equal 8.",
                                          UtilsUnicodeToString(strMidReg).c_str());
                            }
                        }
                        else
                        {
                            LOG_DEBUG("RegKey:%s RegQueryValue: InstallDate error. %ld",
                                      UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        }

                        if (software.szInstallTime[0] == 0)
                        {
                            time_t t = FileTimeToUnixTime(ftLastWriteTime);
                            _snprintf_s(software.szInstallTime, MAX_LEN_32 - 1, sizeof(software.szInstallTime) - 1,
                                        "%lld", t);
                            if (strlen(software.szInstallTime) != 10)
                            {
                                software.szInstallTime[0] = 0;
                            }
                        }

                        dwBuffLen = MAX_LEN_256;

                        //lReturn = RegQueryValueEx(hkRKey, L"EstimatedSize", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        //if (lReturn == ERROR_SUCCESS)
                        //{
                        //    software.nSize = *(unsigned int*)szBuffer;
                        //}
                        //else
                        //{
                        //    LOG_DEBUG("RegKey:%s RegQueryValue: EstimatedSize error. %ld",
                        //              UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        //}
                        //dwBuffLen = MAX_LEN_256;

                        lReturn = RegQueryValueEx(hkRKey, L"DisplayName", 0, &dwType, (LPBYTE)szBuffer, &dwBuffLen);
                        if (lReturn == ERROR_SUCCESS)
                        {
                            std::string Softname = UtilsUnicodeToString(szBuffer).c_str();
                            Softname             = UtilsTrim(Softname, "\"");
                            strncpy_s(software.szSoftName, sizeof(software.szSoftName) - 1, Softname.c_str(), -1);
                            vctSoftware.push_back(software);
                        }
                        else
                        {
                            LOG_DEBUG("RegKey:%s RegQueryValue: DisplayName error. %ld",
                                      UtilsUnicodeToString(strMidReg).c_str(), lReturn);
                        }
                        dwBuffLen = MAX_LEN_256;
                    }
                    RegCloseKey(hkRKey);
                }
                else
                {
                    LOG_ERROR("RegOpenKeyEx strMidReg:%s failed. %ld", UtilsUnicodeToString(strMidReg).c_str(),
                              lReturn);
                }
            }
            dwKeyLen = MAX_LEN_256;
        }
        RegCloseKey(hkResult);
    }
    else
    {
        LOG_WARN("RegOpenKeyEx failed. %s %ld", UtilsUnicodeToString(lpSubKey).c_str(), lReturn);
    }
}

void GeRegUserWare(std::vector<BASELINE_SOFTWARE>& vctSoftware, HKEY RootKey)
{
    HKEY hkResult;
    LONG lReturn;
    std::wstring strBuffer;
    std::wstring strMidReg;

    DWORD index                  = 0;
    WCHAR szKeyName[MAX_LEN_256] = {0};
    WCHAR szBuffer[MAX_LEN_256]  = {0};
    DWORD dwKeyLen               = MAX_LEN_256;
    DWORD dwBuffLen              = MAX_LEN_256;
    DWORD dwType                 = REG_BINARY | REG_DWORD | REG_EXPAND_SZ | REG_MULTI_SZ | REG_NONE | REG_SZ;
    FILETIME ftLastWriteTime;

    lReturn = RegOpenKeyEx(RootKey, NULL, 0, KEY_ALL_ACCESS, &hkResult);
    if (lReturn == ERROR_SUCCESS)
    {
        while (ERROR_NO_MORE_ITEMS !=
               RegEnumKeyEx(hkResult, index, szKeyName, &dwKeyLen, 0, NULL, NULL, &ftLastWriteTime))
        {
            Sleep(1);
            index++;
            strBuffer = szKeyName;
            strBuffer = strBuffer + L"\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
            GetSoftWare(vctSoftware, HKEY_USERS, strBuffer.c_str());
            dwKeyLen = MAX_LEN_256;
        }
        RegCloseKey(hkResult);
    }
    else
    {
        LOG_DEBUG("RegOpenKeyEx:HKEY_USERS failed. %ld", lReturn);
    }
}


void EnrichApplication(BASELINE_APPLICATION& application, const wchar_t* pPath)
{
    UtilsFileProperty stProperty;
    if (UtilsGetFileProperty(stProperty, pPath) == HRA_OK)
    {
        _snprintf_s(application.szFileVersion, sizeof(application.szFileVersion), "%s",
                    UtilsUnicodeToString(stProperty.strFileVersion).c_str());
        _snprintf_s(application.szVendor, sizeof(application.szVendor), "%s",
                    UtilsUnicodeToString(stProperty.strCompanyName).c_str());
        _snprintf_s(application.szApplication, sizeof(application.szApplication), "%s",
                    UtilsUnicodeToString(stProperty.strProductName).c_str());
        _snprintf_s(application.szApplicationVersion, sizeof(application.szApplicationVersion), "%s",
                    UtilsUnicodeToString(stProperty.strProductVersion).c_str());
    }

    char buff[FILE_INFO_SIZE] = {0};
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    DWORD bytesRead = 0;
    HANDLE hFile    = ::CreateFileW(pPath, FILE_READ_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
                                    OPEN_EXISTING, NULL, NULL);
    if (hFile != NULL)
    {
        do
        {
            if (!::ReadFile(hFile, buff, FILE_INFO_SIZE, &bytesRead, NULL))
            {
                memset(&ctx, 0, sizeof(SHA_CTX));
                break;
            }
            else
            {
                // Sleep(1);
                SHA1_Update(&ctx, buff, bytesRead);
            }
            Sleep(0);
        } while (bytesRead != 0);

        SHA1_Final(application.ucSha1, &ctx);
        CloseHandle(hFile);
    }
    else
    {
        LOG_ERROR("CreateFileW %s failed. %lu", pPath, GetLastError());
    }
}

/// <summary>
/// 获得应用程序列表
/// </summary>
void GetApplicationInfo(std::map<std::string, BASELINE_APPLICATION>& mapApplication)
{
    char szSystemRootPath[MAX_PATH];
    memset(szSystemRootPath, 0, sizeof(szSystemRootPath));
    DWORD dwRet = GetEnvironmentVariableA("SystemRoot", szSystemRootPath, MAX_PATH - 1);
    if (dwRet == 0 || dwRet == MAX_PATH - 1)
    {
        strncpy_s(szSystemRootPath, MAX_PATH - 1, "C:\\Windows", -1);
    }

    unsigned char szBuff[FILE_INFO_SIZE];
    memset(szBuff, 0, sizeof(szBuff));

    HANDLE hProcessSnap;
    PROCESSENTRY32 proc;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        LOG_ERROR("CreateToolhelp32Snapshot return handle invalid. %lu", GetLastError());
        return;
    }

    proc.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &proc))
    {
        CloseHandle(hProcessSnap);
        LOG_ERROR("Process32First failed. %lu", GetLastError());
        return;
    }

    mapApplication.clear();
    do
    {
        if (proc.th32ProcessID == 0 || proc.th32ProcessID == 4)
        {
            LOG_WARN("th32ProcessID:%lu continue!", proc.th32ProcessID);
            continue;
        }

        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, proc.th32ProcessID);
        if (process == NULL)
        {
            LOG_WARN("th32ProcessID:%lu open null! code:%lu", proc.th32ProcessID, GetLastError());
            continue;
        }

        wchar_t filepath[MAX_PATH] = {0};
        char file_path[MAX_PATH]   = {0};
        if (GetModuleFileNameEx(process, NULL, filepath, MAX_PATH) != 0)
        {
            strncpy_s(file_path, sizeof(file_path) - 1, UtilsUnicodeToString(filepath).c_str(), -1);
            static const char* s_pSystemRootPrefix = "\\SystemRoot\\";
            size_t nTextLen                        = strlen(file_path);
            size_t nPrefixLen                      = strlen(s_pSystemRootPrefix);
            if (nTextLen >= nPrefixLen && _strnicmp(file_path, s_pSystemRootPrefix, nPrefixLen) == 0)
            {
                char szTempPath[MAX_PATH] = {0};
                strcpy_s(szTempPath, file_path + nPrefixLen);
                _snprintf_s(file_path, MAX_PATH - 1, "%s\\%s", szSystemRootPath, szTempPath);
            }

            std::map<std::string, BASELINE_APPLICATION>::iterator iter = mapApplication.find(file_path);
            if (iter != mapApplication.end())
            {
                //iter->second.nUseTime = (UINT32)time(NULL);
                CloseHandle(process);
                continue;
            }

            //EnterCriticalSection(&m_cs);
            BASELINE_APPLICATION application = {0};
            //application.nUseTime           = (unsigned int)time(NULL);
            strncpy_s(application.szFileName, sizeof(application.szFileName) - 1,
                      UtilsUnicodeToString(proc.szExeFile).c_str(), -1);
            strncpy_s(application.szPath, sizeof(application.szPath) - 1, UtilsUnicodeToString(filepath).c_str(), -1);
            EnrichApplication(application, filepath);
            mapApplication[file_path] = application;
            //LeaveCriticalSection(&m_cs);
        }
        else
        {
            LOG_DEBUG("GetModuleFileNameEx failed. %lu", GetLastError());
        }
        CloseHandle(process);
        // Sleep(1000);
    } while (Process32Next(hProcessSnap, &proc));

    CloseHandle(hProcessSnap);

    return;
}

unsigned short aisntohs(unsigned short port)
{
    port = (port << 8) | (port >> 8);
    return port;
}

std::string GetTcpIpv4Port()
{
    DWORD dwRetVal   = 0;
    DWORD dwSize     = 0;
    std::string port = "";

    // 获取合适大小的buffer
    PMIB_TCPTABLE_OWNER_PID pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(sizeof(MIB_TCPTABLE_OWNER_PID));
    if (pTcpTable == NULL)
    {
        return port;
    }

    dwSize = sizeof(MIB_TCPTABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) ==
        ERROR_INSUFFICIENT_BUFFER)
    {
        free(pTcpTable);
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable == NULL)
        {
            return port;
        }
    }

    // 获取TCPTable
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR)
    {
        int nNum = (int)pTcpTable->dwNumEntries;
        for (int i = 0; i < nNum; i++)
        {
            // 只采集监听状态的端口
            if (pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN)
            {
                continue;
            }

            port += std::to_string(aisntohs((u_short)pTcpTable->table[i].dwLocalPort)).c_str();
            port += ";";
        }
    }
    else
    {
        free(pTcpTable);
        return port;
    }

    if (pTcpTable != NULL)
    {
        free(pTcpTable);
        pTcpTable = NULL;
    }
    return port;
}

std::string GetTcpIpv6Port()
{
    DWORD dwRetVal   = 0;
    DWORD dwSize     = 0;
    std::string port = "";

    // 获取合适大小的buffer
    PMIB_TCP6TABLE_OWNER_PID pTcpTable = (MIB_TCP6TABLE_OWNER_PID*)malloc(sizeof(MIB_TCP6TABLE_OWNER_PID));
    if (pTcpTable == NULL)
    {
        return port;
    }

    dwSize = sizeof(MIB_TCP6TABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) ==
        ERROR_INSUFFICIENT_BUFFER)
    {
        free(pTcpTable);
        pTcpTable = (MIB_TCP6TABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable == NULL)
        {
            return port;
        }
    }

    // 获取TCPTable
    if ((dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) == NO_ERROR)
    {
        int nNum = (int)pTcpTable->dwNumEntries;
        for (int i = 0; i < nNum; i++)
        {
            // 只采集监听状态的端口
            if (pTcpTable->table[i].dwState != MIB_TCP_STATE_LISTEN)
            {
                continue;
            }

            port += std::to_string(aisntohs((u_short)pTcpTable->table[i].dwLocalPort)).c_str();
            port += ";";
        }
    }
    else
    {
        free(pTcpTable);
        return port;
    }

    if (pTcpTable != NULL)
    {
        free(pTcpTable);
        pTcpTable = NULL;
    }
    return port;
}

std::string GetUdpIpv4Port()
{
    std::string port;
    DWORD dwRetVal = 0;

    // 获取合适大小的buffer
    PMIB_UDPTABLE_OWNER_PID pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(sizeof(MIB_UDPTABLE_OWNER_PID));
    if (pUdpTable == NULL)
    {
        LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
        return port;
    }

    DWORD dwSize = sizeof(MIB_UDPTABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) ==
        ERROR_INSUFFICIENT_BUFFER)
    {
        free(pUdpTable);
        pUdpTable = (MIB_UDPTABLE_OWNER_PID*)malloc(dwSize);
        if (pUdpTable == NULL)
        {
            LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
            return port;
        }
    }

    // 获取UDPTable
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR)
    {
        int nNum = (int)pUdpTable->dwNumEntries;
        for (int i = 0; i < nNum; i++)
        {
            port += std::to_string(aisntohs((u_short)pUdpTable->table[i].dwLocalPort)).data(); // 端口号
            port += ";";
        }
    }
    else
    {
        LOG_ERROR("GetExtendedUdpTable failed, invalid paramter.");
    }

    if (pUdpTable != NULL)
    {
        free(pUdpTable);
        pUdpTable = NULL;
    }
    return port;
}

std::string GetUdpIpv6Port()
{
    std::string port;
    DWORD dwRetVal = 0;

    // 获取合适大小的buffer
    PMIB_UDP6TABLE_OWNER_PID pUdpTable = (MIB_UDP6TABLE_OWNER_PID*)malloc(sizeof(MIB_UDP6TABLE_OWNER_PID));
    if (pUdpTable == NULL)
    {
        LOG_ERROR("DIAssetPort::get_udp_table_msg：Error allocating memory\n");
        return port;
    }

    DWORD dwSize = sizeof(MIB_UDP6TABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0)) ==
        ERROR_INSUFFICIENT_BUFFER)
    {
        free(pUdpTable);
        pUdpTable = (MIB_UDP6TABLE_OWNER_PID*)malloc(dwSize);
        if (pUdpTable == NULL)
        {
            LOG_ERROR("DIAssetPort::get_udp_table_msg_ex：Error allocating memory\n");
            return port;
        }
    }

    // 获取UDPTable
    if ((dwRetVal = GetExtendedUdpTable(pUdpTable, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0)) == NO_ERROR)
    {
        int nNum = (int)pUdpTable->dwNumEntries;
        for (int i = 0; i < nNum; i++)
        {
            port += std::to_string(aisntohs((u_short)pUdpTable->table[i].dwLocalPort)).data(); // 端口号
            port += ";";
        }
    }
    else
    {
        LOG_ERROR("GetExtendedUdpTable failed, invalid paramter.");
    }

    if (pUdpTable != NULL)
    {
        free(pUdpTable);
        pUdpTable = NULL;
    }
    return port;
}

#endif