#include "HraInstall.h"
#include "WinServiceInstall.h"
#include "InstallUtility.h"
#include "utility/version.hpp"
#include "utility/HraAppDef.h"
#include "Libs/LibUtilityBase/LibConfigSave.h"
#include <wchar.h>
#include <Shlwapi.h>
#include <string>
#include <fstream>
#include <time.h>
#include "zlib/unzip.h"
#include "zlib/zconf.h"
#include "zlib/zlib.h"
#include "zlib/zip.h"
#include "json/json.h"
#include <algorithm>

#define HRA_START_ARGC 3

#define HRA_APP_EXE_NAME L"hra.exe"
#define HRA_CONFIG_DIR_NAME L"config"
#define HRA_VERSION_FILE_NAME L"version.ini"
#define HRA_CONFIG_DB_NAME L"config.db"
#define HRA_CONFIG_APP_VERSION L"app_version"
#define HRA_CONFIG_BUILD_VERSION L"build_version"
#define HRA_CONFIG_IPC_INTERFACE_VERSION L"ipc_interface_version"
#define HRA_ZIP_CONFIG_FILE_PATH L"Setup\\config\\version.ini"
#define HRA_UNZIP_COPY_PATH L"setup"
#define HRA_GLOBAL_CONFIG_TABLE "GlobalConfigTable"

//#define REG_HRA_SERVICE_REGISTRY_KEY L"SYSTEM\\CurrentControlSet\\Services"
#define REG_HRA_SERVICE_TYPE L"Type"
#define REG_HRA_SERVICE_VALUE 16

#define HRA_DEFAULT_IPC_INTERFACE_VERSION 1

#define MAX_SERVICE_SIZE (1024 * 1024)

#define LOG_DEBUG_TO_CONSOLE_A(...) do \
                                  {\
                                    char szTemp[MAX_PATH] = {0};\
                                    sprintf_s(szTemp, __VA_ARGS__);\
                                    OutputDebugStringA(szTemp);\
                                  } while (false);

#define LOG_DEBUG_TO_CONSOLE_W(...) do \
                                   {\
                                   wchar_t wszTemp[MAX_PATH] = {0};\
                                   swprintf_s(wszTemp, __VA_ARGS__);\
                                   OutputDebugStringW(wszTemp);\
                                    } while (false);

/// <summary>
/// 获得服务的Config文件信息
/// </summary>
/// <param name="pszParamBuff"></param>
/// <param name="nSizeCount"></param>
/// <param name="pszServiceName"></param>
/// <param name="pszParam"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD GetHraIniValue(wchar_t* pszParamBuff, size_t nSizeCount, const wchar_t* pszServiceName, const wchar_t* pszKey)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !pszKey || wcslen(pszKey) <= 0 || !pszParamBuff ||
        nSizeCount <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    //获得服务配置属性
    wchar_t szBinaryPath[MAX_PATH];
    ZeroMemory(szBinaryPath, sizeof(szBinaryPath));
    dwError = WinSrv_QueryBinaryPathName(pszServiceName, szBinaryPath, MAX_PATH);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //获得安装目录下的version.ini文件
    std::wstring strInstallPath = szBinaryPath;
    strInstallPath              = strInstallPath.substr(0, strInstallPath.rfind(L"\\"));
    wchar_t szConfigPath[MAX_PATH];
    ZeroMemory(szConfigPath, sizeof(szConfigPath));
    _snwprintf_s(szConfigPath, MAX_PATH, MAX_PATH - 1, L"%ls\\%ls\\%ls", strInstallPath.c_str(), HRA_CONFIG_DIR_NAME,
                 HRA_VERSION_FILE_NAME);
    if (!PathFileExists(szConfigPath))
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        return dwError;
    }

    std::wstring strLineTmp;
    std::wstring strFindParam;
    std::wifstream fVersionFile;
    fVersionFile.open(szConfigPath);
    if (!fVersionFile.is_open())
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        return dwError;
    }

    BOOL bFind = FALSE;
    while (std::getline(fVersionFile, strLineTmp))
    {
        size_t posKey = strLineTmp.find(pszKey);
        if (posKey == std::wstring::npos)
        {
            continue;
        }

        size_t posValue = strLineTmp.find(L"=");
        if (std::wstring::npos == posValue)
        {
            continue;
        }

        bFind        = TRUE;
        strFindParam = strLineTmp.substr(posValue + 1, strLineTmp.length() - posValue - 1);
        break;
    }
    fVersionFile.close();

    if (!bFind)
    {
        dwError = ERROR_NOT_FOUND;
        return dwError;
    }

    _snwprintf_s(pszParamBuff, nSizeCount, nSizeCount - 1, L"%ls", strFindParam.c_str());
    HraInst_Trim(pszParamBuff, nSizeCount);
    HraInst_Trim(pszParamBuff, nSizeCount, L"\"");
    return dwError;
}

/// <summary>
/// 获得当前安装的HRA版本
/// </summary>
/// <param name="pszHraVersion"></param>
/// <param name="nBuffSize"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD GetHraInstalledVersion(unsigned __int64& nVersion, const wchar_t* pszServiceName)
{
    DWORD dwError = ERROR_SUCCESS;
    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    wchar_t szHraVersion[1024];
    dwError =
        GetHraIniValue(szHraVersion, sizeof(szHraVersion) / sizeof(wchar_t), pszServiceName, HRA_CONFIG_APP_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    wchar_t szBuildVersion[1024];
    dwError = GetHraIniValue(szBuildVersion, sizeof(szBuildVersion) / sizeof(wchar_t), pszServiceName,
                             HRA_CONFIG_BUILD_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    int ourMaj = 0;
    int ourMin = 0;
    int ourpat = 0;
    int ourBld = 0;
    if (3 == swscanf_s(szHraVersion, L"%d.%d.%d", &ourMaj, &ourMin, &ourpat) &&
        1 == swscanf_s(szBuildVersion, L"%d", &ourBld))
    {
        nVersion = HRA_VERSION_BUILD_MAKE(ourMaj, ourMin, ourpat, ourBld);
    }
    else
    {
        dwError = ERROR_INVALID_DATA;
        return dwError;
    }

    return dwError;
}

/// <summary>
/// 获得当前安装的HRA版本
/// </summary>
/// <param name="szHraVersion">版本号</param>
/// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
/// <returns></returns>
DWORD GetHraInstalledIpcInterfaceVersion(unsigned __int64& nVersion, const wchar_t* pszServiceName)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    wchar_t szInterfaceVersion[1024];
    dwError = GetHraIniValue(szInterfaceVersion, sizeof(szInterfaceVersion) / sizeof(wchar_t), pszServiceName,
                             HRA_CONFIG_IPC_INTERFACE_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    int nIpcInterfaceVersion = 0;
    if (1 == swscanf_s(szInterfaceVersion, L"%d", &nIpcInterfaceVersion))
    {
        nVersion = nIpcInterfaceVersion;
    }
    else
    {
        dwError = ERROR_INVALID_DATA;
        return dwError;
    }

    return dwError;
}

/// <summary>
/// 获得hra zip包的Config文件信息
/// </summary>
/// <param name="pszParamBuff"></param>
/// <param name="nSizeCount"></param>
/// <param name="pszServiceName"></param>
/// <param name="pszParam"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD GetHraZipIniValue(wchar_t* pszParamBuff, size_t nSizeCount, const wchar_t* pszZipPath, const wchar_t* pszKey)
{
    BOOL bFind        = FALSE;
    DWORD dwError     = ERROR_SUCCESS;
    unzFile pvZipFile = NULL;
    std::string strFileCont;
    unz_file_info zFileInfo;
    memset(&zFileInfo, 0, sizeof(zFileInfo));
    char szSubFileName[MAX_PATH];
    memset(szSubFileName, 0, sizeof(szSubFileName));
    char* pscFileData = NULL;
    char szZipPath[MAX_PATH];
    memset(szZipPath, 0, sizeof(szZipPath));
    char szSubIniCmp[MAX_PATH];
    memset(szSubIniCmp, 0, sizeof(szSubIniCmp));
    char szKey[MAX_PATH];
    memset(szKey, 0, sizeof(szKey));

    if (!pszZipPath || wcslen(pszZipPath) <= 0 || !pszKey || wcslen(pszKey) <= 0 || !pszParamBuff || nSizeCount <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    dwError = HraInst_UnicodeToString(szZipPath, sizeof(szZipPath), pszZipPath);
    if (dwError != ERROR_SUCCESS)
    {
        goto _exit;
    }
    dwError = HraInst_UnicodeToString(szKey, sizeof(szKey), pszKey);
    if (dwError != ERROR_SUCCESS)
    {
        goto _exit;
    }
    dwError = HraInst_UnicodeToString(szSubIniCmp, sizeof(szSubIniCmp), HRA_ZIP_CONFIG_FILE_PATH);
    if (dwError != ERROR_SUCCESS)
    {
        goto _exit;
    }

    //文件是否存在
    if (!PathFileExists(pszZipPath))
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    //打开zip文件
    pvZipFile = unzOpen(szZipPath);
    if (NULL == pvZipFile)
    {
        dwError = errno;
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    //获取压缩文件的全局信息
    unz_global_info zGlobalInfo;
    if (unzGetGlobalInfo(pvZipFile, &zGlobalInfo) != UNZ_OK)
    {
        dwError = errno;
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        goto _exit;
    }

    //寻找文件
    for (size_t i = 0; i < zGlobalInfo.number_entry; ++i)
    {
        //从压缩包循环获得子文件信息：文件名， 文件大小
        if (UNZ_OK !=
            unzGetCurrentFileInfo(pvZipFile, &zFileInfo, szSubFileName, sizeof(szSubFileName), NULL, 0, NULL, 0))
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }

        std::string strSubFileName = szSubFileName;
        std::replace(strSubFileName.begin(), strSubFileName.end(), '/', '\\');
        if (strSubFileName != std::string(szSubIniCmp))
        {
            unzGoToNextFile(pvZipFile);
            continue;
        }

        if (UNZ_OK != unzOpenCurrentFile(pvZipFile))
        {
            dwError = errno;
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            goto _exit;
        }

        if (pscFileData)
        {
            free(pscFileData);
            pscFileData = NULL;
        }
        size_t lFileLength = zFileInfo.uncompressed_size; // 子文件长度
        pscFileData        = (char*)malloc(lFileLength + 1);
        memset(pscFileData, 0, lFileLength + 1);
        //解压子文件
        int lUnzSubfileLen          = unzReadCurrentFile(pvZipFile, (voidp)pscFileData, (unsigned int)lFileLength);
        pscFileData[lUnzSubfileLen] = '\0';
        unzCloseCurrentFile(pvZipFile);

        //查找key
        strFileCont   = pscFileData;
        size_t posKey = strFileCont.find(szKey);
        if (posKey == std::wstring::npos)
        {
            dwError = ERROR_NOT_FOUND;
            goto _exit;
        }
        strFileCont = strFileCont.erase(0, posKey);

        posKey = strFileCont.find("\n");
        if (posKey != std::wstring::npos)
        {
            strFileCont = strFileCont.erase(posKey, strFileCont.length() - posKey);
        }

        //截取value
        size_t posValue = strFileCont.find("=");
        if (std::wstring::npos == posValue)
        {
            dwError = ERROR_NOT_FOUND;
            goto _exit;
        }

        strFileCont = strFileCont.substr(posValue + 1, strFileCont.length() - posValue - 1);
        dwError     = HraInst_StringToUnicode(pszParamBuff, nSizeCount, strFileCont.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            goto _exit;
        }
        HraInst_Trim(pszParamBuff, nSizeCount);
        HraInst_Trim(pszParamBuff, nSizeCount, L"\"");
        dwError = ERROR_SUCCESS;
        goto _exit;
    }

_exit:
    if (pvZipFile)
    {
        unzClose(pvZipFile);
        pvZipFile = NULL;
    }

    if (pscFileData)
    {
        free(pscFileData);
        pscFileData = NULL;
    }

    return dwError;
}

/// <summary>
/// 获得zip包的HRA版本
/// </summary>
/// <param name="szHraVersion">版本号</param>
/// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
/// <returns></returns>
DWORD GetHraZipVersion(unsigned __int64& nVersion, const wchar_t* pszZipPath)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszZipPath || wcslen(pszZipPath) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    wchar_t szHraVersion[1024];
    dwError =
        GetHraZipIniValue(szHraVersion, sizeof(szHraVersion) / sizeof(wchar_t), pszZipPath, HRA_CONFIG_APP_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    wchar_t szBuildVersion[1024];
    dwError = GetHraZipIniValue(szBuildVersion, sizeof(szBuildVersion) / sizeof(wchar_t), pszZipPath,
                                HRA_CONFIG_BUILD_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    int ourMaj = 0;
    int ourMin = 0;
    int ourpat = 0;
    int ourBld = 0;
    if (3 == swscanf_s(szHraVersion, L"%d.%d.%d", &ourMaj, &ourMin, &ourpat) &&
        1 == swscanf_s(szBuildVersion, L"%d", &ourBld))
    {
        nVersion = HRA_VERSION_BUILD_MAKE(ourMaj, ourMin, ourpat, ourBld);
    }
    else
    {
        dwError = ERROR_INVALID_DATA;
        return dwError;
    }

    return dwError;
}

/// <summary>
/// 获得zip包的HRA接口版本
/// </summary>
/// <param name="szHraVersion">版本号</param>
/// <param name="nBuffSize">buff大小，szHraVersion字符个数+1</param>
/// <returns></returns>
DWORD GetHraZipIpcInterfaceVersion(unsigned __int64& nVersion, const wchar_t* pszZipPath)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszZipPath || wcslen(pszZipPath) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    wchar_t szInterfaceVersion[1024];
    dwError = GetHraZipIniValue(szInterfaceVersion, sizeof(szInterfaceVersion) / sizeof(wchar_t), pszZipPath,
                                HRA_CONFIG_IPC_INTERFACE_VERSION);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    int nIpcInterfaceVersion = 0;
    if (1 == swscanf_s(szInterfaceVersion, L"%d", &nIpcInterfaceVersion))
    {
        nVersion = nIpcInterfaceVersion;
    }
    else
    {
        dwError = ERROR_INVALID_DATA;
        return dwError;
    }

    return dwError;
}

/// <summary>
/// 通过hra服务名获得安装路径
/// </summary>
/// <param name="pszInstallPath"></param>
/// <param name="nSizeCount"></param>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD GetHraInstallPathByServiceName(wchar_t* pszInstallPath, size_t nSizeCount, const wchar_t* pszServiceName)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszInstallPath || nSizeCount <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    wchar_t szBinaryPath[MAX_PATH];
    ZeroMemory(szBinaryPath, sizeof(szBinaryPath));
    dwError = WinSrv_QueryBinaryPathName(pszServiceName, szBinaryPath, MAX_PATH);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    std::wstring strPath = szBinaryPath;
    strPath              = strPath.substr(0, strPath.rfind(L"\\"));
    _snwprintf_s(pszInstallPath, nSizeCount, nSizeCount - 1, L"%ls", strPath.c_str());
    return dwError;
}

/// <summary>
/// 通过hra安装路径获得服务名
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="nSizeCount"></param>
/// <param name="pszInstallPath"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
// BOOL GetHraServiceNameByInstallPath(wchar_t* pszServiceName, size_t nSizeCount, const wchar_t* pszInstallPath,
//                                    DWORD* pWin32ErrorCode)
//{
//    //枚举服务列表
//    SC_HANDLE hSCManager = NULL, hService = NULL;
//    BOOL bRet   = TRUE;
//    DWORD dwErr = ERROR_SUCCESS;
//
//    DWORD bufferSize         = 0;
//    DWORD requiredBufferSize = 0;
//    DWORD totalServicesCount = 0;
//
//    wchar_t szPathTemp[MAX_PATH];
//    ZeroMemory(szPathTemp, sizeof(szPathTemp));
//    wchar_t szInstallPath[MAX_PATH];
//    ZeroMemory(szInstallPath, sizeof(szInstallPath));
//
//    LPENUM_SERVICE_STATUS_PROCESS pServiceStatus = NULL;
//
//    _snwprintf_s(szPathTemp, sizeof(szPathTemp) / sizeof(wchar_t), L"%ls\\%ls", pszInstallPath, HRA_APP_EXE_NAME);
//    DWORD dwPathLen = GetFullPathName(szPathTemp, MAX_PATH - 1, szInstallPath, NULL);
//    if (dwPathLen == 0)
//    {
//        dwErr = GetLastError();
//        bRet  = FALSE;
//        goto _exit;
//    }
//    for (size_t i = 0; i < wcslen(szInstallPath); ++i)
//    {
//        szInstallPath[i] = ::towlower(szInstallPath[i]);
//    }
//
//    hSCManager  = OpenSCManager(NULL, NULL, GENERIC_READ);
//    if (hSCManager == NULL)
//    {
//        dwErr = GetLastError();
//        bRet  = FALSE;
//        goto _exit;
//    }
//
//    pServiceStatus = (LPENUM_SERVICE_STATUS_PROCESS)LocalAlloc(LPTR, MAX_SERVICE_SIZE);
//    if (!EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
//                              (LPBYTE)pServiceStatus, requiredBufferSize, &requiredBufferSize, &totalServicesCount,
//                              nullptr, nullptr))
//    {
//        dwErr = GetLastError();
//        bRet  = FALSE;
//        goto _exit;
//    }
//
//    for (size_t i = 0; i < totalServicesCount; ++i)
//    {
//        ENUM_SERVICE_STATUS_PROCESS service = pServiceStatus[i];
//        QUERY_SERVICE_CONFIG SrvConfig;
//        memset(&SrvConfig, 0, sizeof(SrvConfig));
//        DWORD nBuffSize = (DWORD)sizeof(SrvConfig);
//        std::wstring strServiceBinName;
//
//        hService = OpenService(hSCManager, service.lpServiceName, GENERIC_READ);
//        if (hService == NULL)
//        {
//            dwErr = GetLastError();
//            bRet  = FALSE; // cannot open the service manager
//            goto _exit;
//        }
//
//        if (!QueryServiceConfig(hService, &SrvConfig, nBuffSize, &nBuffSize))
//        {
//            dwErr = GetLastError();
//            bRet  = FALSE; // cannot open the service manager
//            goto _exit;
//        }
//
//        strServiceBinName = SrvConfig.lpBinaryPathName;
//        for (size_t j = 0; j < strServiceBinName.length(); ++j)
//        {
//            strServiceBinName[i] = ::towlower(strServiceBinName[i]);
//        }
//
//        if (strServiceBinName != szInstallPath)
//        {
//            continue;
//        }
//
//        _snwprintf_s(pszServiceName, nSizeCount, nSizeCount - 1, L"%ls", service.lpServiceName);
//        dwErr = ERROR_SUCCESS;
//        bRet  = TRUE;
//        goto _exit;
//    }
//
//_exit:
//    if (hService)
//    {
//        CloseServiceHandle(hService);
//        hService = NULL;
//    }
//
//    if (hSCManager)
//    {
//        CloseServiceHandle(hSCManager);
//        hSCManager == NULL;
//    }
//
//    if (pServiceStatus)
//    {
//        LocalFree(pServiceStatus);
//        pServiceStatus = NULL;
//    }
//
//    if (pWin32ErrorCode)
//    {
//        *pWin32ErrorCode = dwErr;
//    }
//    return bRet;
//}

/// <summary>
/// 判断HRA是否已经安装
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
BOOL IsHraInstalled(const wchar_t* pszServiceName)
{
    return WinSrv_Exists(pszServiceName);
}

/// <summary>
/// 获得hra服务状态
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="sStatus"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD GetHraServiceStatus(const wchar_t* pszServiceName, SERVICE_STATUS& sStatus)
{
    return WinSrv_QueryStatus(pszServiceName, sStatus);
}

/// <summary>
/// 启动hra服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pszUUID"></param>
/// <param name="pszProCommName"></param>
/// <param name="pszHraCommName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD HraStart(const wchar_t* pszServiceName, const wchar_t* pszUUID, const wchar_t* pszProIpcName,
               const wchar_t* pszHraIpcName)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || !pszUUID || !pszProIpcName || !pszHraIpcName)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    if (!WinSrv_Exists(pszServiceName))
    {
        dwError = ERROR_NOT_FOUND;
        return dwError;
    }

    //"--uuid xxxxxx --pro_ipc_name xxxxxx --hra_ipc_name xxxxxx"
    wchar_t szParamUUID[1024];
    ZeroMemory(szParamUUID, sizeof(szParamUUID));
    _snwprintf_s(szParamUUID, sizeof(szParamUUID) / sizeof(wchar_t), L"%ls%ls %ls", HRA_INSTALL_PARAM_START,
                 HRA_INSTALL_PARAM_UUID, pszUUID);
    wchar_t szParamProIpcName[1024];
    ZeroMemory(szParamProIpcName, sizeof(szParamProIpcName));
    _snwprintf_s(szParamProIpcName, sizeof(szParamProIpcName) / sizeof(wchar_t), L"%ls%ls %ls", HRA_INSTALL_PARAM_START,
                 HRA_INSTALL_PARAM_PRO_IPC_NAME, pszProIpcName);
    wchar_t szParamHraIpcName[1024];
    ZeroMemory(szParamHraIpcName, sizeof(szParamHraIpcName));
    _snwprintf_s(szParamHraIpcName, sizeof(szParamHraIpcName) / sizeof(wchar_t), L"%ls%ls %ls", HRA_INSTALL_PARAM_START,
                 HRA_INSTALL_PARAM_HRA_IPC_NAME, pszHraIpcName);

    //无论传几个参数，hra都能够处理
    DWORD dwArgc = HRA_START_ARGC;
    LPCWSTR pArgv[HRA_START_ARGC];
    pArgv[0] = szParamUUID;
    pArgv[1] = szParamProIpcName;
    pArgv[2] = szParamHraIpcName;
    return WinSrv_StartService(pszServiceName, dwArgc, pArgv);
}

/// <summary>
/// 停止hra服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <returns></returns>
DWORD HraStop(const wchar_t* pszServiceName)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    if (!WinSrv_Exists(pszServiceName))
    {
        return dwError;
    }

    return WinSrv_StopService(pszServiceName);
}

/// <summary>
/// 创建服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pszInstallPath"></param>
/// <returns></returns>
DWORD HraCreateService(const wchar_t* pszServiceName, const wchar_t* pszInstallPath)
{
    return HraCreateServiceEX(pszServiceName, pszInstallPath, L"");
}

DWORD HraCreateServiceEX(const wchar_t* pszServiceName, const wchar_t* pszInstallPath, const wchar_t* pszDataPath)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !pszInstallPath || wcslen(pszInstallPath) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    //服务存在则直接返回true
    if (WinSrv_Exists(pszServiceName))
    {
        return dwError;
    }

    //文件不存在
    if (!PathFileExists(pszInstallPath))
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        return dwError;
    }

    wchar_t szHraPath[MAX_PATH];
    ZeroMemory(szHraPath, sizeof(szHraPath));
    size_t iLen = wcslen(pszInstallPath);
    if (pszInstallPath[iLen - 1] == L'\\')
    {
        _snwprintf_s(szHraPath, MAX_PATH, MAX_PATH - 1, L"%s%s", pszInstallPath, HRA_APP_EXE_NAME); 
    }
    else
    {
        _snwprintf_s(szHraPath, MAX_PATH, MAX_PATH - 1, L"%s\\%s", pszInstallPath, HRA_APP_EXE_NAME);
    }
    if (!PathFileExists(szHraPath))
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        return dwError;
    }

    //路径加上双引号
    wchar_t szHraPathQuot[MAX_PATH] = {0};
    _snwprintf_s(szHraPathQuot, MAX_PATH, MAX_PATH - 1, L"\"%s\"", szHraPath);

    wchar_t szDisplayName[MAX_PATH];
    ZeroMemory(szDisplayName, sizeof(szDisplayName));
    _snwprintf_s(szDisplayName, MAX_PATH, MAX_PATH - 1, L"AsiaInfo Security Host Hardening Agent");
    DWORD dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    dwError = WinSrv_Create(pszServiceName, szDisplayName, dwServiceType, SERVICE_DEMAND_START, szHraPathQuot,
                            L"Extended Base", NULL);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //设置hra失败后动作属性
    SC_ACTION action[3];
    action[0].Type  = SC_ACTION_RESTART;
    action[0].Delay = 60000;
    action[1].Type  = SC_ACTION_RESTART;
    action[1].Delay = 60000;
    action[2].Type  = SC_ACTION_RESTART;
    action[2].Delay = 60000;
    SERVICE_FAILURE_ACTIONS failureActions;
    failureActions.dwResetPeriod = 0;
    failureActions.lpRebootMsg   = NULL;
    failureActions.lpCommand     = NULL;
    failureActions.lpsaActions   = action;
    failureActions.cActions      = 3;

    dwError = WinSrv_ChangeConfig(pszServiceName, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //修改服务注册表值
    wchar_t szHraKey[MAX_PATH];
    ZeroMemory(szHraKey, sizeof(szHraKey));
    _snwprintf_s(szHraKey, MAX_PATH, L"%ls\\%ls", REG_HRA_SERVICE_REGISTRY_KEY, pszServiceName);
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, szHraKey, 0, (KEY_READ | KEY_WRITE), &hKey) == ERROR_SUCCESS)
    {
        DWORD dwType  = 0;
        DWORD dwLen   = 0;
        DWORD dwValue = REG_HRA_SERVICE_VALUE;
        if (RegQueryValueEx(hKey, REG_HRA_SERVICE_TYPE, 0, &dwType, (LPBYTE)szHraKey, &dwLen) == ERROR_SUCCESS)
        {
            dwError =
                RegSetValueEx(hKey, REG_HRA_SERVICE_TYPE, NULL, REG_DWORD, (BYTE* const) & dwValue, sizeof(DWORD));
            if (dwError != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return dwError;
            }
        }
        // hra有关注册表中设置指定数据路径
        wchar_t wszDataPathTmp[MAX_PATH] = {0};
        if (pszDataPath != NULL && _wcsicmp(pszDataPath, L"") != 0)
        {   // 产线指定了数据路径
            size_t iLength = wcslen(pszDataPath);
            if (pszDataPath[iLength - 1] == L'\\')
            {
                _snwprintf_s(wszDataPathTmp, MAX_PATH - 1, L"%s%s\\", pszDataPath, pszServiceName);
            }
            else
            {
                _snwprintf_s(wszDataPathTmp, MAX_PATH - 1, L"%s\\%s\\", pszDataPath, pszServiceName); 
            }
        }
        else
        {   // 产线没有指定数据路径, 则使用缺省路径
            wchar_t wszProgramDir[MAX_PATH] = {0};
            dwError                         = HraInst_GetProgramDataDir(wszProgramDir, sizeof(wszProgramDir));
            if (dwError != ERROR_SUCCESS)
            {
                RegCloseKey(hKey);
                return dwError;
            }
            _snwprintf_s(wszDataPathTmp, sizeof(wszDataPathTmp), L"%s\\%s\\%s\\", wszProgramDir,
                         HRAW_PARAM_AIS_DIR_NAME, pszServiceName);
        }
        dwError = RegSetValueExW(hKey, REG_HRA_DATA_DIR, NULL, REG_EXPAND_SZ, (LPCBYTE)wszDataPathTmp,
                                 wcslen(wszDataPathTmp) * sizeof(wchar_t));
        RegCloseKey(hKey);
    }

    return dwError;
}

/// <summary>
/// 安装hra服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pszInstallPath"></param>
/// <param name="pszZipPath"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD HraInstall(const wchar_t* pszServiceName, const wchar_t* pszZipPath,
                                 const wchar_t* pszInstallPath)
{
    return HraInstallEX(pszServiceName, pszZipPath, pszInstallPath, L"");
}

DWORD HraInstallEX(const wchar_t* pszServiceName, const wchar_t* pszZipPath, const wchar_t* pszInstallPath,
                 const wchar_t* pszDataPath)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !pszInstallPath || wcslen(pszInstallPath) <= 0 ||
        !pszZipPath || wcslen(pszZipPath) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    if (IsHraInstalled(pszServiceName))
    {
        dwError = ERROR_SERVICE_EXISTS;
        return dwError;
    }

    // zip包是否存在
    if (!PathFileExists(pszZipPath))
    {
        dwError = GetLastError();
        dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
        return dwError;
    }

    //安装路径不存在则创建
    if (!HraInst_IsDirExists(pszInstallPath))
    {
        //创建安装目录
        if (!CreateDirectory(pszInstallPath, NULL))
        {
            dwError = GetLastError();
            dwError = (dwError == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwError);
            return dwError;
        }
    }

    wchar_t szUnzipTmpPath[MAX_PATH];
    ZeroMemory(szUnzipTmpPath, sizeof(szUnzipTmpPath));
    _snwprintf_s(szUnzipTmpPath, MAX_PATH, MAX_PATH - 1, L"%ls\\unzip_tmp_%lld", pszInstallPath, time(NULL));

    //解压zip包至解压目录
    dwError = HraInst_Unzip(pszZipPath, szUnzipTmpPath);
    if (dwError != ERROR_SUCCESS)
    {
        HraInst_RemoveDirectory(szUnzipTmpPath);
        return dwError;
    }

    //拷贝文件至安装目录
    wchar_t szCpoyPath[MAX_PATH];
    ZeroMemory(szCpoyPath, sizeof(szCpoyPath));
    _snwprintf_s(szCpoyPath, MAX_PATH, MAX_PATH - 1, L"%ls\\%ls", szUnzipTmpPath, HRA_UNZIP_COPY_PATH);
    dwError = HraInst_CopyDirectory(szCpoyPath, pszInstallPath);
    if (dwError != ERROR_SUCCESS)
    {
        HraInst_RemoveDirectory(szUnzipTmpPath);
        return dwError;
    }

    //创建服务
    dwError = HraCreateServiceEX(pszServiceName, pszInstallPath, pszDataPath);
    if (dwError != ERROR_SUCCESS)
    {
        HraInst_RemoveDirectory(szUnzipTmpPath);
        return dwError;
    }

    //删除解压临时目录
    HraInst_RemoveDirectory(szUnzipTmpPath);
    return dwError;
}

/// <summary>
/// 卸载服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD HraUninstall(const wchar_t* pszServiceName)
{
    return HraUninstallEX(pszServiceName, HRA_UNINSTALL_ACTION_DELETE_DATA);
}
DWORD HraUninstallEX(const wchar_t* pszServiceName, int nUninstallAction)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    if (!WinSrv_Exists(pszServiceName))
    {
        return dwError;
    }

    // 从注册表获取指定的数据路径
    wchar_t wszSubKey[MAX_PATH] = {0};
    _snwprintf_s(wszSubKey, MAX_PATH, L"%s\\%s", REG_HRA_SERVICE_REGISTRY_KEY, pszServiceName);
    wchar_t wszDataDir[MAX_PATH] = {0};
    dwError                      = HraInst_GetRegValue(wszDataDir, wszSubKey, REG_HRA_DATA_DIR, HKEY_LOCAL_MACHINE);
    //if (dwError != ERROR_SUCCESS)
    //{
    //    return dwError;
    //}

    //先停止服务
    dwError = HraStop(pszServiceName);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    wchar_t szBinaryPath[MAX_PATH];
    ZeroMemory(szBinaryPath, sizeof(szBinaryPath));
    dwError = WinSrv_QueryBinaryPathName(pszServiceName, szBinaryPath, MAX_PATH);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //删除服务
    dwError = WinSrv_Delete(pszServiceName);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //等待目录释放
    Sleep(1000);

    //安装目录
    std::wstring strInstallPath = szBinaryPath;
    strInstallPath              = strInstallPath.substr(0, strInstallPath.rfind(L"\\"));

    // 更新，保留数据文件
    if (HRA_UNINSTALL_ACTION_UPDATE == nUninstallAction)
    {
        BOOL bHasExption = FALSE;
        dwError          = HraInst_RemoveDirectory_WithException(bHasExption, L"^.+-b[0-9]+\\.[Z|z][I|i][P|p]$",
                                                                 strInstallPath.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            return dwError;
        }
    }
    else
    {
        // 删除安装目录
        dwError = HraInst_RemoveDirectory(strInstallPath.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            return dwError;
        }

        // 删除数据目录 1.产线集成的HRA_v2.0.2分隔升级; 2.产线卸载HRA时
        //wszDataDir可能为空字符串，2.0.2版本没有这个注册表项
        if (wszDataDir != NULL && wcslen(wszDataDir) > 0)
        {
            dwError = HraInst_RemoveDirectory(wszDataDir);
            if (ERROR_SUCCESS != dwError)
            {
                return dwError;
            }
        }
    }

    return dwError;
}

/// <summary>
/// HRA自动判断安装
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pszZipPath"></param>
/// <param name="pszInstallPath"></param>
/// <param name="nInstallType"></param>
/// <param name="nInstallAction"></param>
/// <returns></returns>
DWORD HraAutoInstall(const wchar_t* pszServiceName, const wchar_t* pszZipPath, const wchar_t* pszInstallPath,
                     int nInstallType, int nInstallAction, const wchar_t* pszUUID, const wchar_t* pszProIpcName,
                     const wchar_t* pszHraIpcName)
{
    return HraAutoInstallEX(pszServiceName, pszZipPath, pszInstallPath, nInstallType, nInstallAction, pszUUID,
                            pszProIpcName, pszHraIpcName, L"", HRA_UNINSTALL_ACTION_DELETE_DATA);
}

DWORD HraAutoInstallEX(const wchar_t* pszServiceName, const wchar_t* pszZipPath, const wchar_t* pszInstallPath,
                    int nInstallType, int nInstallAction, const wchar_t* pszUUID, const wchar_t* pszProIpcName,
                     const wchar_t* pszHraIpcName, const wchar_t* pszDataPath,
                     int nUninstallAction)
{
    DWORD dwError = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    //获取zip包信息
    unsigned __int64 ulHraZipVersion = 0;
    dwError                          = GetHraZipVersion(ulHraZipVersion, pszZipPath);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    unsigned __int64 ulHraZippcInterfaceVersion = 0;
    dwError                                     = GetHraZipIpcInterfaceVersion(ulHraZippcInterfaceVersion, pszZipPath);
    if (dwError != ERROR_SUCCESS)
    {
        ulHraZippcInterfaceVersion = HRA_DEFAULT_IPC_INTERFACE_VERSION;
    }

    //已安装的Hra版本
    unsigned __int64 ulHraInstalledVersion             = 0;
    unsigned __int64 ulHraInstalledIpcInterfaceVersion = 0;
    if (IsHraInstalled(pszServiceName))
    {
        dwError = GetHraInstalledVersion(ulHraInstalledVersion, pszServiceName);
        if (dwError != ERROR_SUCCESS)
        {
            return dwError;
        }

        dwError = GetHraInstalledIpcInterfaceVersion(ulHraInstalledIpcInterfaceVersion, pszServiceName);
        if (dwError != ERROR_SUCCESS)
        {
            ulHraInstalledIpcInterfaceVersion = HRA_DEFAULT_IPC_INTERFACE_VERSION;
        }
    }

    //产品集成部署
    if (nInstallType == HRA_INSTALL_TYPE_INTEGRATED)
    {
        //已安装的版本更高，无需更新
        if (ulHraInstalledVersion >= ulHraZipVersion)
        {
            dwError = ERROR_SUCCESS;
            return dwError;
        }
    }
    //独立部署
    else if (nInstallType == HRA_INSTALL_TYPE_INDEPENDENT)
    {
        //如果接口版本号不一致，不允许安装
        if (ulHraZippcInterfaceVersion != ulHraInstalledIpcInterfaceVersion)
        {
            dwError = ERROR_INSTALL_PACKAGE_VERSION;
            return dwError;
        }

        //已安装的版本更高，无需更新
        if (ulHraInstalledVersion >= ulHraZipVersion)
        {
            dwError = ERROR_SUCCESS;
            return dwError;
        }
    }
    //强制安装
    else if (nInstallType == HRA_INSTALL_TYPE_FORCE)
    {
        //无需任何动作，直接执行下方的安装
    }
    //参数错误
    else
    {
        dwError = ERROR_BAD_ARGUMENTS;
        return dwError;
    }

    //先卸载服务
    dwError = HraUninstallEX(pszServiceName, nUninstallAction);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //_install:
    //安装hra
    dwError = HraInstallEX(pszServiceName, pszZipPath, pszInstallPath, pszDataPath);
    if (dwError != ERROR_SUCCESS)
    {
        return dwError;
    }

    //立即启动
    if (nInstallAction == HRA_INSTALL_ACTION_START_SERVER)
    {
        dwError = HraStart(pszServiceName, pszUUID, pszProIpcName, pszHraIpcName);
        if (dwError != ERROR_SUCCESS)
        {
            return dwError;
        }
    }

    return dwError;
}

DWORD GetHraLoadedPatternVersion(wchar_t* pwszValue, size_t nSizeCount, const wchar_t* pwszServiceName)
{
    LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] >>>>>>>>>>>>>");
    
    DWORD dwError = ERROR_SUCCESS;
    
    Json::Value jsValue;
    jsValue["sysscan_pattern_version"]  = "";
    jsValue["sysscan_update_time"]      = "";
    jsValue["baseline_pattern_version"] = "";
    jsValue["baseline_update_time"]     = "";
    jsValue["wpscan_pattern_version"]   = "";
    jsValue["wpscan_update_time"]       = "";
    jsValue["vuln_pattern_display_version"]       = "";

    do 
    {
        // 参数校验
        if (!pwszValue || nSizeCount <= 0 || !pwszServiceName || wcslen(pwszServiceName) <= 0)
        {
            dwError = ERROR_BAD_ARGUMENTS;
            LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] invalid args");
            break;
        }

        // 获取HRA的安装位置
        wchar_t wszBinaryPath[MAX_PATH] = {0};
        dwError                         = WinSrv_QueryBinaryPathName(pwszServiceName, wszBinaryPath, MAX_PATH);
        if (dwError != ERROR_SUCCESS)
        {
            LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] invalid service name: %s", pwszServiceName);
            break;
        }

        // 获取config.db文件路径
        std::wstring wstrInstallPath = wszBinaryPath;

        wstrInstallPath              = wstrInstallPath.substr(0, wstrInstallPath.rfind(L"\\"));

        std::wstring wstrConfigPath  = wstrInstallPath + L"\\" + HRA_CONFIG_DIR_NAME;
        wstrConfigPath = wstrConfigPath + L"\\" + HRA_CONFIG_DB_NAME;

        // config.db不存在
        if (!PathFileExistsW(wstrConfigPath.c_str()))
        {
            dwError = ERROR_FILE_NOT_FOUND;
            LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] invalid config db: %s", wstrConfigPath.c_str());
            break;
        }

        // config.db路径，宽字节转成ASCII
        char szPath[MAX_PATH] = {0};
        dwError               = HraInst_UnicodeToString(szPath, MAX_PATH, wstrConfigPath.c_str());
        if (dwError != ERROR_SUCCESS)
        {
            LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] convert to char failed, errCode: %d", dwError);
            break;
        }

        // 读取config.db中内容
        CLibConfigSave clibConfigDB;

        dwError = clibConfigDB.ConfigSaveInit(szPath);
        if (dwError != ERROR_SUCCESS)
        {
            LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] open db failed, errCode: %d", dwError);
            break;
        }

        jsValue["sysscan_pattern_version"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "OsscanPatternVersion");
        jsValue["sysscan_update_time"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "OsscanPatternUpdateTime");
        jsValue["baseline_pattern_version"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "BaselinePatternVersion");
        jsValue["baseline_update_time"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "BaselinePatternUpdateTime");
        jsValue["wpscan_pattern_version"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "WpscanPatternVersion");
        jsValue["wpscan_update_time"] =
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "WpscanPatternUpdateTime");

        // Windows上漏洞严格来说只有系统漏洞，POC规则也是放在系统漏洞里面的，所以把系统漏洞版本号当成漏洞版本号显示。
        jsValue["vuln_pattern_display_version"] = 
            clibConfigDB.ConfigSaveGetValue(HRA_GLOBAL_CONFIG_TABLE, "OsscanDisplayVersion");

        dwError = ERROR_SUCCESS;

    } while (false);

    LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] dwError: %d", dwError);

    // 获取成功
    if(dwError == ERROR_SUCCESS)
    {
        // 转成json字符串
        dwError = HraInst_JsontoWString(pwszValue, nSizeCount, jsValue);
        LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] to json string retcode: %d", dwError);
    }

    LOG_DEBUG_TO_CONSOLE_W(L"[GetHraLoadedPatternVersion] <<<<<<<<<<<<<<<<<<<");

    return dwError;
}
