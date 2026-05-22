#include "WinServiceInstall.h"
#include <stdio.h>
#include "InstallUtility.h"

//#define HRA_SERVICE_DEF_DAC (SERVICE_ALL_ACCESS & ~DELETE)

/// <summary>
/// 启动服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="dwArgc"></param>
/// <param name="pArgv"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_StartService(const wchar_t* pszServiceName, DWORD dwArgc, LPCWSTR* pArgv)
{
    SC_HANDLE hSCManager(NULL), hService(NULL);
    LPCTSTR ptrMcName = NULL, ptrDBName = NULL;
    SERVICE_STATUS SrvStatus;
    memset(&SrvStatus, 0, sizeof(SrvStatus));
    DWORD dwErr = ERROR_SUCCESS;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(ptrMcName, ptrDBName, GENERIC_READ);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_EXECUTE | GENERIC_READ);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // check service status before StartService() is called.
    if (false == ::QueryServiceStatus(hService, &SrvStatus))
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    if ((SERVICE_RUNNING == SrvStatus.dwCurrentState) || (SERVICE_START_PENDING == SrvStatus.dwCurrentState))
    {
        goto _exit;
    }

    if (!StartService(hService, dwArgc, pArgv))
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

_exit:
    // Close the service handle
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    // Close the SCM
    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}

/// <summary>
/// 
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_StopService(const wchar_t* pszServiceName)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    SERVICE_STATUS SrvStatus;
    memset(&SrvStatus, 0, sizeof(SrvStatus));
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_EXECUTE | GENERIC_READ);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    if (::QueryServiceStatus(hService, &SrvStatus) == FALSE)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    if ((SERVICE_STOPPED == SrvStatus.dwCurrentState) || (SERVICE_STOP_PENDING == SrvStatus.dwCurrentState))
    {
        goto _exit;
    }

    if (ControlService(hService, SERVICE_CONTROL_STOP, &SrvStatus) == FALSE)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    dwTimeout = GetTickCount() + 30000;
    while (::QueryServiceStatus(hService, &SrvStatus) == TRUE)
    {
        ::Sleep(SrvStatus.dwWaitHint);
        if (SrvStatus.dwCurrentState == SERVICE_STOPPED)
        {
            goto _exit;
        }
        if (dwTimeout < GetTickCount())
        {
            dwErr = ERROR_TIMEOUT;
            goto _exit;
        }
    }

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}

/// <summary>
/// 查询状态
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="sStatus"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_QueryStatus(const wchar_t* pszServiceName, SERVICE_STATUS& sStatus)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    SERVICE_STATUS SrvStatus;
    memset(&SrvStatus, 0, sizeof(SrvStatus));
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_READ);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    if (!::QueryServiceStatus(hService, &SrvStatus))
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    memcpy(&sStatus, &SrvStatus, sizeof(SrvStatus));

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}

/// <summary>
/// 查询服务信息
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="sConfig"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_QueryBinaryPathName(const wchar_t* pszServiceName, wchar_t* pszBinaryPathName, size_t nSizeCount)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    LPQUERY_SERVICE_CONFIG pSrvConfig = NULL;
    //memset(&SrvConfig, 0, sizeof(SrvConfig));
    DWORD nBuffSize    = 0;
    //DWORD nOutBuffSize = 0;
    DWORD dwErr        = ERROR_SUCCESS;
    DWORD dwTimeout    = 0;
    DWORD dwPathLen    = 0;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !pszBinaryPathName || nSizeCount <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_READ);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    if (!::QueryServiceConfig(hService, NULL, 0, &nBuffSize))
    {
        dwErr = GetLastError();
        if (dwErr == ERROR_INSUFFICIENT_BUFFER)
        {
            pSrvConfig = (LPQUERY_SERVICE_CONFIG)malloc(nBuffSize);
            if (!pSrvConfig)
            {
                dwErr = ERROR_INVALID_HANDLE;
                goto _exit;
            }

            if (!::QueryServiceConfig(hService, pSrvConfig, nBuffSize, &nBuffSize))
            {
                dwErr = GetLastError();
                dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
                goto _exit;
            }
        }
        else
        {
            dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
            goto _exit;
        }
    }

    if (!pSrvConfig || !pSrvConfig->lpBinaryPathName)
    {
        dwErr = ERROR_INVALID_HANDLE;
        goto _exit;
    }

    dwPathLen = (DWORD)wcslen(pSrvConfig->lpBinaryPathName);
    if (dwPathLen >= nSizeCount)
    {
        dwErr = ERROR_INCORRECT_SIZE;
        goto _exit;
    }

    _snwprintf_s(pszBinaryPathName, nSizeCount, nSizeCount - 1, L"%ls", pSrvConfig->lpBinaryPathName);
    HraInst_Trim(pszBinaryPathName, nSizeCount);
    HraInst_Trim(pszBinaryPathName, nSizeCount, L"\"");
    dwErr = ERROR_SUCCESS;

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    if (pSrvConfig)
    {
        free(pSrvConfig);
        pSrvConfig = NULL;
    }

    return dwErr;
}

/// <summary>
/// 查询服务是否存在
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
BOOL WinSrv_Exists(const wchar_t* pszServiceName)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    //SERVICE_STATUS SrvStatus;
    //memset(&SrvStatus, 0, sizeof(SrvStatus));
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_READ);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_READ);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    //if (!::QueryServiceStatus(hService, &SrvStatus))
    //{
    //    dwErr = GetLastError();
    //    bRet  = FALSE; // cannot open the service manager
    //    goto _exit;
    //}

    //memcpy(&sStatus, &SrvStatus, sizeof(SrvStatus));

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr == ERROR_SUCCESS ? TRUE : FALSE;
}

/// <summary>
/// 创建服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pszDisplayName"></param>
/// <param name="dwServiceType"></param>
/// <param name="dwStartType"></param>
/// <param name="pszBinaryPathName"></param>
/// <param name="pszLoadOrderGroup"></param>
/// <param name="pszDependencies"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_Create(const wchar_t* pszServiceName, const wchar_t* pszDisplayName, const DWORD& dwServiceType,
                    const DWORD& dwStartType, const wchar_t* pszBinaryPathName, const wchar_t* pszLoadOrderGroup,
                    const wchar_t* pszDependencies)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    // SERVICE_STATUS SrvStatus;
    // memset(&SrvStatus, 0, sizeof(SrvStatus));
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;

    DWORD dwDesiredAccess   = SERVICE_ALL_ACCESS;
    DWORD dwErrorControl    = SERVICE_ERROR_NORMAL;
    LPDWORD pdwTagId        = NULL;
    LPCTSTR ptszAccountName = NULL;
    LPCTSTR ptszPassword    = NULL;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !pszDisplayName || wcslen(pszDisplayName) <= 0 ||
        !pszBinaryPathName || wcslen(pszBinaryPathName) <= 0 || !pszLoadOrderGroup || wcslen(pszLoadOrderGroup)<= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_ALL);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    //创建服务
    hService = ::CreateService(hSCManager, pszServiceName, pszDisplayName, dwDesiredAccess, dwServiceType, dwStartType,
                               dwErrorControl, pszBinaryPathName, pszLoadOrderGroup, pdwTagId, pszDependencies,
                               ptszAccountName, ptszPassword);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}

/// <summary>
/// 删除服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
DWORD WinSrv_Delete(const wchar_t* pszServiceName)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;

    if (!pszServiceName || wcslen(pszServiceName) <= 0)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_ALL);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_ALL);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    if (::DeleteService(hService) == FALSE)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}

/// <summary>
/// 修改服务配置属性
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="dwInfoLevel"></param>
/// <param name="lpInfo"></param>
/// <returns></returns>
DWORD WinSrv_ChangeConfig(const wchar_t* pszServiceName, DWORD dwInfoLevel, LPVOID lpInfo)
{
    SC_HANDLE hSCManager = NULL, hService = NULL;
    DWORD dwErr     = ERROR_SUCCESS;
    DWORD dwTimeout = 0;
    SC_LOCK sclLock = NULL;

    if (!pszServiceName || wcslen(pszServiceName) <= 0 || !lpInfo)
    {
        dwErr = ERROR_BAD_ARGUMENTS;
        goto _exit;
    }

    // Open the SCM
    hSCManager = OpenSCManager(NULL, NULL, GENERIC_ALL);
    if (hSCManager == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    // Get the service handle
    hService = OpenService(hSCManager, pszServiceName, GENERIC_ALL);
    if (hService == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        goto _exit;
    }

    sclLock = ::LockServiceDatabase(hSCManager);
    if (sclLock == NULL)
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        ::UnlockServiceDatabase(sclLock);
        goto _exit;
    }

    if (!::ChangeServiceConfig2(hService, dwInfoLevel, lpInfo))
    {
        dwErr = GetLastError();
        dwErr = (dwErr == ERROR_SUCCESS ? ERROR_INVALID_FUNCTION : dwErr);
        ::UnlockServiceDatabase(sclLock);
        goto _exit;
    }
    ::UnlockServiceDatabase(sclLock);

_exit:
    if (hService)
    {
        CloseServiceHandle(hService);
        hService = NULL;
    }

    if (hSCManager)
    {
        CloseServiceHandle(hSCManager);
        hSCManager = NULL;
    }

    return dwErr;
}