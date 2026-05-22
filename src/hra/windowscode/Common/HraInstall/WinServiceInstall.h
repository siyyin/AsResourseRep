#pragma once
#include <Windows.h>
#include "HraInstallDef.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// <summary>
/// 启动Windows NT 服务函数
/// </summary>
/// <param name="_tszServiceName"></param>
/// <param name="wstrUUID"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD WinSrv_StartService(const wchar_t* pszServiceName, DWORD dwArgc, LPCWSTR* pArgv);

/// <summary>
/// 停止Windows NT服务
/// </summary>
/// <param name="_tszServiceName"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD WinSrv_StopService(const wchar_t* pszServiceName);

/// <summary>
/// 查询服务状态
/// </summary>
HRA_INSTALL_API DWORD WinSrv_QueryStatus(const wchar_t* pszServiceName, SERVICE_STATUS& sStatus);

/// <summary>
/// 查询服务信息
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="sStatus"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD WinSrv_QueryBinaryPathName(const wchar_t* pszServiceName, wchar_t* pszBinaryPathName, size_t nSizeCount);

/// <summary>
/// 查询服务是否存在
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API BOOL WinSrv_Exists(const wchar_t* pszServiceName);

/// <summary>
/// 安装服务
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
HRA_INSTALL_API DWORD WinSrv_Create(const wchar_t* pszServiceName, const wchar_t* pszDisplayName,
                                    const DWORD& dwServiceType, const DWORD& dwStartType,
                                    const wchar_t* pszBinaryPathName, const wchar_t* pszLoadOrderGroup,
                                    const wchar_t* pszDependencies);

/// <summary>
/// 删除服务
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="pWin32ErrorCode"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD WinSrv_Delete(const wchar_t* pszServiceName);

/// <summary>
/// 修改服务配置属性
/// </summary>
/// <param name="pszServiceName"></param>
/// <param name="dwInfoLevel"></param>
/// <param name="lpInfo"></param>
/// <returns></returns>
HRA_INSTALL_API DWORD WinSrv_ChangeConfig(const wchar_t* pszServiceName, DWORD dwInfoLevel, LPVOID lpInfo);

#ifdef __cplusplus
}
#endif