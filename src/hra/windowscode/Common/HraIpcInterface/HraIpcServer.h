#pragma once
#include "HraIpcCommDef.h"
#include "include\AsiEsmIpcCommonDefine.h"
#include "AsiEsmIpcServerPlugin/AsiEsmIpcServerPlugin.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// <summary>
/// 注册回调函数
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <param name="pCmdHandler">回调函数</param>
/// <returns></returns>
HRA_IPC_INTERFACE_API int HraIpcRegistCallbackFun(const char* pszServiceName, int nCmdType, Cmd_Handler pCmdHandler);

/// <summary>
/// 启动监听服务
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <returns></returns>
HRA_IPC_INTERFACE_API int HraIpcStartListenService();

/// <summary>
/// 停止监听服务
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <returns></returns>
HRA_IPC_INTERFACE_API int HraIpcStopListenService();



#ifdef __cplusplus
}
#endif