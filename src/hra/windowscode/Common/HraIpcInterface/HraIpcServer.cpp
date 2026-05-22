#include "HraIpcServer.h"

/// <summary>
/// 注册回调函数
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <param name="pCmdHandler">回调函数</param>
/// <returns></returns>
int HraIpcRegistCallbackFun(const char* pszServiceName, int nCmdType, Cmd_Handler pCmdHandler)
{
    int iRet = RPC_ERROR_SUCCESS;
    iRet     = Init_Plugin(pszServiceName);
    if (iRet != RPC_ERROR_SUCCESS)
    {
        return iRet;
    }
    iRet = Register_CallBack_Fun(nCmdType, pCmdHandler);
    return iRet;
}

/// <summary>
/// 启动监听服务
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <returns></returns>
int HraIpcStartListenService()
{
    return Start_Listen_Service();
}

/// <summary>
/// 停止监听服务
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <returns></returns>
int HraIpcStopListenService()
{
    return Stop_Listen_Service();
}