#pragma once
#include "HraIpcCommDef.h"
#include "include\AsiEsmIpcCommonDefine.h"

#ifdef __cplusplus
extern "C"
{
#endif

/// <summary>
/// 客户端向服务端发送数据
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <param name="pData">消息体的数据</param>
/// <param name="nSize">消息体数据长度</param>
/// <returns></returns>
    HRA_IPC_INTERFACE_API int HraIpcSendMsg(const char* pszIpcName, int nCmdType, const unsigned char* pData,
                                            unsigned int nDatLen, unsigned char* pOutData, unsigned int nOutLen);


#ifdef __cplusplus
}
#endif