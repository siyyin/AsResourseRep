#include "AsiEsmIpcClientPlugin/AsiEsmIpcClientPlugin.h"
#include "HraIpcClient.h"

/// <summary>
/// 客户端向服务端发送数据
/// </summary>
/// <param name="pszServiceName">服务名</param>
/// <param name="pData">消息体的数据</param>
/// <param name="nSize">消息体数据长度</param>
/// <returns></returns>
int HraIpcSendMsg(const char* pszIpcName, int nCmdType, const unsigned char* pData, unsigned int nDatLen,
                  unsigned char* pOutData, unsigned int nOutLen)
{
    return SendCmdData(pszIpcName, nCmdType, (const char*)pData, nDatLen, (char*)pOutData, nOutLen);
}