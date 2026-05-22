// AsiEsmIpcClientPlugin.cpp : Defines the exported functions for the DLL application.
//

#include "AsiEsmIpcClientPlugin.h"
#include "AsiEsmIpcPlugin_h.h"
#include <string.h>
#include <iostream>
#include "CommonDefine.h"
#include "..\include\AsiEsmIpcCommonDefine.h"

using namespace std;

string g_sNameHeader = "\\pipe\\";

void __RPC_FAR * __RPC_USER midl_user_allocate( size_t len )
{
  return (malloc(len) );
}
void __RPC_USER midl_user_free( void __RPC_FAR *ptr )
{
  free( ptr );
}

ASIESMIPCCLIENTPLUGINDLL_API int SendCmdData(
      const char* module,
      int iType, 
			const char* params,
			unsigned int paramsLen,
			char* pOutBuf,
			unsigned int iOutBufLen)
{
  int iRet = RPC_ERROR_SUCCESS;
 
  do
  {
    // 参数校验
    if (!module)
    {
      iRet = RPC_ERROR_PARAMETER_NULL;
      break;
    }

    // 定义连接句柄
    RPC_BINDING_HANDLE pRPCServer_IfHandle = NULL;
    // 声明连接名称，用于构建连接对象名称
    //char szConnectServerName[MAX_PATH] = "\\pipe\\";
	char szConnectServerName[MAX_PATH] = {0x0};

    // 构建连接对象名称
    strcat_s(szConnectServerName, module);

    // 建立连接
    unsigned short *pszUuid = NULL;
    wchar_t pszProtocolSequence[] = L"ncalrpc";
    unsigned short *pszNetworkAddress = NULL;
    unsigned short *pszOptions = NULL;
    unsigned short *pszStringBinding = NULL;

    int unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, szConnectServerName, -1, NULL, 0);
    wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
    memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
    ::MultiByteToWideChar(CP_ACP, 0, szConnectServerName, -1, (LPWSTR)pUnicode, unicodeLen);

    RPC_STATUS rpcStatus = RpcStringBindingCompose(pszUuid,
      (unsigned short *)pszProtocolSequence,
      pszNetworkAddress,
      (unsigned short *)pUnicode,
      pszOptions,
      &pszStringBinding);
    if (rpcStatus){
      delete[] pUnicode;
      iRet = RPC_ERROR_RPC_STRING_BINDING_COMPOSE_ERROR;
      break;
    }

    delete[] pUnicode;

    rpcStatus = RpcBindingFromStringBinding(pszStringBinding,
      &pRPCServer_IfHandle);
    if (rpcStatus){
      iRet = RPC_ERROR_RPC_BINGDING_FROM_STRINGBINDING_ERROR;
      break;
    }

    #define BUFFER_LENGTH 1024
    char p[] = "";
    //char szRetMsg[BUFFER_LENGTH] = {0};
	bool bSendSucceed = true;
	error_status_t lRet = 0;
    RpcTryExcept
    {
      if (!params || (paramsLen == 0))
      {
        lRet = Send_Msg(pRPCServer_IfHandle, 
          iType,
          (unsigned char*)p, 
          (int)strlen(p), 
          //(unsigned char*)szRetMsg, 
		  (unsigned char*)pOutBuf,
		  iOutBufLen
          //BUFFER_LENGTH
		  );
      }
      else
      {
        // 发送消息
         lRet = Send_Msg(pRPCServer_IfHandle, 
          iType,
          (unsigned char*)params, 
          (int)paramsLen, 
          //(unsigned char*)szRetMsg,
		  (unsigned char*)pOutBuf,
		  iOutBufLen
          //BUFFER_LENGTH
		  );
      }
    }
    RpcExcept( 1 )
    {
      unsigned long ulCode = RpcExceptionCode();
      bSendSucceed = false;
      char szDebugMsg[1024] = {0};
      _snprintf_s(szDebugMsg, sizeof(szDebugMsg)-1, "AsiEsm Debug Msg Send_Msg exception code: %lu", ulCode);
      OutputDebugStringA(szDebugMsg);
      iRet = RPC_ERROR_RPC_SEND_MSG_EXCEPTION;
    }
    RpcEndExcept
	
    rpcStatus = RpcStringFree(&pszStringBinding);
    if (rpcStatus){
      iRet = RPC_ERROR_RPC_STRING_FREE_ERROR;
      break;
    }

    rpcStatus = RpcBindingFree(&pRPCServer_IfHandle);
    if (rpcStatus){
      // 打印日志
      iRet = RPC_ERROR_RPC_BINDING_FREE_ERROR;
      break;
    }

	// 拷贝返回数据
	if (bSendSucceed)
	{
		iRet = lRet;
	}

  }while(false);

  return iRet;
}

