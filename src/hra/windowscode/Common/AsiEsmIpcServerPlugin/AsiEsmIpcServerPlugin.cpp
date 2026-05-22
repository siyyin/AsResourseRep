// AsiEsmIpcServerPlugin.cpp : Defines the exported functions for the DLL application.
//
#include "AsiEsmIpcServerPlugin.h"
#include <string.h>
#include <iostream>
#include <map>
#include "AsiEsmIpcPlugin_h.h"
#include "CommonDefine.h"
#include <Shlwapi.h>
#include "..\include\AsiEsmIpcCommonDefine.h"

using namespace std;

// 私有函数声明
DWORD WINAPI RpcServiceThread(LPVOID lpParam);

// 私有资源声明定义
string g_sNameHeader = "\\pipe\\";
string g_sServiceName = "";
map<int, Cmd_Handler> g_cmdHandlerMap;
HANDLE g_ThreadHandle = NULL;
DWORD g_dwThreadId = 0;
RPC_BINDING_VECTOR *g_BindingVector = NULL;

void __RPC_FAR * __RPC_USER midl_user_allocate( size_t len )
{
  return (malloc(len) );
}
void __RPC_USER midl_user_free( void __RPC_FAR *ptr )
{
  free( ptr );
}

int Init_Plugin(_IN const char* pszName)
{
  int iRet = RPC_ERROR_SUCCESS;
  do
  {  
    // 保存监听服务名
    if (!pszName || !strlen(pszName))
    {
      iRet = RPC_ERROR_PARAMETER_NULL;
      break;
    }

    //g_sServiceName = g_sNameHeader + string(pszName);
    g_sServiceName = string(pszName);
  }while(false);
  return iRet;
}

int Register_CallBack_Fun(int iType, Cmd_Handler pCmdHandler)
{
  int iRet = RPC_ERROR_SUCCESS;
  do
  {
    if (g_cmdHandlerMap.find(iType) == g_cmdHandlerMap.end())
    {
      g_cmdHandlerMap.insert(pair<int, Cmd_Handler>(iType, pCmdHandler));
    }
    else
    {
      g_cmdHandlerMap.find(iType)->second = pCmdHandler;
    }
  }while(false);
  return iRet;
}

int Start_Listen_Service(void)
{
  int iRet = RPC_ERROR_SUCCESS;
  do
  {
    LPSECURITY_ATTRIBUTES lpThreadAttributes = NULL;
    SIZE_T dwStackSize = 0;
    LPVOID lpParameter = NULL;
    DWORD dwCreationFlags = 0;
    g_ThreadHandle = CreateThread(
      lpThreadAttributes, 
      dwStackSize, 
      RpcServiceThread, 
      lpParameter, 
      dwCreationFlags, 
      &g_dwThreadId);
    if (g_ThreadHandle == NULL)
    {
      iRet = RPC_ERROR_CREATE_RPC_SERVICE_THREAD_ERROR;
    }
  }while(false);
  return iRet;
}

int Stop_Listen_Service(void)
{
    int iRet = RPC_ERROR_SUCCESS;
    do
    {
        // 停止RPC服务
        if (g_BindingVector != nullptr)
        {
            RPC_STATUS rpcStats = RpcServerUnregisterIf(AsiEsmIpcPlugin_v1_0_s_ifspec, nullptr, TRUE);
            if (RPC_S_OK != rpcStats )
            {
                iRet = RPC_ERROR_RPC_SERVER_UNREGISTERIF_ERROR;
            }
            rpcStats = RpcEpUnregister(AsiEsmIpcPlugin_v1_0_s_ifspec, g_BindingVector, nullptr);
            if (RPC_S_OK != rpcStats)
            {
                iRet = RPC_ERROR_RPC_EP_UNREGISTER_ERROR;
            }
            RpcBindingVectorFree(&g_BindingVector);
            g_BindingVector = nullptr;
        }
    }while(false);
    return iRet;
}

DWORD WINAPI RpcServiceThread(LPVOID lpParam)
{
  int iRet = RPC_ERROR_SUCCESS;
  do
  {
    wchar_t pszProtocolSequence[] = L"ncalrpc";
    unsigned short* pszSecurity = NULL;

    RPC_STATUS rpcStats = RpcServerUseProtseqEp( 
      (unsigned short*)pszProtocolSequence,
      RPC_C_LISTEN_MAX_CALLS_DEFAULT,
      (unsigned short*)StringToUnicode(g_sServiceName.data()).data(),
      pszSecurity);
    if (RPC_S_OK != rpcStats && RPC_S_DUPLICATE_ENDPOINT != rpcStats)
    {
      iRet = RPC_ERROR_RPC_SERVER_USE_PROTSEQEP_ERROR;
      break;
    }

    rpcStats = RpcServerRegisterIf2(
        AsiEsmIpcPlugin_v1_0_s_ifspec,
        nullptr,
        nullptr,
        RPC_IF_AUTOLISTEN | RPC_IF_ALLOW_LOCAL_ONLY,
        RPC_C_LISTEN_MAX_CALLS_DEFAULT,
        0,
        nullptr);
    if (RPC_S_OK != rpcStats){
      iRet = RPC_ERROR_RPC_SERVER_REGISTERIF_ERROR;
      break;
    }

    rpcStats = RpcServerInqBindings(&g_BindingVector);
    if (RPC_S_OK != rpcStats){
        iRet = RPC_ERROR_RPC_NO_BINDINGS_ERROR;
        break;
    }

    rpcStats = RpcEpRegister(
        AsiEsmIpcPlugin_v1_0_s_ifspec,
        g_BindingVector,
        nullptr,
        nullptr);
    if (RPC_S_OK != rpcStats){
        iRet = RPC_ERROR_RPC_EP_REGISTER_ERROR;
        break;
    }
  }while(false);
  return iRet;
}

int Send_Msg( 
    /* [in] */ handle_t IDL_handle,
    /* [in] */ int type,
    /* [size_is][in] */ unsigned char *params,
    /* [in] */ int paramsLen,
    /* [out] */ unsigned char *pOutBuf,
    /* [in] */ int iOutBufLen)
{
  int iRet = RPC_ERROR_SUCCESS;
  do
  {
    // 如果命令有注册回调，则优先使用命令注册的回调
    if (g_cmdHandlerMap.find(type) != g_cmdHandlerMap.end())
    {
      iRet = g_cmdHandlerMap.find(type)->second(type, params, paramsLen, pOutBuf, iOutBufLen);
    }
    // 如果命令没有注册回调，但是有针对所有命令的统一回调，则使用统一回调
    else if (g_cmdHandlerMap.find(HRA_CMD_HANDLE) != g_cmdHandlerMap.end())
    {
      iRet = g_cmdHandlerMap.find(HRA_CMD_HANDLE)->second(type, params, paramsLen, pOutBuf, iOutBufLen);
    }
    // 没有任何注册回调，则不作处理，直接返回
    else
    {
      iRet = RPC_ERROR_CALL_REGISTERED_FUN_ERROR;
    }
  }while(false);

  return iRet;
}

