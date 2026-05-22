#pragma once
#include "utility/comm.h"
#include "HraRpcCommModuleDefine.h"

//监听DSA下发指令线程函数
HRA_RPCCOMM_EXPORT int DsaCmd_StartThread(const char* pszHraIpcName);

//停止线程
//void StopThread_DsaCmd();