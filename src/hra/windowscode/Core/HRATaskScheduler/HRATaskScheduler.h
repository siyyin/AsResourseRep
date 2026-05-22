#pragma once
#include <stdint.h>
#include "HRATaskSchedulerDefine.h"

//添加任务线程
HRA_TASKSCHEDULER_EXPORT uint64_t HraTask_AddWorker(const char* pszTaskId, 
                                               int iType, 
                                               int iRqType,
                                               void *(*pProcessFunc) (void *p), 
                                               void *pArg, 
                                               unsigned int ulArgSize,
                                               uint64_t nPreTaskSeq = 0);
//HRA任务线程
HRA_TASKSCHEDULER_EXPORT int HraTask_StartThread();

//HRA初始化
HRA_TASKSCHEDULER_EXPORT int HraTask_Init(const wchar_t* pServiceName);
//HRA释放
HRA_TASKSCHEDULER_EXPORT void HraTask_DeInit();

//取消线程
HRA_TASKSCHEDULER_EXPORT int HraTask_CancelWorker(const char* pszTaskId, int iType, int iRqType);