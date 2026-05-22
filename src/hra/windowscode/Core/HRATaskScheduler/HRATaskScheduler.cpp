// HRATaskScheduler.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "HRATaskScheduler.h"
#include "utility/RwLock.h"
#include "utility/Logger.h"
#include "utility/HraTaskType.h"
//#include "HRAModuleInterface/HRAModuleInterface.h"
#include "utility/HraCtrlCmd.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraReport.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
//#include "HraIpcInterface/HraIpcCommDef.h"

#include <list>
#include <map>

#define HRA_ADD_TASK_EVENT_NAME L"hra_add_task_event"

/* 宏定义 */
#define HRA_MAX_THREAD_NUM          3//同时启动的线程改此宏定义即可
#define HRA_MAX_WOKER_CNT           (512)/* 工作最大节点数 */

////如果后续有新增任务类型，直接增加type（可以不连续），其他无需修改
const int work_type_list[] =
{
    HRA_ELMT_ASSETS_SCAN_CFG,
    HRA_ELMT_APP_SCAN_CFG,
    HRA_ELMT_OS_SCAN_CFG,
    HRA_ELMT_BASE_LINE_CFG,
    HRA_PATTERN_UPDATE_CMD,
    HRA_ELMT_WP_SACN_CFG,
    HRA_ELMT_HOST_DISCOVERY_CFG,
    HRA_ELMT_VULN_POC_CFG
};
/* 数据结构定义 */
typedef struct _HraTask
{
    void *(*pProcess) (void *pArg);
    void *pArg;
    int iArgSize;
    int iWorkType;
    int iRqType;
    char szTaskId[128];
    uint64_t nThreadID;
    uint64_t nTaskSeq;
    uint64_t nPreTaskSeq;//任务前置依赖
}HraTask;

CDIMutex g_lockTask; //队列读写锁
typedef struct _HraTaskQueue
{
	int m_iHandleCount;
    HANDLE m_hEventHandles[HRA_MAX_THREAD_NUM + 1]; //第一个为添加任务消息句柄，后4个为任务完成句柄
    std::map<HANDLE, HraTask*> m_mapRunTask; //正在运行的任务
    int m_iCurrentSearchIndex;  //当前搜索的类型
    uint64_t m_nCurrentTaskSeq;//当前任务序号，用于任务唯一标识
    std::list<HraTask*> m_listWorkTask; //排队等待的任务
}HraTaskQueue;
HraTaskQueue g_queueTask;//只要是操作g_queueTask，必须加锁

/// <summary>
/// 任务队列信息打印
/// </summary>
void PrintHraTaskQueueInfo()
{
    g_lockTask.Lock();
    char szInfo[1024];
    memset(szInfo, 0, sizeof(szInfo));
    std::string strPrint;
    
    //正在运行的任务
    std::map<int, int> mapRunCount;
    for (std::map<HANDLE, HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
         g_queueTask.m_mapRunTask.end() != it; ++it)
    {
        if (mapRunCount.end() == mapRunCount.find(it->second->iWorkType))
        {
            mapRunCount.insert(std::map<int, int>::value_type(it->second->iWorkType, 1));
        }
        else
        {
            mapRunCount[it->second->iWorkType] += 1;
        }
    }
    strPrint = "Running tasks: [";
    for (std::map<int, int>::const_iterator it_count = mapRunCount.begin();
         mapRunCount.end() != it_count; ++it_count)
    {
        if (it_count != mapRunCount.begin())
        {
            strPrint += ", ";
        }
        _snprintf_s(szInfo, sizeof(szInfo), "%d:%d", it_count->first, it_count->second);
        strPrint += szInfo;
    }
    strPrint += "], ";

    //等待的任务
    std::map<int, int> mapWaitCount;
    for (std::list<HraTask*>::const_iterator it = g_queueTask.m_listWorkTask.begin();
         g_queueTask.m_listWorkTask.end() != it; ++it)
    {
        if (mapWaitCount.end() == mapWaitCount.find((*it)->iWorkType))
        {
            mapWaitCount.insert(std::map<int, int>::value_type((*it)->iWorkType, 1));
        }
        else
        {
            mapWaitCount[(*it)->iWorkType] += 1;
        }
    }
    strPrint += "Waitting tasks: [";
    for (std::map<int, int>::const_iterator it_count = mapWaitCount.begin();
         mapWaitCount.end() != it_count; ++it_count)
    {
        if (it_count != mapWaitCount.begin())
        {
            strPrint += ", ";
        }
        _snprintf_s(szInfo, sizeof(szInfo), "%d:%d", it_count->first, it_count->second);
        strPrint += szInfo;
    }
    strPrint += "]";
    g_lockTask.UnLock();
    LOG_INFO(strPrint.c_str());
}

int HraTask_Init(const wchar_t* pServiceName)
{
    if (!pServiceName || wcslen(pServiceName) <= 0)
    {
        LOG_ERROR("HraTask_Init failed! pServiceName empty!");
        return HRA_BAD_PARAM;
    }

    g_lockTask.Lock();
    wchar_t szEvent[MAX_PATH];
    _snwprintf_s(szEvent, MAX_PATH, L"%ls_%ls", HRA_ADD_TASK_EVENT_NAME, pServiceName);
	g_queueTask.m_iHandleCount = 0;
    g_queueTask.m_hEventHandles[0] = ::CreateEvent(NULL, FALSE, FALSE, szEvent);
	if (!g_queueTask.m_hEventHandles[0])
	{
		g_lockTask.UnLock();
		LOG_ERROR("HraTask_Init failed!");
		return HRA_FAILED;
	}
    g_queueTask.m_iHandleCount = 1;
    g_queueTask.m_iCurrentSearchIndex = -1;
    g_queueTask.m_nCurrentTaskSeq     = 0;
    g_lockTask.UnLock();
    LOG_INFO("HraTask_Init finished!");
    return HRA_OK;
}

void HraTask_DeInit()
{
    g_lockTask.Lock();
	if (g_queueTask.m_hEventHandles[0] != NULL)
	{
		::CloseHandle(g_queueTask.m_hEventHandles[0]);
		g_queueTask.m_hEventHandles[0] = NULL;
	}

	for (std::map<HANDLE,HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
		it != g_queueTask.m_mapRunTask.end(); ++it)
    {
		HraTask* pTaskTmp = it->second;
		if (pTaskTmp != NULL)
		{
			if (pTaskTmp->pArg != NULL)
			{
				free(pTaskTmp->pArg);
				pTaskTmp->pArg = NULL;
			}
			free(pTaskTmp);
			pTaskTmp = NULL;
		}
	}
	g_queueTask.m_mapRunTask.clear();

	for (std::list<HraTask*>::const_iterator it = g_queueTask.m_listWorkTask.begin();
		it != g_queueTask.m_listWorkTask.end(); ++it)
    {
		HraTask* pTaskTmp = *it;
		if (pTaskTmp != NULL)
		{
			if (pTaskTmp->pArg != NULL)
			{
				free(pTaskTmp->pArg);
				pTaskTmp->pArg = NULL;
			}
			free(pTaskTmp);
			pTaskTmp = NULL;
		}
	}
	g_queueTask.m_listWorkTask.clear();

    g_lockTask.UnLock();
    LOG_INFO("HraTask_DeInit finished!");
}

//开启单个任务线程
HANDLE StartTask(HraTask* pTask)
{
	if (pTask == NULL)
	{
		return NULL;
	}

    //如果有命令在队列中则删除
    //int iCmd = HraCtrlCmd::getInstance()->popCmd(pTask->szTaskId, pTask->iWorkType, pTask->iRqType);

	DWORD dwThreadID = 0;
    HANDLE hHandle = ::CreateThread(NULL,
        0,
        (LPTHREAD_START_ROUTINE)pTask->pProcess,
        pTask->pArg,
        0,
        &dwThreadID);
    if (NULL == hHandle)
    {
        LOG_ERROR("Start task thread error! type(%d)", pTask->iWorkType);
		return NULL;
    }
    pTask->nThreadID = dwThreadID;
    LOG_INFO("Start task! type:%d, threadid:%llu", pTask->iWorkType, pTask->nThreadID);
	return hHandle;
}

/// <summary>
/// 是否存在对应TaskSeq的任务
/// 不加锁
/// </summary>
/// <param name="nTaskSeq"></param>
/// <returns></returns>
bool IsExistsTask_NoLock(uint64_t nTaskSeq)
{
    for (std::map<HANDLE, HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
         g_queueTask.m_mapRunTask.end() != it; ++it)
    {
        if (it->second->nTaskSeq == nTaskSeq)
        {
            return true;
        }
    }

    for (std::list<HraTask*>::const_iterator it = g_queueTask.m_listWorkTask.begin();
         it != g_queueTask.m_listWorkTask.end(); ++it)
    {
        if ((*it)->nTaskSeq == nTaskSeq)
        {
            return true;
        }
    }

    return false;
}

//开启空闲任务类型的任务
void StartTasks()
{
    g_lockTask.Lock();
    for (int i = 0; i < sizeof(work_type_list)/sizeof(int); ++i)
    {
        //只允许有3种类型任务同时在跑，满队列则直接返回
        if (g_queueTask.m_mapRunTask.size() >= HRA_MAX_THREAD_NUM)
        {
            g_lockTask.UnLock();
            return;
        }

        g_queueTask.m_iCurrentSearchIndex++;
        if (g_queueTask.m_iCurrentSearchIndex >= (sizeof(work_type_list) / sizeof(int)))
        {
            g_queueTask.m_iCurrentSearchIndex = 0;
        }

        //判断是否有正在运行的此类型
        bool bRun = false;
        for (std::map<HANDLE, HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
             g_queueTask.m_mapRunTask.end() != it; ++it)
        {
            if (it->second->iWorkType == work_type_list[g_queueTask.m_iCurrentSearchIndex])
            {
                bRun = true;
                break;
            }
        }

        if (bRun)
        {
            continue;
        }

        //没有此类型任务在跑，在等待队列中寻找此类型任务
        HraTask* pTaskRun = NULL;
        int iType = work_type_list[g_queueTask.m_iCurrentSearchIndex];
        for (std::list<HraTask*>::const_iterator it = g_queueTask.m_listWorkTask.begin();
             it != g_queueTask.m_listWorkTask.end(); ++it)
        {
            HraTask* pTaskTmp = *it;
            if (pTaskTmp->iWorkType != iType)
            {
                continue;
            }

            //大于0，则表示有前置任务，判断前置任务是否完成运行
            if (pTaskTmp->nPreTaskSeq > 0 && IsExistsTask_NoLock(pTaskTmp->nPreTaskSeq))
            {
                //用break，此类型任务后续任务不在查找，按顺序执行;
                //用continue，后续同类型没有前置依赖的任务将先执行；
                break;
            }

            pTaskRun = pTaskTmp;
            //找到了，从队列里面移除
            g_queueTask.m_listWorkTask.erase(it);
            break;
        }

        //没有此类型任务，继续找下一类型
        if (pTaskRun == NULL)
        {
            continue;
        }

        HANDLE handleTask = StartTask(pTaskRun);
        //启动线程失败，删除任务内存信息
        if (handleTask == NULL)
        {
            if (pTaskRun != NULL)
            {
                if (pTaskRun->pArg != NULL)
                {
                    free(pTaskRun->pArg);
                    pTaskRun->pArg = NULL;
                }
                free(pTaskRun);
                pTaskRun = NULL;
            }
            continue;
        }
        //启动线程成功，将任务添加到正在运行的任务队列
        g_queueTask.m_mapRunTask.insert(std::map<HANDLE, HraTask*>::value_type(handleTask, pTaskRun));
    }
    g_lockTask.UnLock();
    PrintHraTaskQueueInfo();
}

void ManageHandles()
{
	g_lockTask.Lock();
	g_queueTask.m_iHandleCount = 1;//0号位置不处理，为添加句柄
	for (std::map<HANDLE,HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
		it != g_queueTask.m_mapRunTask.end(); ++it)
    {
		if (g_queueTask.m_iHandleCount > HRA_MAX_THREAD_NUM)
		{
			LOG_ERROR("More task is running!");
			break;
		}
		g_queueTask.m_hEventHandles[g_queueTask.m_iHandleCount] = it->first;
		g_queueTask.m_iHandleCount++;
	}
	g_lockTask.UnLock();
}

void FinishTask(int iIndex)
{
    g_lockTask.Lock();
    HANDLE hTmpTask = NULL;
    HraTask* pTmpTask = NULL;
    int i = 0;
    for (std::map<HANDLE,HraTask*>::const_iterator it = g_queueTask.m_mapRunTask.begin();
		it != g_queueTask.m_mapRunTask.end(); ++it)
    {
        if (i != iIndex)
        {
            ++i;
            continue;
        }

        hTmpTask = it->first;
        pTmpTask = it->second;
        g_queueTask.m_mapRunTask.erase(it);
        break;
    }

    //如果有命令在队列中则删除
    if (pTmpTask != NULL)
    {
        int iCmd = HraCtrlCmd::getInstance()->popCmd(pTmpTask->nThreadID);
    }
    if (g_queueTask.m_mapRunTask.empty())
    {
        HraCtrlCmd::getInstance()->clear();
    }

    if (hTmpTask != NULL)
    {
        ::CloseHandle(hTmpTask);
        hTmpTask = NULL;
    }

    if (pTmpTask != NULL)
    {
        if (pTmpTask->pArg != NULL)
        {
            free(pTmpTask->pArg);
            pTmpTask->pArg = NULL;
        }
        free(pTmpTask);
        pTmpTask = NULL;
    }
    g_lockTask.UnLock();
}

int HraTask_ThreadFun(void* lpParam)
{
    //HraTask_Init();
    while (true)
    {
        ManageHandles();
        LOG_INFO("WaitForMultipleObjects handle count:%d, handle:%u",g_queueTask.m_iHandleCount, (unsigned int)(g_queueTask.m_hEventHandles));
		DWORD dwRet = ::WaitForMultipleObjects(g_queueTask.m_iHandleCount, 
												g_queueTask.m_hEventHandles, 
												FALSE, 
												INFINITE);
        if (dwRet == WAIT_OBJECT_0)
        {
            LOG_INFO("Receive task add event!");
            StartTasks();
        }
        else if (dwRet > WAIT_OBJECT_0 && dwRet <= (WAIT_OBJECT_0 + HRA_MAX_THREAD_NUM))
        {
            LOG_INFO("Receive Task finish event!");
            FinishTask(dwRet-1);
            StartTasks();
        }
        else
        {
            LOG_ERROR("Receive error event! ret:%lu, err:%lu", dwRet, GetLastError());
        }        
    }
    //HraTask_DeInit();//这里执行不到，只是放在这里以备后用
    return HRA_OK;
}

//HRA任务线程
int HraTask_StartThread()
{
    DWORD dwThreadID = 0;
    HANDLE hHandle = ::CreateThread(NULL,
        0,
        (LPTHREAD_START_ROUTINE)HraTask_ThreadFun,
        NULL,
        0,
        &dwThreadID);
    if (NULL == hHandle)
    {
        LOG_ERROR("HRA task thread start failed!");
        return HRA_FAILED;
    }
    LOG_INFO("HRA task thread started!");
    return HRA_OK;
}

void SetAddTaskEvent()
{
    if (g_queueTask.m_hEventHandles[0] == NULL)
    {
        return;
    }

    if (FALSE == ::SetEvent(g_queueTask.m_hEventHandles[0]))
    {
        LOG_ERROR("SetEvent(add task) error!");
        ::CloseHandle(g_queueTask.m_hEventHandles[0]);
        g_queueTask.m_hEventHandles[0] = NULL;
    }


    /*
    HANDLE hAddMsg = ::OpenEvent(EVENT_ALL_ACCESS, FALSE, HRA_ADD_TASK_EVENT_NAME);
    if (!hAddMsg)
    {
        LOG_ERROR("OpenEvent(add task) error!");
        return;
    }

    if (FALSE == ::SetEvent(hAddMsg))
    {
        LOG_ERROR("SetEvent(add task) error!");
        ::CloseHandle(hAddMsg);
        return;
    }
    ::CloseHandle(hAddMsg);
    */
}

uint64_t HraTask_AddWorker(const char* pszTaskId, int iType, int iRqType, void* (*pProcessFunc)(void* p), void* pArg,
                           unsigned int ulArgSize, uint64_t nPreTaskSeq)
{
    //int ret = HRA_OK;
    uint64_t nTaskSeqRet = 0;
    HraTask* pNewTask = NULL;

    bool bFind = false;
    for (int i = 0; i < sizeof(work_type_list)/sizeof(int); ++i)
    {
        if (iType == work_type_list[i])
        {
            bFind = true;
            break;
        }
    }
    if (!bFind)
    {
        LOG_ERROR("Work type:%d not found!", iType);
        //ret = HRA_BAD_PARAM;
        goto _error_return_;
    }

    if ((ulArgSize > 0 && pArg == NULL)
        || (ulArgSize <= 0 && pArg != NULL))
    {
        LOG_ERROR("Param error!");
        //ret = HRA_BAD_PARAM;
        goto _error_return_;
    }

    g_lockTask.Lock();
    if (g_queueTask.m_listWorkTask.size() >= HRA_MAX_WOKER_CNT)
    {
        g_lockTask.UnLock();
        LOG_ERROR("WorkTask full!");
        //ret = HRA_FULL;
        goto _error_return_;
    }

    pNewTask = (HraTask*)malloc(sizeof(HraTask));
    if (!pNewTask)
    {
        g_lockTask.UnLock();
        LOG_ERROR("malloc failed!");
        //ret = HRA_MALLOC_FAIL;
        goto _error_return_;
    }
    memset(pNewTask, 0, sizeof(HraTask));
    _snprintf_s(pNewTask->szTaskId, sizeof(pNewTask->szTaskId), "%s", pszTaskId);
    pNewTask->iWorkType = iType;
    pNewTask->iRqType = iRqType;
    pNewTask->pProcess = pProcessFunc;
    pNewTask->iArgSize = ulArgSize;
    // unsigned long long最大值18446744073709551615，以每天1万条任务计算，可以使用5,053,902,485,947年，所以不用从0循环；
    ++g_queueTask.m_nCurrentTaskSeq;
    pNewTask->nTaskSeq = g_queueTask.m_nCurrentTaskSeq;
    pNewTask->nPreTaskSeq = nPreTaskSeq;
    if (ulArgSize > 0)
    {
        pNewTask->pArg = (void*)malloc(ulArgSize);
        if (!pNewTask->pArg)
        {
            g_lockTask.UnLock();
            LOG_ERROR("malloc failed!");
            //ret = HRA_MALLOC_FAIL;
            goto _error_return_;
        }
        memcpy(pNewTask->pArg, pArg, ulArgSize);
    }
    //加入队列末尾
    g_queueTask.m_listWorkTask.push_back(pNewTask);
    nTaskSeqRet = g_queueTask.m_nCurrentTaskSeq;
    g_lockTask.UnLock();

    LOG_INFO("Add new task! type:%d, RqType:%d, task_seq:%llu", iType, iRqType, nTaskSeqRet);
    PrintHraTaskQueueInfo();
    SetAddTaskEvent();
    return nTaskSeqRet;

_error_return_:
    if (pNewTask != NULL)
    {
        if (pNewTask->pArg != NULL)
        {
            free(pNewTask->pArg);
            pNewTask->pArg = NULL;
        }
        free(pNewTask);
        pNewTask = NULL;
    }
    return nTaskSeqRet;
}

/// <summary>
/// 取消任务
/// 注意：取消任务命令本身管理端不需要返回结果，只需要返回扫描任务的成功、失败结果即可
/// </summary>
/// <param name="iType"></param>
/// <param name="iRqType"></param>
/// <returns></returns>
int HraTask_CancelWorker(const char* pszTaskId, int iType, int iRqType)
{
    LOG_INFO("CancelWorker start! work_type:%d, rq_type:%d", iType, iRqType);
    //删除排队的任务
    g_lockTask.Lock();
    //int iDeleteCount = 0;
    std::vector<std::string> vctDelTaskIds;
    std::list<HraTask*>::const_iterator it = g_queueTask.m_listWorkTask.begin();
    while (g_queueTask.m_listWorkTask.end() != it)
    {
        HraTask* pTaskTmp = *it;
        if ((pTaskTmp != NULL) &&
            (pTaskTmp->iWorkType != iType || pTaskTmp->iRqType != iRqType || strcmp(pTaskTmp->szTaskId, pszTaskId) != 0))
        {
            ++it;
            continue;
        }

        if (pTaskTmp != NULL)
        {
            vctDelTaskIds.push_back(pTaskTmp->szTaskId);
            LOG_INFO("Delete task! type:%d, rq_type:%d, task_id:%s", iType, iRqType, pTaskTmp->szTaskId);
        }

        it = g_queueTask.m_listWorkTask.erase(it);
        //lstFree.push_back(pTaskTmp);
        if (pTaskTmp != NULL)
        {
            if (pTaskTmp->pArg != NULL)
            {
                free(pTaskTmp->pArg);
                pTaskTmp->pArg = NULL;
            }
            free(pTaskTmp);
            pTaskTmp = NULL;
        }
    }

    //寻找是否有正在运行的任务
    for (std::map<HANDLE, HraTask*>::const_iterator itRun = g_queueTask.m_mapRunTask.begin();
         g_queueTask.m_mapRunTask.end() != itRun; ++itRun)
    {
        if (itRun->second->iWorkType != iType || itRun->second->iRqType != iRqType ||
            strcmp(itRun->second->szTaskId, pszTaskId) != 0)
        {
            ++itRun;
            continue;
        }

        //有正在跑的任务，插入取消命令
        HraCtrlCmd::getInstance()->pushCmd(itRun->second->nThreadID, HraCtrlCmd::CmdDef::cmd_cancel);
    }
    g_lockTask.UnLock();

    //上报被删除的任务结果
    RspMsgType emCmdType;
    if (iType == HRA_ELMT_ASSETS_SCAN_CFG)
    {
        emCmdType = ASSET_SCAN_RESULT;
    }
    else if (iType == HRA_ELMT_APP_SCAN_CFG)
    {
        emCmdType = APP_SCAN_RESULT;
    }
    else if (iType == HRA_ELMT_OS_SCAN_CFG)
    {
        emCmdType = OS_SCAN_RESULT;
    }
    else if (iType == HRA_ELMT_BASE_LINE_CFG)
    {
        emCmdType = BASELINE_RESULT;
    }
    else if (iType == HRA_ELMT_WP_SACN_CFG)
    {
        emCmdType = DOLPHIN_RESULT;
    }
    else
    {
        LOG_INFO("Work type error! work_type:%d, rq_type:%d", iType, iRqType);
        return HRA_BAD_PARAM;
    }

    LOG_INFO("CancelWorker end! work_type:%d, rq_type:%d", iType, iRqType);

    //删除了几条任务就上报几次
    HraMsgHead::MsgType emMsgType = HraMsgHead::MsgType::FEATURE_RESULT;
    for (std::vector<std::string>::const_iterator it = vctDelTaskIds.begin(); vctDelTaskIds.end() != it; ++it)
    {
        std::string strResult = GetReportResultInfo(it->c_str(),HRA_USER_CANCEL, "", LOG_LEVEL_INFO);
        CReportInfo cReportBaseLineInfo;
        cReportBaseLineInfo.SetCompress(NEED_COMPRESSION);
        cReportBaseLineInfo.Request(emMsgType, emCmdType, strResult.c_str(), strResult.length());
    }

    return HRA_OK;
}
