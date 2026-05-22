#include "DIAssetTask.h"
#include <Windows.h>
#include "LogManager.h"
#include "StringUtils.h"
#include "DIUtils.h"

#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "Mstask.lib")

#define TASKS_TO_RETRIEVE          5
extern BOOL g_IsWinXP;
bool g_IsInitInstanceXP = false;
ITaskScheduler *g_pITS = NULL;

namespace di_rest_client
{
  std::map<std::string, DIAssetTaskItem> g_map_tasks_table;
  DIAssetTask::DIAssetTask(void)
  {
  }


  DIAssetTask::~DIAssetTask(void)
  {
    g_map_tasks_table.clear();
  }

  bool DIAssetTask::InitTasksList(void)
  {
    if (g_IsWinXP){
      return InitTasksListXP();
    }
    g_map_tasks_table.clear();
    //  Initialize COM.
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::InitTasksList: CoInitializeEx failed: %x", hr);
      return false;
    }

    //  Create an instance of the Task Service. 
    ITaskService *pService = NULL;
    hr = CoCreateInstance(CLSID_TaskScheduler,
      NULL,
      CLSCTX_INPROC_SERVER,
      IID_ITaskService,
      (void**)&pService);  
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::InitTasksList: Failed to CoCreate an instance of the TaskService class: %x", hr);
      CoUninitialize();
      return false;
    }

    //  Connect to the task service.
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::InitTasksList:ITaskService:: Connect failed: %x", hr);
      pService->Release();
      CoUninitialize();
      return false;
    }

    //  Get the pointer to the root task folder.
    ITaskFolder *pRootFolder = NULL;
    hr = pService->GetFolder( _bstr_t( L"\\") , &pRootFolder);
    pService->Release();
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::InitTasksList: Cannot get Root Folder pointer: %x", hr);
      CoUninitialize();
      return false;
    }

    try {
      EnumSubFolders(pRootFolder);
      pRootFolder->Release();
    }
    catch (const std::exception& e) {
      DI_LOG_ERROR("DIAssetTask: EnumSubFolders failed, %s", e.what());
    }

    CoUninitialize();
    return true;
  }

  void DIAssetTask::EnumSubFolders(ITaskFolder *pTaskFolder)
  {
    ITaskFolderCollection* pSubFolders = NULL;
    BSTR folderName = NULL;
    HRESULT hr = pTaskFolder->get_Name(&folderName);
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::EnumSubFolders: get_Name() error: %x", hr);
      return;
    }

    SysFreeString(folderName);

    GetTaskItemByFolder(pTaskFolder);   // 获取当前目录的任务

    hr = pTaskFolder->GetFolders(0, &pSubFolders);
    if (FAILED(hr)){
      DI_LOG_DEBUG("DIAssetTask::EnumSubFolders: GetFolders error: %x", hr);
      return;
    }

    LONG lCount = 0;
    hr = pSubFolders->get_Count(&lCount);
    if (FAILED(hr)){
      pSubFolders->Release();
      DI_LOG_DEBUG("DIAssetTask::EnumSubFolders: get_Count error: %x", hr);
      return;
    }

    if (lCount >= 1)   // 如果存在子目录，则递归调用
    {
      for (int i=1; i <= lCount; i++)
      {
        ITaskFolder *pSubFolder = NULL;
        hr = pSubFolders->get_Item((_variant_t)i, &pSubFolder);
        if (FAILED(hr)){
          DI_LOG_ERROR("DIAssetTask::EnumSubFolders: get_Item error: %x", hr);
          continue;
        }

        EnumSubFolders(pSubFolder);   // 递归调用
        pSubFolder->Release();
      }
    }

    pSubFolders->Release();
  }

  bool DIAssetTask::InitInstance(void)
  {
    HRESULT hr = S_OK;
    if (!g_IsInitInstanceXP){
      hr = CoInitialize(NULL);
      if (FAILED(hr)){
        DI_LOG_ERROR("DIAssetTask::InitTasksListXP: CoInitialize failed: %x", hr);
        return false;
      }

      hr = CoCreateInstance(CLSID_CTaskScheduler,
        NULL,
        CLSCTX_INPROC_SERVER,
        IID_ITaskScheduler,
        (void **) &g_pITS);  
      if (FAILED(hr)){
        DI_LOG_ERROR("DIAssetTask::InitTasksListXP: Failed to CoCreate an instance of the ITaskScheduler class: %x", hr);
        CoUninitialize();
        return false;
      }

      g_IsInitInstanceXP = true;

      return true;
    }

    return false;
  }
    
  void DIAssetTask::UnInitInstance(void)
  {
    g_pITS->Release();
    CoUninitialize();
    g_IsInitInstanceXP = false;
  }

  bool DIAssetTask::InitTasksListXP(void)
  {
    g_map_tasks_table.clear();
    HRESULT hr = S_OK;
    if (!g_IsInitInstanceXP){
      if (!InitInstance())
        return false;
    }

    IEnumWorkItems *pIEnum;
    hr = g_pITS->Enum(&pIEnum);
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::InitTasksListXP: Failed to Enum IEnumWorkItems: %x", hr);
      CoUninitialize();
      return false;
    }

    LPWSTR *lpwszNames;
    DWORD dwFetchedTasks = 0;
    while (SUCCEEDED(pIEnum->Next(TASKS_TO_RETRIEVE, &lpwszNames, &dwFetchedTasks)) && (dwFetchedTasks != 0))
    {
      while (dwFetchedTasks)
      {
        DIAssetTaskItem task_Value_item;
        task_Value_item.strTaskName = "--";
        task_Value_item.strTaskState = "--";

        task_Value_item.strEnabled = "0"; 
        task_Value_item.strType = "--";
        task_Value_item.strStartBoundary = "--";
        task_Value_item.strID = "--";
        task_Value_item.strEndBoundary = "--";
        task_Value_item.strExecutionTimeLimit = "--";
        task_Value_item.strDetailMsg = "--";

        task_Value_item.strTaskCreator = "--";
        task_Value_item.strExcuteCycle = "--";
        task_Value_item.strTaskStartProcessCmd = "--";
        task_Value_item.strTaskNextRunTime = "--";
        task_Value_item.strTaskLastRunTime = "--";
        task_Value_item.strTaskLastRunResult = "--";
        task_Value_item.strTaskCreateTime = "--";  

        ITask *pITask;
        hr = g_pITS->Activate(lpwszNames[--dwFetchedTasks],
          IID_ITask,
          (IUnknown**) &pITask);
        
        if (FAILED(hr)){
          DI_LOG_ERROR("DIAssetTask::InitTasksListXP: Failed to Activate pITask: %x", hr);
          pIEnum->Release();
          CoUninitialize();
          return false;
        }
        // 任务计划名称
        task_Value_item.strTaskName = UnicodeToUtf8String(lpwszNames[dwFetchedTasks]);

        // 计划任务状态
        HRESULT phrStatus;
        hr = pITask->GetStatus(&phrStatus);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetStatus phrStatus: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }

        switch (phrStatus)
        {
        case SCHED_S_TASK_READY: 
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_READY");       // 参考宏定义说明
          break;
        case SCHED_S_TASK_RUNNING: 
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_RUNNING"); 
          break;
        case SCHED_S_TASK_DISABLED:
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_DISABLED"); 
          break;
        case SCHED_S_TASK_HAS_NOT_RUN:
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_HAS_NOT_RUN"); 
          break;
        case SCHED_S_TASK_NOT_SCHEDULED:
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_NOT_SCHEDULED"); 
          break;
        case SCHED_S_TASK_NO_MORE_RUNS:
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_NO_MORE_RUNS");  
          break;
        case SCHED_S_TASK_NO_VALID_TRIGGERS:
          task_Value_item.strTaskState = ansi_to_utf8("SCHED_S_TASK_NO_VALID_TRIGGERS"); 
          break;
        default:
          break;
        }

        // 计划任务下次启动时间
        SYSTEMTIME pstNextRun;
        hr = pITask->GetNextRunTime(&pstNextRun);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetNextRunTime pstNextRun: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        task_Value_item.strTaskNextRunTime = ansi_to_utf8(systemTime2Str(pstNextRun).data());

        // 计划任务上次启动时间
        SYSTEMTIME pstLastRun;
        hr = pITask->GetMostRecentRunTime(&pstLastRun);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetMostRecentRunTime pstLastRun: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        task_Value_item.strTaskLastRunTime = ansi_to_utf8(systemTime2Str(pstLastRun).data());

        // 获取上次运行结果
        DWORD pdwExitCode;
        hr = pITask->GetExitCode(&pdwExitCode);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetExitCode pdwExitCode: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        if (SUCCEEDED(hr)){
          LPVOID lpMsgBuf = NULL;
          FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            pdwExitCode,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL );
          if (lpMsgBuf){
            task_Value_item.strTaskLastRunResult = UnicodeToUtf8String((LPTSTR)lpMsgBuf);
            if (task_Value_item.strTaskLastRunResult.find("\r\n") != std::string::npos)
              task_Value_item.strTaskLastRunResult =task_Value_item.strTaskLastRunResult.substr(0, task_Value_item.strTaskLastRunResult.find("\r\n"));
            LocalFree(lpMsgBuf);
          }
        }

        // 获取任务的创建者
        LPWSTR ppwszCreator;
        hr = pITask->GetCreator(&ppwszCreator);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetCreator ppwszCreator: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        task_Value_item.strTaskCreator = UnicodeToUtf8String(ppwszCreator);

        // 计划任务创建时间
        // XP下没有该字段

        // 获取工作目录，进程名，命令行参数, 组合获取命令行参数
        LPWSTR lpwszWorkDir;
        hr = pITask->GetWorkingDirectory(&lpwszWorkDir);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetWorkingDirectory lpwszWorkDir: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        LPWSTR lpwszApplicationName;
        hr = pITask->GetApplicationName(&lpwszApplicationName);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetApplicationName lpwszApplicationName: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        LPWSTR lpwszParameters;
        hr = pITask->GetParameters(&lpwszParameters);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetParameters lpwszParameters: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        task_Value_item.strTaskStartProcessCmd = UnicodeToUtf8String(lpwszParameters);

        // 解析触发器
        WORD plTriggerCount;
        hr = pITask->GetTriggerCount(&plTriggerCount);
        if (FAILED(hr)){
          DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetTriggerCount plTriggerCount: %x", hr);
          pIEnum->Release();
          pITask->Release();
          CoUninitialize();
          return false;
        }
        WORD CurrentTrigger = 0;
        if (plTriggerCount == 0){       // 个数为0特殊处理
          std::string strKey = task_Value_item.strTaskName +  ":" +  
                        task_Value_item.strID +  ":" + 
                        task_Value_item.strType +  ":" + 
                        task_Value_item.strEnabled +  ":" + 
                        task_Value_item.strDetailMsg; 
          if (g_map_tasks_table.find(strKey) == g_map_tasks_table.end())
            g_map_tasks_table.insert(make_pair(strKey, task_Value_item)); 
        }
        else{
          for (CurrentTrigger=0; CurrentTrigger<plTriggerCount; CurrentTrigger++)
          {  
            ITaskTrigger* pTaskTrigger;
            hr = pITask->GetTrigger(CurrentTrigger, &pTaskTrigger);
            if (FAILED(hr)){
              DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to CurrentTrigger pTaskTrigger: %x", hr);
              pIEnum->Release();
              pITask->Release();
              CoUninitialize();
              return false;
            }
            TASK_TRIGGER task_Trigger;
            task_Trigger.cbTriggerSize = sizeof(TASK_TRIGGER);
            hr = pTaskTrigger->GetTrigger(&task_Trigger);
            if (FAILED(hr)){
              DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetTrigger pTask_Trigger: %x", hr);
              pIEnum->Release();
              pTaskTrigger->Release();
              pITask->Release();
              CoUninitialize();
              return false;
            }
            switch (task_Trigger.TriggerType)    // 触发器类型
            {
            case 0:
              task_Value_item.strType = ansi_to_utf8("TASK_TIME_TRIGGER_ONCE");
              break;
            case 1:
              task_Value_item.strType = ansi_to_utf8("TASK_TIME_TRIGGER_DAILY");
              break;
            case 2:
              task_Value_item.strType = ansi_to_utf8("TASK_TIME_TRIGGER_WEEKLY");
              break;
            case 3:
              task_Value_item.strType = ansi_to_utf8("TASK_TIME_TRIGGER_MONTHLYDATE");
              break;
            case 4:
              task_Value_item.strType = ansi_to_utf8("TASK_TIME_TRIGGER_MONTHLYDOW");
              break;
            case 5:
              task_Value_item.strType = ansi_to_utf8("TASK_EVENT_TRIGGER_ON_IDLE");
              break;
            case 6:
              task_Value_item.strType = ansi_to_utf8("TASK_EVENT_TRIGGER_AT_SYSTEMSTART");
              break;
            case 7:
              task_Value_item.strType = ansi_to_utf8("TASK_EVENT_TRIGGER_AT_LOGON");
              break;
            default:
              break;
            }

            LPWSTR ppwszTrigger;
            hr = pTaskTrigger->GetTriggerString(&ppwszTrigger);
            if (FAILED(hr)){
              DI_LOG_DEBUG("DIAssetTask::InitTasksListXP: Failed to GetTriggerString ppwszTrigger: %x", hr);
              pIEnum->Release();
              pTaskTrigger->Release();
              pITask->Release();
              CoUninitialize();
              return false;
            }
            task_Value_item.strDetailMsg = UnicodeToUtf8String(ppwszTrigger);
            task_Value_item.strEnabled = "1";
            CoTaskMemFree(ppwszTrigger);

            pTaskTrigger->Release();

            std::string strKey = task_Value_item.strTaskName +  ":" +  
                        task_Value_item.strID +  ":" + 
                        task_Value_item.strType +  ":" + 
                        task_Value_item.strEnabled +  ":" + 
                        task_Value_item.strDetailMsg; 
            if (g_map_tasks_table.find(strKey) == g_map_tasks_table.end())
              g_map_tasks_table.insert(make_pair(strKey, task_Value_item)); 
          }
        }

        pITask->Release();
        CoTaskMemFree(lpwszNames[dwFetchedTasks]);
        Sleep(1);
      }
      CoTaskMemFree(lpwszNames);
    }

    pIEnum->Release();
    return S_OK;
  }

  std::map<std::string, DIAssetTaskItem>& DIAssetTask::GetTasksList(void)
  {
    return g_map_tasks_table;
  }

  void DIAssetTask::GetTaskItemByFolder(ITaskFolder *pTaskFolder)
  {
    //  Get the registered tasks in the folder.
    IRegisteredTaskCollection* pTaskCollection = NULL;
    BSTR folderName = NULL;
    HRESULT hr = pTaskFolder->get_Name(&folderName);
    if (FAILED(hr)){
      DI_LOG_ERROR("DIAssetTask::EnumSubFolders: get_Name() error: %x", hr);
    }

    hr = pTaskFolder->GetTasks(NULL, &pTaskCollection);
    if (FAILED(hr)){
      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Folder_Name is %s, GetTasks() error.: %x", UnicodeToString(folderName).data(),hr);
      return;
    }

    LONG numTasks = 0;
    hr = pTaskCollection->get_Count(&numTasks);
    if (numTasks == 0){
      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Folder_Name is %s, get_Count() error.: %x", UnicodeToString(folderName).data(), hr);
      pTaskCollection->Release();
      return;
    }

    SysFreeString(folderName);

    for (LONG i=0; i < numTasks; i++)
    {
      IRegisteredTask* pRegisteredTask = NULL;
      hr = pTaskCollection->get_Item( _variant_t(i+1), &pRegisteredTask );
      DIAssetTaskItem task_Value_item;
      task_Value_item.strTaskName = "--";
      task_Value_item.strTaskState = "--";

      task_Value_item.strEnabled = "0"; 
      task_Value_item.strType = "--";
      task_Value_item.strStartBoundary = "--";
      task_Value_item.strID = "--";
      task_Value_item.strEndBoundary = "--";
      task_Value_item.strExecutionTimeLimit = "--";
      task_Value_item.strDetailMsg = "--";

      task_Value_item.strTaskCreator = "--";
      task_Value_item.strExcuteCycle = "--";
      task_Value_item.strTaskStartProcessCmd = "--";
      task_Value_item.strTaskNextRunTime = "--";
      task_Value_item.strTaskLastRunTime = "--";
      task_Value_item.strTaskLastRunResult = "--";
      task_Value_item.strTaskCreateTime = "--";         
      if (SUCCEEDED(hr)){
        BSTR taskName = NULL;
        hr = pRegisteredTask->get_Name(&taskName);           // 计划任务名称
        if (SUCCEEDED(hr)){
          if (taskName){
            task_Value_item.strTaskName = UnicodeToUtf8String(taskName);
            SysFreeString(taskName);
          }
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task name: %x", hr);

        TASK_STATE task_State;
        hr = pRegisteredTask->get_State(&task_State);           // 计划任务状态
        if (SUCCEEDED(hr)){
          switch (task_State)
          {
          case 0: 
            task_Value_item.strTaskState = ansi_to_utf8("TASK_STATE_UNKNOWN");   // 未知
            break;
          case 1: 
            task_Value_item.strTaskState = ansi_to_utf8("TASK_STATE_DISABLED");  // 已禁用
            break;
          case 2:
            task_Value_item.strTaskState = ansi_to_utf8("TASK_STATE_QUEUED");    // 已排队
            break;
          case 3:
            task_Value_item.strTaskState = ansi_to_utf8("TASK_STATE_READY");     // 就绪
            break;
          case 4:
            task_Value_item.strTaskState = ansi_to_utf8("TASK_STATE_RUNNING");   // 正在运行
            break;
          default:
            break;
          }
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task state: %x", hr);

        DATE date;
        hr = pRegisteredTask->get_NextRunTime(&date);              // 计划任务下次运行时间
        if (SUCCEEDED(hr)){
          if (date)
            task_Value_item.strTaskNextRunTime = ansi_to_utf8(oleTime2Str1(date).data());
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task next run time: %x", hr);

        hr = pRegisteredTask->get_LastRunTime(&date);              // 计划任务上次运行时间
        if (SUCCEEDED(hr)){
          if (date)
            task_Value_item.strTaskLastRunTime = ansi_to_utf8(oleTime2Str1(date).data());
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task last run time: %x", hr);

        LONG lLastRunResult = 0;
        hr = pRegisteredTask->get_LastTaskResult(&lLastRunResult);           // 计划任务上次运行结果，返回值为错误码
        if (SUCCEEDED(hr)){
          LPVOID lpMsgBuf = NULL;
          FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            lLastRunResult,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL );
          if (lpMsgBuf){
            task_Value_item.strTaskLastRunResult = UnicodeToUtf8String((LPTSTR)lpMsgBuf);
            if (task_Value_item.strTaskLastRunResult.find("\r\n") != std::string::npos)
              task_Value_item.strTaskLastRunResult =task_Value_item.strTaskLastRunResult.substr(0, task_Value_item.strTaskLastRunResult.find("\r\n"));
            LocalFree(lpMsgBuf);
          }
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task last run result: %x", hr);

        ITaskDefinition* pDefinition = NULL;
        hr = pRegisteredTask->get_Definition(&pDefinition);         // 获取任务的定义  
        if (SUCCEEDED(hr)){
          IRegistrationInfo *pRegistrationInfo = NULL;
          hr = pDefinition->get_RegistrationInfo(&pRegistrationInfo);         // 获取任务的注册信息
          if (SUCCEEDED(hr)){
            BSTR author;
            hr = pRegistrationInfo->get_Author(&author);       // 计划任务创建者
            if (SUCCEEDED(hr)){
              if (author){
                task_Value_item.strTaskCreator = UnicodeToUtf8String(author);
                SysFreeString(author);
              }
            }
            else
              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Author error: %x", hr);

            BSTR date;
            hr = pRegistrationInfo->get_Date(&date);           // 计划任务创建时间
            if (SUCCEEDED(hr)){
              if (date){
                std::string strCreateTime = UnicodeToUtf8String(date);
                size_t pos = strCreateTime.find_first_of("T");
                task_Value_item.strTaskCreateTime = StringToDatetime(strCreateTime.substr(0, pos) + ansi_to_utf8(" ") + strCreateTime.substr(pos+1));
                SysFreeString(date);
              }
            }
            else
              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Date error: %x", hr);

            pRegistrationInfo->Release();
          }
          else
            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_RegistrationInfo error: %x", hr);

          IActionCollection* pcollection = NULL;
          hr = pDefinition->get_Actions(&pcollection);           // 计划任务启动进程命令行
          if (SUCCEEDED(hr)){
            long count = 0;
            hr = pcollection->get_Count(&count);
            if (SUCCEEDED(hr)){
              for (int i=1; i < count+1; i++)
              {
                IAction* pAction = NULL;
                hr = pcollection->get_Item(i, &pAction);
                if (SUCCEEDED(hr)){
                  IExecAction* pExecAction = NULL;
                  hr = pAction->QueryInterface(IID_IExecAction, (void**) &pExecAction);
                  if (SUCCEEDED(hr)){
                    std::string strCmd;
                    BSTR path;
                    hr = pExecAction->get_Path(&path);
                    if (SUCCEEDED(hr)){
                      if (path){
                        strCmd += UnicodeToUtf8String(path);
                        SysFreeString(path);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Path error: %x", hr);

                    BSTR argument;
                    hr = pExecAction->get_Arguments(&argument);
                    if (SUCCEEDED(hr)){
                      if (argument){
                        strCmd = strCmd + " " + UnicodeToUtf8String(argument);
                        SysFreeString(argument);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Arguments error: %x", hr);

                    task_Value_item.strTaskStartProcessCmd = strCmd;
                    pExecAction->Release();
                  }
                  else
                    DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface error: %x", hr);

                  pAction->Release();
                }
                else
                  DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Item error: %x", hr);
              }
            }
            else
              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Count error: %x", hr);

            pcollection->Release();
          }
          else
            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Actions error: %x", hr);

          ITriggerCollection* pTriggerCollection = NULL;
          hr = pDefinition->get_Triggers(&pTriggerCollection);           // 计划任务触发器
          if (SUCCEEDED(hr)){
            long count = 0;
            hr = pTriggerCollection->get_Count(&count);
            if (SUCCEEDED(hr)){
              if (count == 0){
                std::string strKey = task_Value_item.strTaskName +  ":" +  
                        task_Value_item.strID +  ":" + 
                        task_Value_item.strType +  ":" + 
                        task_Value_item.strEnabled +  ":" + 
                        task_Value_item.strDetailMsg; 
                if (g_map_tasks_table.find(strKey) == g_map_tasks_table.end())
                  g_map_tasks_table.insert(make_pair(strKey, task_Value_item)); 
              }
              else{
                // 增加自定义触发器这种，任何触发器字段一样做特殊处理
                unsigned short int iTriggerNum = 0;
                for (int i=1; i < count+1; i++)
                {
                  // 每个触发器解析都要重新初始化触发器相关字段
                  task_Value_item.strEnabled = "0"; 
                  task_Value_item.strType = "--";
                  task_Value_item.strStartBoundary = "--";
                  task_Value_item.strID = "--";
                  task_Value_item.strEndBoundary = "--";
                  task_Value_item.strExecutionTimeLimit = "--";
                  task_Value_item.strDetailMsg = "--";
 
                  ITrigger* pTrigger = NULL;
                  hr = pTriggerCollection->get_Item(i, &pTrigger);
                  if (SUCCEEDED(hr)){
                    VARIANT_BOOL Enabled;
                    hr = pTrigger->get_Enabled(&Enabled);  // 触发器状态
                    if (SUCCEEDED(hr)){
                      if (Enabled == 0)
                        task_Value_item.strEnabled = ansi_to_utf8("0");
                      else
                        task_Value_item.strEnabled = ansi_to_utf8("1");
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Enabled error: %x", hr);

                    BSTR Id;
                    hr = pTrigger->get_Id(&Id);           // ID
                    if (SUCCEEDED(hr)){
                      if (Id){
                        task_Value_item.strID = UnicodeToUtf8String(Id);
                        SysFreeString(Id);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Id error: %x", hr);

                    BSTR StartBoundary;
                    hr = pTrigger->get_StartBoundary(&StartBoundary);           // 计划任务启动时间
                    std::string strStartBoundary;
                    if (SUCCEEDED(hr)){
                      if (StartBoundary){
                        strStartBoundary = UnicodeToUtf8String(StartBoundary);
                        size_t pos = strStartBoundary.find_first_of("T");
                        strStartBoundary = strStartBoundary.substr(0, pos) + ansi_to_utf8(" ") + strStartBoundary.substr(pos+1);
                        task_Value_item.strStartBoundary = StringToDatetime(strStartBoundary);
                        SysFreeString(StartBoundary);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_StartBoundary error: %x", hr);

                    BSTR EndBoundary;
                    hr = pTrigger->get_EndBoundary(&EndBoundary);             // 计划任务停止时间
                    std::string strEndBoundary;
                    if (SUCCEEDED(hr)){
                      if (EndBoundary){
                        strEndBoundary = UnicodeToUtf8String(EndBoundary);
                        size_t pos = strEndBoundary.find_first_of("T");
                        strEndBoundary = strEndBoundary.substr(0, pos) + ansi_to_utf8(" ") + strEndBoundary.substr(pos+1);
                        task_Value_item.strEndBoundary = StringToDatetime(strEndBoundary);
                        SysFreeString(EndBoundary);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_EndBoundary error: %x", hr);

                    BSTR ExecutionTimeLimit;
                    hr = pTrigger->get_ExecutionTimeLimit(&ExecutionTimeLimit);             // 计划任务限制时间
                    if (SUCCEEDED(hr)){
                      if (ExecutionTimeLimit){
                        std::string strExecutionTimeLimit = UnicodeToUtf8String(ExecutionTimeLimit);
                        size_t pos = strExecutionTimeLimit.find_first_of("T");
                        task_Value_item.strExecutionTimeLimit = StringToDatetime(strExecutionTimeLimit.substr(0, pos) + ansi_to_utf8(" ") + strExecutionTimeLimit.substr(pos+1));
                        SysFreeString(ExecutionTimeLimit);
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_ExecutionTimeLimit error: %x", hr);

                    TASK_TRIGGER_TYPE2 TaskTriggerType;
                    hr = pTrigger->get_Type(&TaskTriggerType);  // 触发器的类型
                    if (SUCCEEDED(hr)){
                      switch (TaskTriggerType)
                      {
                      case 0:
                        task_Value_item.strType = ansi_to_utf8("TASK_TRIGGER_EVENT");           // 发生特定事件时触发任务
                        task_Value_item.strDetailMsg = WcharToString(L"发生事件时，事件详细信息请到探针所在终端查看");
                        break;
                      case 1:
                        {
                          task_Value_item.strType  = "TASK_TRIGGER_TIME";           // 在一天中的特定时间触发任务
                          size_t pos = strStartBoundary.find(" ");
                          if (pos != std::string::npos){
                            task_Value_item.strDetailMsg = WcharToString(L"在") + strStartBoundary.substr(0, pos) + WcharToString(L"的") + strStartBoundary.substr(pos+1) + WcharToString(L"时");
                          }
                        }
                        break;
                      case 2:
                        {
                          //--
                          //--这里暂未处理触发器到期时间和触发器触发后的时间间隔，后面有时间再处理
                          //--
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_DAILY");          // 每天计划触发任务
                          IDailyTrigger *DailyTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_IDailyTrigger, (void**) &DailyTrigger);
                          if (SUCCEEDED(hr)){
                            short Days = 0;
                            hr = DailyTrigger->get_DaysInterval(&Days);
                            if (SUCCEEDED(hr)){
                              size_t pos = strStartBoundary.find(" ");
                              if (pos != std::string::npos){
                                task_Value_item.strDetailMsg = WcharToString(L"在每");
                                if (Days > 1)
                                  task_Value_item.strDetailMsg += ansi_to_utf8(type2str(Days).data());
                                task_Value_item.strDetailMsg = task_Value_item.strDetailMsg + WcharToString(L"天的") + strStartBoundary.substr(pos+1);
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_DaysInterval error: %x", hr);
                            DailyTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface DailyTrigger: %x", hr);
                        }
                        break;
                      case 3:
                        {
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_WEEKLY");         // 每周计划触发任务
                          IWeeklyTrigger *WeeklyTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_IWeeklyTrigger, (void**) &WeeklyTrigger);
                          if (SUCCEEDED(hr)){
                            short DaysOfWeek = 0;
                            hr = WeeklyTrigger->get_DaysOfWeek(&DaysOfWeek);
                            if (SUCCEEDED(hr)){
                              short Weeks = 0;
                              hr = WeeklyTrigger->get_WeeksInterval(&Weeks);
                              if (SUCCEEDED(hr)){
                                size_t pos = strStartBoundary.find(" ");
                                if (pos != std::string::npos){
                                  task_Value_item.strDetailMsg = WcharToString(L"每");
                                  if (Weeks > 1)
                                    task_Value_item.strDetailMsg += ansi_to_utf8(type2str(Weeks).data());
                                  task_Value_item.strDetailMsg +=  WcharToString(L"周的");
                                  bool bHasHeader = false;
                                  if (DaysOfWeek & 0X01){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期日");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期日");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X02){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期一");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期一");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X04){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期二");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期二");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X08){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期三");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期三");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X10){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期四");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期四");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X20){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期五");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期五");
                                    bHasHeader = true;
                                  }
                                  if (DaysOfWeek & 0X40){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg +=  WcharToString(L",星期六");
                                    else
                                      task_Value_item.strDetailMsg +=  WcharToString(L"星期六");
                                    bHasHeader = true;
                                  }

                                  task_Value_item.strDetailMsg =  task_Value_item.strDetailMsg + strStartBoundary.substr(pos+1) +  WcharToString(L"时, 开始日期：") +
                                    strStartBoundary.substr(0, pos);
                                }
                              }
                              else
                                DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_WeeksInterval error: %x", hr);
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_DaysOfWeek error: %x", hr);
                            WeeklyTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface WeeklyTrigger error: %x", hr);
                        }
                        break;
                      case 4:
                        {
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_MONTHLY");        // 按月计划触发任务
                          IMonthlyTrigger *MonthlyTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_IMonthlyTrigger, (void**) &MonthlyTrigger);
                          if (SUCCEEDED(hr)){
                            short Months = 0;
                            hr = MonthlyTrigger->get_MonthsOfYear(&Months);
                            if (SUCCEEDED(hr)){
                              size_t pos = strStartBoundary.find(" ");
                              if (pos != std::string::npos){
                                task_Value_item.strDetailMsg =  WcharToString(L"在");
                                bool bHasHeader = false;
                                if (Months & 0X001){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",一月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"一月");
                                  bHasHeader = true;
                                }
                                if (Months & 0x002){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",二月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"二月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X004){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",三月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"三月");
                                  bHasHeader = true;
                                }
                                if (Months & 0x008){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",四月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"四月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X010){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",五月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"五月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X020){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",六月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"六月");
                                  bHasHeader = true;
                                }
                                if (Months & 0x040){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",七月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"七月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X080){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",八月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"八月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X100){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",九月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"九月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X200){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",十月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"十月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X400){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",十一月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"十一月");
                                  bHasHeader = true;
                                }
                                if (Months & 0X800){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg +=  WcharToString(L",十二月");
                                  else
                                    task_Value_item.strDetailMsg +=  WcharToString(L"十二月");
                                  bHasHeader = true;
                                }
                                task_Value_item.strDetailMsg +=  WcharToString(L"的");
                                long Days;
                                hr = MonthlyTrigger->get_DaysOfMonth(&Days);
                                if (SUCCEEDED(hr)){
                                  if (Days != 0X00){
                                    bHasHeader = false;
                                    if (Days & 0x01){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",1");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("1");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x02){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",2");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("2");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x04){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",3");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("3");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x08){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",4");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("4");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x10){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",5");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("5");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x20){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",6");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("6");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x40){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",7");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("7");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x80){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",8");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("8");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x100){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",9");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("9");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x200){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",10");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("10");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x400){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",11");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("11");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x800){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",12");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("12");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x1000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",13");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("13");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x2000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",14");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("14");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x4000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",15");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("15");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x8000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",16");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("16");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x10000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",17");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("17");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x20000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",18");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("18");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x40000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",19");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("19");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x80000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",20");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("20");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x100000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",21");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("21");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x200000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",22");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("22");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x400000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",23");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("23");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x800000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",24");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("24");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x1000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",25");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("25");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x2000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",26");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("26");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x4000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",27");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("27");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x8000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",28");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("28");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x10000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",29");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("29");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x20000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",30");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("30");
                                      bHasHeader = true;
                                    }
                                    if (Days & 0x40000000){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += ansi_to_utf8(",31");
                                      else
                                        task_Value_item.strDetailMsg += ansi_to_utf8("31");
                                      bHasHeader = true;
                                    }
                                    VARIANT_BOOL bRunOnLastDay = false;
                                    hr = MonthlyTrigger->get_RunOnLastDayOfMonth(&bRunOnLastDay);
                                    if (SUCCEEDED(hr)){
                                      if (bRunOnLastDay){
                                        if (bHasHeader)
                                          task_Value_item.strDetailMsg += WcharToString(L",最后一个");
                                        else
                                          task_Value_item.strDetailMsg += WcharToString(L"最后一个");
                                        bHasHeader = true;
                                      }
                                    }
                                    else
                                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_RunOnLastDayOfMonth error: %x", hr);
                                  }
                                  else{

                                  }
                                }
                                else 
                                  DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_DaysOfMonth: %x", hr);
                                task_Value_item.strDetailMsg += WcharToString(L"的");
                                task_Value_item.strDetailMsg = task_Value_item.strDetailMsg + strStartBoundary.substr(pos+1) +  WcharToString(L", 开始日期：") +
                                  strStartBoundary.substr(0, pos);
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_MonthsOfYear error: %x", hr);
                            MonthlyTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface MonthlyTrigger %x", hr);
                        }
                        break;
                      case 5:
                        {
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_MONTHLYDOW");        // 按月计划触发任务
                          IMonthlyDOWTrigger *MonthlyDOWTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_IMonthlyDOWTrigger, (void**) &MonthlyDOWTrigger);
                          if (SUCCEEDED(hr)){
                            short Weeks;
                            hr = MonthlyDOWTrigger->get_WeeksOfMonth(&Weeks);
                            if (SUCCEEDED(hr)){
                              size_t pos = strStartBoundary.find(" ");
                              if (pos != std::string::npos){
                                task_Value_item.strDetailMsg = WcharToString(L"在");
                                bool bHasHeader = false;
                                if (Weeks & 0X01){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg += WcharToString(L",第一个");
                                  else
                                    task_Value_item.strDetailMsg += WcharToString(L"第一个");
                                  bHasHeader = true;
                                }
                                if (Weeks & 0x02){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg += WcharToString(L",第二个");
                                  else
                                    task_Value_item.strDetailMsg += WcharToString(L"第二个");
                                  bHasHeader = true;
                                }
                                if (Weeks & 0X04){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg += WcharToString(L",第三个");
                                  else
                                    task_Value_item.strDetailMsg += WcharToString(L"第三个");
                                  bHasHeader = true;
                                }
                                if (Weeks & 0X08){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg += WcharToString(L",第四个");
                                  else
                                    task_Value_item.strDetailMsg += WcharToString(L"第四个");
                                  bHasHeader = true;
                                }
                                if (Weeks & 0X08){
                                  if (bHasHeader)
                                    task_Value_item.strDetailMsg += WcharToString(L",最后一个");
                                  else
                                    task_Value_item.strDetailMsg += WcharToString(L"最后一个");
                                  bHasHeader = true;
                                }
                                VARIANT_BOOL bRunOnLastWeek = false;
                                hr = MonthlyDOWTrigger->get_RunOnLastWeekOfMonth(&bRunOnLastWeek);
                                if (SUCCEEDED(hr)){
                                  if (bRunOnLastWeek){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",最后一个");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"最后一个");
                                    bHasHeader = true;
                                  }
                                }
                                else
                                  DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_RunOnLastDayOfMonth error: %x", hr);

                                short Days;
                                hr = MonthlyDOWTrigger->get_DaysOfWeek(&Days);
                                if (SUCCEEDED(hr)){
                                  bool bHasHeader = false;
                                  if (Days & 0X01){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期日");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期日");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X02){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期一");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期一");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X04){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期二");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期二");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X08){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期三");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期三");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X10){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期四");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期四");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X20){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期五");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期五");
                                    bHasHeader = true;
                                  }
                                  if (Days & 0X40){
                                    if (bHasHeader)
                                      task_Value_item.strDetailMsg += WcharToString(L",星期六");
                                    else
                                      task_Value_item.strDetailMsg += WcharToString(L"星期六");
                                    bHasHeader = true;
                                  }

                                  task_Value_item.strDetailMsg += WcharToString(L"运行，每个");
                                  short Months = 0;
                                  hr = MonthlyDOWTrigger->get_MonthsOfYear(&Months);
                                  if (SUCCEEDED(hr)){
                                    bool bHasHeader = false;
                                    if (Months & 0X001){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",一月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"一月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0x002){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",二月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"二月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X004){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",三月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"三月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0x008){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",四月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"四月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X010){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",五月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"五月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X020){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",六月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"六月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0x040){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",七月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"七月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X080){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",八月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"八月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X100){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",九月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"九月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X200){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",十月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"十月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X400){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",十一月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"十一月");
                                      bHasHeader = true;
                                    }
                                    if (Months & 0X800){
                                      if (bHasHeader)
                                        task_Value_item.strDetailMsg += WcharToString(L",十二月");
                                      else
                                        task_Value_item.strDetailMsg += WcharToString(L"十二月");
                                      bHasHeader = true;
                                    }
                                  }
                                  else 
                                    DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_MonthsOfYear: %x", hr);
                                  task_Value_item.strDetailMsg = task_Value_item.strDetailMsg + WcharToString(L", 开始日期：") + strStartBoundary.substr(0, pos);
                                }
                                else
                                  DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_DaysOfWeek error: %x", hr);
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_WeeksOfMonth error %x", hr);

                            MonthlyDOWTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface MonthlyTrigger %x", hr);
                        }
                        break;
                      case 6:
                        task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_IDLE");           // 计算机空闲状态下触发任务
                        task_Value_item.strDetailMsg = WcharToString(L"当计算机空闲时");
                        break;
                      case 7:
                        task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_REGISTRATION");   // 注册任务是触发任务
                        task_Value_item.strDetailMsg = WcharToString(L"当创建任务或修改任务时");
                        break;
                      case 8:
                        task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_BOOT");           // 系统启动时触发任务
                        task_Value_item.strDetailMsg = WcharToString(L"在系统启动时");
                        break;
                      case 9:
                        {
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_LOGON");          // 用户登录时触发任务
                          ILogonTrigger* TaskLogonTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_ILogonTrigger, (void**) &TaskLogonTrigger);
                          if (SUCCEEDED(hr)){
                            BSTR UserID;
                            hr = TaskLogonTrigger->get_UserId(&UserID);
                            std::string strUserID;
                            if (SUCCEEDED(hr)){
                              if (UserID){
                                strUserID =UnicodeToUtf8String(UserID);
                                SysFreeString(UserID);
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_UserId error: %x", hr);

                            if (!strUserID.empty())
                              task_Value_item.strDetailMsg = WcharToString(L"登录") + strUserID + WcharToString(L"时");
                            else
                              task_Value_item.strDetailMsg = WcharToString(L"当任何用户登录时");

                            TaskLogonTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface TaskLogonTrigger error: %x", hr);
                        }
                        break;
                      case 11:
                        {
                          task_Value_item.strType  = ansi_to_utf8("TASK_TRIGGER_SESSION_STATE_CHANGE");      // 用户会话状态改变时触发任务
                          ISessionStateChangeTrigger* SessionStateChangeTrigger = NULL;
                          hr = pTrigger->QueryInterface(IID_ISessionStateChangeTrigger, (void**) &SessionStateChangeTrigger);
                          if (SUCCEEDED(hr)){
                            BSTR UserID;
                            hr = SessionStateChangeTrigger->get_UserId(&UserID);   //** 获取用户 **
                            std::string strUserID;
                            if (SUCCEEDED(hr)){
                              if (UserID){
                                strUserID = UnicodeToUtf8String(UserID);
                                SysFreeString(UserID);
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_UserId error: %x", hr);

                            TASK_SESSION_STATE_CHANGE_TYPE TaskSessionStateChangeType; 
                            hr = SessionStateChangeTrigger->get_StateChange(&TaskSessionStateChangeType);   //** SessionState **
                            if (SUCCEEDED(hr)){
                              switch (TaskSessionStateChangeType)
                              {
                              case 1:    // "TASK_CONSOLE_CONNECT"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"当至") + strUserID + WcharToString(L"的用户会话的本地连接上");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当本地连接到任何用户会话时");
                                break;
                              case 2:    // "TASK_CONSOLE_DISCONNECT"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"在本地断开与") + strUserID + WcharToString(L"的用户会话的连接");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当断开来自任何用户会话的本地连接时");
                                break;
                              case 3:    // "TASK_REMOTE_CONNECT"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"当至") + strUserID + WcharToString(L"的用户会话的远程连接上");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当远程连接到任何用户会话时");
                                break;
                              case 4:    // "TASK_REMOTE_DISCONNECT"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"从远程断开与") + strUserID + WcharToString(L"的用户会话的连接");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当断开来自任何用户会话的远程连接时");
                                break;
                              case 7:    // "TASK_SESSION_LOCK"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"当锁定") + strUserID + WcharToString(L"的工作站时");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当锁定任何用户的工作站时");
                                break;
                              case 8:    // "TASK_SESSION_UNLOCK"
                                if (!strUserID.empty())
                                  task_Value_item.strDetailMsg = WcharToString(L"当解锁") + strUserID + WcharToString(L"的工作站时");
                                else
                                  task_Value_item.strDetailMsg = WcharToString(L"当解锁任何用户的工作站时");
                                break;
                              default:
                                break;
                              }
                            }
                            else
                              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_StateChange error: %x", hr);
                            SessionStateChangeTrigger->Release();
                          }
                          else
                            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: QueryInterface SessionStateChangeTrigger error: %x", hr);
                        }
                        break;
                      case 12:
                        iTriggerNum++;
                        task_Value_item.strType  = WcharToString(L"自定义触发器");
                        task_Value_item.strDetailMsg = task_Value_item.strType + ansi_to_utf8(type2str(iTriggerNum).data());        // 增加编号
                        break;
                      default:
                        break;
                      }
                    }
                    else
                      DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_type error: %x", hr);
                      std::string strKey = task_Value_item.strTaskName +  ":" +  
                        task_Value_item.strID +  ":" + 
                        task_Value_item.strType +  ":" + 
                        task_Value_item.strEnabled +  ":" + 
                        task_Value_item.strDetailMsg;
                      if (g_map_tasks_table.find(strKey) == g_map_tasks_table.end())
                        g_map_tasks_table.insert(make_pair(strKey, task_Value_item)); 
                    pTrigger->Release();
                  }
                  else 
                    DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Item error: %x", hr);
                }
              }
            }
            else
              DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Count error: %x", hr);

            pTriggerCollection->Release();
          }
          else{
            std::string strKey = task_Value_item.strTaskName +  ":" +  
                        task_Value_item.strID +  ":" + 
                        task_Value_item.strType +  ":" + 
                        task_Value_item.strEnabled +  ":" + 
                        task_Value_item.strDetailMsg;
                      if (g_map_tasks_table.find(strKey) == g_map_tasks_table.end())
                        g_map_tasks_table.insert(make_pair(strKey, task_Value_item)); 
            DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Triggers error, task name is %s: %x", task_Value_item.strTaskName.data(), hr);
          }

          pDefinition->Release();
        }
        else
          DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: get_Definition: %x", hr);
        pRegisteredTask->Release();
      }
      else
        DI_LOG_DEBUG("DIAssetTask::GetTaskItemByFolder: Cannot get the registered task item at index=%d: %x", i+1, hr);

      Sleep(1);
    }

    pTaskCollection->Release();
  }
}
