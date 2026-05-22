#include "stdafx.h"

#include <signal.h>

#include "HRAMain.h"
#include "utility/comm.h"
#include "utility/Logger.h"
#include "utility/ConfigSave.h"
#include "utility/HraCompress.h"
#include "utility/HraUtils.h"
#include "utility/HraJson.h"
//#include "utility/HraCmdPkg.h"
#include "utility/HraReport.h"
#include "utility/version.hpp"
#include "utility/HraAppDef.h"
#include "utility/HraTaskType.h"
//#include "HRARpcClientManager/HRARpcClientManager.h"
//#include "HRARpcServerManager/HRARpcServerManager.h"
#include "HRAModuleInterface/HRAModuleInterface.h"
#include "HRATaskScheduler/HRATaskScheduler.h"
#include "HraRpcCommModule/HraRpcCommModule.h"
//#include "utilInstallation/instComDefine.h"
//#include "HraIpcInterface/HraIpcCommDef.h"

volatile int g_slFinished = MAINLOOP_NOT_FINISHED;
SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_ServiceStatusHandle = NULL;
HANDLE g_HraStopEvent = NULL;

#define MAIN_WAIT_TIME_OUT (10*60*1000) //10分钟


/// <summary>
/// 应用程序总初始化
/// </summary>
/// <returns></returns>
int HraAppInit()
{
    HRA_Code lRet = (HRA_Code)CheckProcRun();
    if (HRA_OK != lRet)
    {
        return lRet;
    }

	SetWorkingDirectory();

    LOG_INFO("HraAppInit finished!");
    return HRA_OK;
}

/// <summary>
/// 应用程序运行
/// </summary>
/// <returns></returns>
int HraAppRun()
{
    SERVICE_TABLE_ENTRY DispatchTable[] = {{/*SZSERVICENAME*/ L"", (LPSERVICE_MAIN_FUNCTION)HraSrvMainFun},
                                           {NULL, NULL}};
    if (!StartServiceCtrlDispatcher(DispatchTable))
    {
        LOG_ERROR("Start main service failed, error=%lu", GetLastError());
    }
    //LOG_INFO("Start win service succeed!");
    return HRA_OK;
}

/// <summary>
/// 应用程序清理
/// </summary>
/// <returns></returns>
int HraAppEnd()
{
    LOG_INFO("Hra stoped!");

    HRA_Code lRet = (HRA_Code)HraUnInitLog();
	if (HRA_OK != lRet)
	{
		LOG_ERROR("Deinit failed: HraUnInitLog");
	}

    return HRA_OK;
}

/// <summary>
/// 检查程序是否已经在运行
/// </summary>
/// <returns></returns>
int CheckProcRun()
{
    HANDLE hMutex = ::CreateMutex(NULL, TRUE, L"aisec_windows_hra");
    if (hMutex == NULL)
    {
        return HRA_NULL_PTR;
    }

    DWORD ret = ::GetLastError();
    if (ret == ERROR_ALIAS_EXISTS)
    {
        return HRA_ALREADY_EXIST;
    }

    return HRA_OK;
}

/// <summary>
/// 设置当前工作目录
/// </summary>
void SetWorkingDirectory()
{
    wchar_t path[MAX_PATH + 1];
    DWORD length = GetModuleFileName(NULL, path, MAX_PATH + 1);
    if (length > 0)
    {
        std::wstring pathString(path);
        std::string::size_type pos = pathString.rfind('\\');
        pathString = pathString.substr(0, pos + 1);
        SetCurrentDirectory(pathString.c_str());
    }
}

/// <summary>
/// 初始化日志
/// </summary>
/// <param name=""></param>
/// <returns></returns>
int HraInitLog(const wchar_t* wszSrvName)
{
    std::string strLogPath;
    std::string strTmpPath = UtilsGetRegDataPath(UtilsUnicodeToString(wszSrvName));
    if (!strTmpPath.empty())
    {
        strLogPath = strTmpPath;
    }
    else
    {
        char szProgramDir[MAX_PATH] = {0};
        if (HRA_OK != UtilsGetProgramDataDir(szProgramDir, MAX_PATH))
        {
            return HRA_FAILED;
        }
        char szValue[MAX_PATH] = {0};
        _snprintf_s(szValue, sizeof(szValue), "%s\\%s\\%s\\", szProgramDir, HRA_PARAM_AIS_DIR_NAME,
                    UtilsUnicodeToString(wszSrvName).c_str());
        strLogPath = szValue;
    }

    if (CLoger::Initialize(strLogPath.c_str()))
    {
#ifdef _DEBUG
        CLoger::SetLogLevel(LOG_LEVEL_DEBUG);
#else
        CLoger::SetLogLevel(LOG_LEVEL_INFO);
#endif
        LOG_INFO("\n"
                 "################################### HRA Welcome #####################################\n"
                 "# Product Name:       AsiaInfo Security Host Hardening Agent\n"
                 "# Product Version:    %d.%d.%d.%d\n"
                 "#####################################################################################",
                 HRA_VER_MAJOR, HRA_VER_MINOR, HRA_VER_PATCH, HRA_VER_BUILD);
        return HRA_OK;
    }

    return HRA_FAILED;
}
int HraUnInitLog(void)
{
    CLoger::UnInitialize();
    return HRA_OK;
}

/// <summary>
/// 解析命令行参数
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <param name="stInputPara"></param>
/// <returns></returns>
int ParseCmdParam(struct InputParamater* stInputPara, DWORD argc, LPCWSTR* wargv)
{
    if (argc <= 0)
    {
        LOG_WARN("argc:%lu error!", argc);
        return HRA_BAD_PARAM;
    }

    std::wstring wstrParam;
    for (DWORD i = 0; i < argc; ++i)
    {
        wstrParam += wargv[i];
        wstrParam += L" ";
    }
    std::string strParam = UtilsUnicodeToString(wstrParam);
    if (!UtilsGetParam(stInputPara->strUUID, HRA_PARAM_UUID, strParam))
    {
        LOG_WARN("%s not found! Param string:%s", HRA_PARAM_UUID, strParam.c_str());
    }
    if (!UtilsGetParam(stInputPara->strProIpcName, HRA_PARAM_PRO_IPC_NAME, strParam))
    {
        LOG_WARN("%s not found! Param string:%s", HRA_PARAM_PRO_IPC_NAME, strParam.c_str());
    }
    if (!UtilsGetParam(stInputPara->strHraIpcName, HRA_PARAM_HRA_IPC_NAME, strParam))
    {
        LOG_WARN("%s not found! Param string:%s", HRA_PARAM_HRA_IPC_NAME, strParam.c_str());
    }

    stInputPara->strServiceName = UtilsUnicodeToString(wargv[0]);

    return HRA_OK;
}

/// <summary>
/// 保存默认配置项
/// </summary>
/// <param name="stInputPara"></param>
/// <returns></returns>
int InitGlobalConfigSave(struct InputParamater* stInputPara)
{
    //初始化配置文件
    WCHAR szPath[MAX_PATH];
    memset(szPath, 0, sizeof(szPath));
    DWORD dwLen            = GetCurrentDirectory(MAX_PATH, szPath);
    std::wstring strDbPath = std::wstring(szPath) + L"\\config\\config.db";
    int iRet               = g_ConfigSave.ConfigSaveInit(UtilsUnicodeToString(strDbPath).c_str());
    if (iRet != HRA_OK)
    {
        LOG_ERROR("Init config save failed! file:%s", UtilsUnicodeToString(strDbPath).c_str());
        return HRA_FAILED;
    }

    // 由于2.0.3版本加了update_time字段，
    // 且为了适配esm遇到删除不了hra安装目录的bug：https://ipd.asiainfo-sec.com:8443/browse/ACD-2284
    // 则初始化时检查表中字段，少了字段则添加字段
    iRet = g_ConfigSave.CheckTableStructure(GLOBAL_CONFIG_TABLE);
    if (iRet != HRA_OK)
    {
        LOG_ERROR("CheckTableStructure failed! table:%s, file:%s",
                  GLOBAL_CONFIG_TABLE, UtilsUnicodeToString(strDbPath).c_str());
        return HRA_FAILED;
    }
    iRet = g_ConfigSave.CheckTableStructure(ASSETSCAN_CFG_TABLE);
    if (iRet != HRA_OK)
    {
        LOG_ERROR("CheckTableStructure failed! table:%s, file:%s", ASSETSCAN_CFG_TABLE,
                  UtilsUnicodeToString(strDbPath).c_str());
        return HRA_FAILED;
    }

    //日志等级
    std::string strLogLevel = g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_LOG_LEVEL);
    std::string strLogAge = g_ConfigSave.ConfigSaveGetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_LOG_AGE);
    if (!strLogLevel.empty() && !strLogAge.empty())
    {
        int nLogLevel = atoi(strLogLevel.c_str());
        int nLogAge   = atoi(strLogAge.c_str());
        if (nLogAge == HRA_LOG_AGE_LONG)
        {
            CLoger::SetLogLevel((LOG_LEVEL)nLogLevel);
            LOG_INFO("Set log level:%d", nLogLevel);
        }
    }

    if (!stInputPara)
    {
        LOG_ERROR("[HRA] initGlobalConfigSave work entry is Null.");
        return HRA_NULL_PTR;
    }

    //判断参数解析情况，没有则先读取db库，两者都没有则不能启动
    if (stInputPara->strUUID.empty())
    {
        stInputPara->strUUID = UtilsGetUUID();
        if (stInputPara->strUUID.empty())
        {
            LOG_ERROR("Get UUID from config.db error!");
            //stInputPara->strUUID = DEFAULT_UUID;
            return HRA_FAILED;
        }
        LOG_INFO("Get UUID from config.db! UUID:%s", stInputPara->strUUID.c_str());
    }

    if (stInputPara->strProIpcName.empty())
    {
        stInputPara->strProIpcName = UtilsGetProIpcName();
        if (stInputPara->strProIpcName.empty())
        {
            LOG_ERROR("Get PRO_IPC_NAME from config.db error!");
            //stInputPara->strProIpcName = DEFAULT_PRO_IPC_NAME;
            return HRA_FAILED;
        }
        LOG_INFO("Get PRO_IPC_NAME from config.db succeed! PRO_IPC_NAME:%s", stInputPara->strProIpcName.c_str());
    }

    if (stInputPara->strHraIpcName.empty())
    {
        stInputPara->strHraIpcName = UtilsGetHraIpcName();
        if (stInputPara->strHraIpcName.empty())
        {
            LOG_ERROR("Get HRA_IPC_NAME from config.db error!");
            //stInputPara->strHraIpcName = DEFAULT_HRA_IPC_NAME;
            return HRA_FAILED;
        }
        LOG_INFO("Get HRA_IPC_NAME from config.db succeed! HRA_IPC_NAME:%s", stInputPara->strHraIpcName.c_str());
    }

    //保存配置
    if (g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_UUID, stInputPara->strUUID) != HRA_OK ||
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_PRO_IPC_NAME, stInputPara->strProIpcName) != HRA_OK ||
        g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_HRA_IPC_NAME, stInputPara->strHraIpcName) != HRA_OK)
    {
        LOG_ERROR("ConfigSaveSetValue ERROR!");
        return HRA_FAILED;
    }

    std::wstring strWorkPath = std::wstring(szPath) + L"\\";
    if (g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_WORK_DIR,
                                        UtilsUnicodeToString(strWorkPath).c_str()) != HRA_OK)
    {
        LOG_ERROR("ConfigSaveSetValue:%s ERROR!", HRA_PARAM_WORK_DIR);
        return HRA_FAILED;
    }

    // 获取不到HRA Version不会退出,因为产品前端页面上并没有显示HRA上报的版本号;
    std::string strHraVersion = UtilsGetAppVersion();
    if (g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_VERSION, strHraVersion.c_str()) != HRA_OK)
    {
        LOG_WARN("ConfigSaveSetValue:%s ERROR!", HRA_PARAM_VERSION);
    }

    // 现在数据目录,不需要自行指定,产品侧会传入
    std::string strSpecificPath = UtilsGetRegDataPath(stInputPara->strServiceName);
    if (strSpecificPath.empty())
    { // 集成HRA_2.0.3以前版本的产品,使用分隔升级HRA
        char szProgramDir[MAX_PATH] = {0};
        if (HRA_OK != UtilsGetProgramDataDir(szProgramDir, MAX_PATH))
        {
            LOG_ERROR("UtilsGetProgramDataDir failed, errorCode:%lu", GetLastError());
            return HRA_FAILED;
        }
        char szValue[MAX_PATH] = {0};
        _snprintf_s(szValue, sizeof(szValue), "%s\\%s\\%s\\", szProgramDir, HRA_PARAM_AIS_DIR_NAME,
                    stInputPara->strServiceName.c_str());
        if (UtilsCheckCreateDir(szValue) != HRA_OK)
        {
            LOG_ERROR("UtilsCheckCreateDir:%s ERROR!", szValue);
            return HRA_FAILED;
        }
        if (g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_DATA_DIR, szValue) != HRA_OK)
        {
            LOG_ERROR("ConfigSaveSetValue:%s ERROR!", HRA_PARAM_WORK_DIR);
            return HRA_FAILED;
        }
    }
    else
    { // 集成HRA_2.0.3及以上版本的产品
        if (UtilsCheckCreateDir(strSpecificPath) != HRA_OK)
        {
            LOG_ERROR("UtilsCheckCreateDir:%s ERROR!", strSpecificPath.c_str());
            return HRA_FAILED;
        }

        if (g_ConfigSave.ConfigSaveSetValue(GLOBAL_CONFIG_TABLE, HRA_PARAM_DATA_DIR, strSpecificPath) != HRA_OK)
        {
            LOG_ERROR("ConfigSaveSetValue:%s ERROR!", HRA_PARAM_WORK_DIR);
            return HRA_FAILED;
        }
    }

    return HRA_OK;
}



//################################服务函数
/// <summary>
/// hra Windows服务主入口
/// </summary>
/// <param name="argc"></param>
/// <param name="argv"></param>
/// <returns></returns>
void WINAPI HraSrvMainFun(DWORD argc, LPCWSTR* argv)
{
    DWORD dwRet = ERROR_SUCCESS;
    // init Log
    if (HRA_OK != HraInitLog(argv[0]))
    {
        goto _end;
    }

    //服务初始化
    if (HRA_OK != HraSrvInit(argc, argv))
    {
        goto _end;
    }

    //等待服务被结束的请求
    if (g_HraStopEvent)
    {
        LOG_INFO("Wait for stop event...");
        while (true)
        {
            dwRet = WaitForSingleObject(g_HraStopEvent, MAIN_WAIT_TIME_OUT);
            if (dwRet == WAIT_TIMEOUT)
            {
                // 报告运行状态给SCM
                ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0);
                LOG_INFO("Wait for stop event timeout, report to scm running stat, continue wait...%lu", dwRet);
                continue;
            }
            
            LOG_INFO("Get stop event! %lu", dwRet);
            break;
        }
    }

_end:
    LOG_INFO("Hra service stopping...");
    HraSrvEnd();
}

/// <summary>
/// 信号处理
/// </summary>
/// <param name="sig"></param>
static VOID sigintHandler(S32 sig)
{
    g_slFinished = MAINLOOP_FINISHED;
}
static void SigHandlerInit()
{
    (VOID)signal(SIGINT, sigintHandler);
    (VOID)signal(SIGTERM, sigintHandler);
}

/// <summary>
/// hra服务初始化
/// </summary>
/// <returns></returns>
int HraSrvInit(DWORD argc, LPCWSTR* wargv)
{
    if (argc <= 0)
    {
        LOG_ERROR("argc:%lu error!", argc);
        return HRA_BAD_PARAM;
    }

    //Windows服务初始化
    int lRet = HraWinSrvInit(wargv[0]);
    if (HRA_OK != lRet)
    {
        return lRet;
    }

    //报告初始状态给SCM
    ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000);

    //解析参数
    InputParamater stInputPara;
    lRet = ParseCmdParam(&stInputPara, argc, wargv);
    if (lRet != HRA_OK)
    {
        return lRet;
    }

    //// 初始化存储配置的数据库,没有就创建,有就直接打开.
    // 初始化global配置
    lRet = InitGlobalConfigSave(&stInputPara);
    if (HRA_OK != lRet)
    {
    	LOG_ERROR( "InitGlobal config save fail");
        return lRet;
    } 

    /* init signal */
    SigHandlerInit();

    /* Scheduler Init */
    lRet = HraTask_Init(wargv[0]);
    if (HRA_OK != lRet)
    {
        LOG_ERROR("HraTask_Init fail");
        return lRet;
    }

    if (g_slFinished == MAINLOOP_FINISHED)
    {
        LOG_WARN("Finish flag!");
        return HRA_NOT_INIT;
    }

    /* 初始化模块 */
    lRet = ModuleInit();
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Init module fail");
        return lRet;
    }

    if (g_slFinished == MAINLOOP_FINISHED)
    {
        LOG_WARN("Finish flag!");
        return HRA_NOT_INIT;
    }

    //启动命令接收线程
    lRet = DsaCmd_StartThread(stInputPara.strHraIpcName.c_str());
    if (HRA_OK != lRet)
    {
        LOG_ERROR("DsaCmd_StartThread failed.");
        return lRet;
    }

    if (g_slFinished == MAINLOOP_FINISHED)
    {
        LOG_WARN("Finish flag!");
        return HRA_NOT_INIT;
    }

    // register 
    lRet = HraRegsterInfo();
    if (HRA_OK != lRet)
    {
        LOG_ERROR("Regster info failed.");
        return lRet;
    }

    // 启动任务处理线程
    lRet = HraTask_StartThread();
    if (HRA_OK != lRet)
    {
        LOG_ERROR("HraTask_StartThread failed.");
        return lRet;
    }

    if (g_slFinished == MAINLOOP_FINISHED)
    {
        LOG_WARN("Finish flag!");
        return HRA_NOT_INIT;
    }

    //报告运行状态给SCM
    ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0);
    return HRA_OK;
}

/// <summary>
/// 服务结束，清理
/// </summary>
/// <returns></returns>
int HraSrvEnd()
{
    HraTask_DeInit();
    ModuleDeinit();
    HraWinSrvDeinit();
    LOG_INFO("HraSrvEnd!");
    return HRA_OK;
}

/// <summary>
/// 接收、处理操作系统的服务控制响应函数入口
/// </summary>
/// <param name="opcode"></param>
/// <returns></returns>
void WINAPI HraSrvCtrlHandlerFun(DWORD opcode)
{
    switch (opcode)
    {
    case SERVICE_CONTROL_STOP:
    {
        LOG_INFO("Receive service control signal:%lu(Stop)!", SERVICE_CONTROL_STOP);
        if (g_HraStopEvent)
        {
            SetEvent(g_HraStopEvent);
        }
        g_slFinished = MAINLOOP_FINISHED;
        //ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
    }
    break;
    case SERVICE_CONTROL_SHUTDOWN:
    {
        LOG_INFO("Receive service control signal:%lu(Shutdown)!", SERVICE_CONTROL_SHUTDOWN);
        if (g_HraStopEvent)
        {
            SetEvent(g_HraStopEvent);
        }
        g_slFinished = MAINLOOP_FINISHED;
        //ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
    }
    break;
    default:
        LOG_INFO("Receive service control signal:%lu! Ignore!", opcode);
        break;
    }
}



/// <summary>
/// hra Windows服务初始化
/// </summary>
/// <returns></returns>
int HraWinSrvInit(const wchar_t* pServiceName)
{
    //调用RegisterServiceCtrlHandler函数去通知SCM它的CtrlHandler回调函数的地址：
    g_ServiceStatusHandle = RegisterServiceCtrlHandler(pServiceName, HraSrvCtrlHandlerFun);
    if (g_ServiceStatusHandle == (SERVICE_STATUS_HANDLE)0)
    {
        LOG_ERROR("Service_Main call RegisterServiceCtrlHandler() failed, error=%lu", GetLastError());
        return HRA_FAILED;
    }
    LOG_INFO("HraSrvMainFun been invoked.");

    g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_ServiceStatus.dwServiceSpecificExitCode = 0;

    //报告初始状态给SCM
    //ReportStatusToSCMgr(SERVICE_START_PENDING, NO_ERROR, 3000);

    //创建等待服务结束请求的事件
    SECURITY_ATTRIBUTES Sa = {0};
    SECURITY_DESCRIPTOR Sd = {0};
    if ((!InitializeSecurityDescriptor(&Sd, SECURITY_DESCRIPTOR_REVISION)) ||
        !SetSecurityDescriptorDacl(&Sd, TRUE, (PACL)NULL, FALSE))
    {
        LOG_ERROR("Service_Main call CreateEvent() failed, error=%lu", GetLastError());
        //ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
        return HRA_FAILED;
    }
    Sa.nLength = sizeof(Sa);
    Sa.lpSecurityDescriptor = &Sd;
    Sa.bInheritHandle = FALSE;
    wchar_t szEvent[MAX_PATH];
    _snwprintf_s(szEvent, MAX_PATH, L"%ls_%ls", REQUEST_STOP_HRAGENT_EVENT, pServiceName);
    g_HraStopEvent = CreateEvent(&Sa, FALSE, FALSE, szEvent);
    if (!g_HraStopEvent)
    {
        LOG_ERROR("Create Hra stop event failed, error=%lu", GetLastError());
        //ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
        return HRA_FAILED;
    }
    //报告运行状态给SCM
    //ReportStatusToSCMgr(SERVICE_RUNNING, NO_ERROR, 0);
    return HRA_OK;
}

int HraWinSrvDeinit()
{
    if (g_HraStopEvent)
    {
        CloseHandle(g_HraStopEvent);
        g_HraStopEvent = NULL;
    }
    ReportStatusToSCMgr(SERVICE_STOPPED, NO_ERROR, 0);
    g_ServiceStatusHandle = NULL;
    LOG_INFO("HraWinSrvDeinit finished!");
    return HRA_OK;
}

/// <summary>
/// 向Windows服务管理器报告当前服务状态
/// </summary>
/// <param name="dwCurrentState"></param>
/// <param name="dwWin32ExitCode"></param>
/// <param name="dwWaitHint"></param>
void ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint, DWORD dwControlsAccepted)
{
    static DWORD dwCheckPoint = 1;

    g_ServiceStatus.dwCurrentState = dwCurrentState;
    g_ServiceStatus.dwWin32ExitCode = dwWin32ExitCode;
    g_ServiceStatus.dwWaitHint = dwWaitHint;
    g_ServiceStatus.dwControlsAccepted = dwControlsAccepted;

    //如果状态为正在运行或已经停止，则checkpoit为0
    if ((dwCurrentState == SERVICE_RUNNING) || (dwCurrentState == SERVICE_STOPPED))
    {
        g_ServiceStatus.dwCheckPoint = 0;
    }
    else
    {
        g_ServiceStatus.dwCheckPoint = dwCheckPoint++;
    }

    //向服务管理器报告当前状态
    if (!SetServiceStatus(g_ServiceStatusHandle, &g_ServiceStatus))
    {
        LOG_ERROR("SetServiceStatus failed! return error code = %lu, State:%lu, ExitCode:%lu, WaitHint:%lu, "
                  "ControlsAccepted:%lu",
                  GetLastError(), dwCurrentState, dwWin32ExitCode, dwWaitHint, dwControlsAccepted);
    }
    else
    {
        LOG_INFO("SetServiceStatus succeed! State:%lu, ExitCode:%lu, WaitHint:%lu, ControlsAccepted:%lu",
                 dwCurrentState, dwWin32ExitCode, dwWaitHint, dwControlsAccepted);
    }
}

/// <summary>
/// 向DSA发送注册信息
/// </summary>
/// <param name=""></param>
/// <returns></returns>
int HraRegsterInfo(void)
{
	int lRet = HRA_FAILED;
	/* 获取注册信息 */
	std::string strRegsterInfo = GetRegsterInfo();
	LOG_INFO("Registration information len:%u, str:%s", (unsigned int)(strRegsterInfo.length()), strRegsterInfo.c_str());

	unsigned int ulTryCnt = 0;
	while (!g_slFinished)
	{
		ulTryCnt++;
        CReportInfo cReportInfo;    /* 生成上报对象*/
		lRet = cReportInfo.Request(HraMsgHead::MsgType::REGISTER, AGENT_REG_INFO, strRegsterInfo.c_str(),strRegsterInfo.size());
		if (lRet != HRA_OK)
		{
			LOG_ERROR("Hra regster info connect failed, retry %u", ulTryCnt);
			::Sleep(5*1000);
			continue;
		}
        else
        {
            break;
        }
	}

    LOG_INFO("Hra regster info end.");
	return lRet; 
}
