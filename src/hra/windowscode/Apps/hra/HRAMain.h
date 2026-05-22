#ifndef HRAMain_h__
#define HRAMain_h__

#include <stdio.h>
#include <string>
#include <Windows.h>

//extern volatile int g_slFinished;

struct InputParamater
{
    std::string strUUID;
    std::string strProIpcName;
    std::string strHraIpcName;
    std::string strServiceName;
    std::string strDataDir;

    void clear()
    {
        strUUID.clear();
        strProIpcName.clear();
        strHraIpcName.clear();
        strServiceName.clear();
        strDataDir.clear();
    }

    InputParamater()
    {
        clear();
    }
};

//以下三个函数只有hra.cpp调用
//整个程序的主流程
int HraAppInit();
int HraAppRun();
int HraAppEnd();


int CheckProcRun();//检查程序是否已经在运行
void SetWorkingDirectory();
int ParseCmdParam(struct InputParamater* stInputPara, DWORD argc, LPCWSTR* wargv);
int HraInitLog(const wchar_t* wszSrvName);
int HraUnInitLog(void);

///////////////////////////下方为win service函数
void WINAPI HraSrvMainFun(DWORD argc, LPCWSTR* argv);
void WINAPI HraSrvCtrlHandlerFun(DWORD opcode);
int HraSrvInit(DWORD argc, LPCWSTR* argv);
int HraSrvEnd();

void ReportStatusToSCMgr(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwWaitHint,
                         DWORD dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP);
int HraWinSrvInit(const wchar_t* pServiceName);//Windows服务初始化
int HraWinSrvDeinit();//Windows服务反初始化
int HraRegsterInfo(void);
//int HraInitConfigSave();
int InitGlobalConfigSave(struct InputParamater *stInputPara);

#endif // HRAMain_h__
