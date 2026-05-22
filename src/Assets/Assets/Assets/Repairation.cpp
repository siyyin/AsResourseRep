// Reparation.cpp : Defines the entry point for the console application.
//
#include "Repairation.h"
#include <Shlwapi.h>
#include "StringUtils.h"
#include "LogManager.h"
#include "DIUtils.h"

#pragma comment(lib, "shlwapi.lib")
namespace di_rest_client
{
Repairation::Repairation(void):
  m_hRead1(NULL),
	m_hWrite1(NULL),
	m_hRead2(NULL),
	m_hWrite2(NULL),
	m_hCmd(NULL),
	m_dwPid(0),
  m_iProcess(0)
{
}

Repairation::~Repairation(void) {}

bool Repairation::Init(unsigned short int iProcess){
  m_iProcess = iProcess;

	int ret;
	SECURITY_ATTRIBUTES sa;
	sa.nLength = 12;
	sa.lpSecurityDescriptor = 0;
	sa.bInheritHandle = true;
	ret = CreatePipe(&m_hRead1, &m_hWrite1, &sa, 0);
	if (ret == 0)
		return false;

	ret = CreatePipe(&m_hRead2, &m_hWrite2, &sa, 0);
	if (ret == 0)
		return true;

	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.dwFlags = STARTF_USESHOWWINDOW|STARTF_USESTDHANDLES;
	si.wShowWindow = SW_SHOW;//SW_HIDE
	si.hStdInput = m_hRead2;
	si.hStdOutput = si.hStdError = m_hWrite1;
	wchar_t cmdLine[] = L"cmd";
	PROCESS_INFORMATION ProcessInformation;
	ret = CreateProcess(NULL, (LPWSTR)cmdLine, NULL, NULL, 1, 0, NULL, NULL, &si, &ProcessInformation);
	if (ret == 0)
		return false;

	m_hCmd = ProcessInformation.hProcess;
	m_dwPid = ProcessInformation.dwProcessId;
	TCHAR szPid[16] = {0};
	wsprintf(szPid, L"%d", m_dwPid);

	DoCmd("cd /d c:/", std::string(""));  // 初始化工作目录
	return true;
}

int Repairation::WriteCMD(char* cmdBuffer, HANDLE hWritePipe){
	DWORD lBytesWrite;
	char cmd_tmp[1024] = {0};
	DWORD dwRetCode;
	if (GetExitCodeProcess(m_hCmd, &dwRetCode)){
		if (dwRetCode != STILL_ACTIVE)
			return -1;
	}
	_snprintf_s(cmd_tmp, sizeof(cmd_tmp)-1, "%s%s", cmdBuffer, "\r\n");
	if (!WriteFile(hWritePipe, (LPTSTR)cmd_tmp, (DWORD)strlen(cmd_tmp), &lBytesWrite, NULL))
		return -1;

	return 0;
}

/*
int Repairation::ReadCMD(HANDLE hReadPipe, string &cmdResult){
	BOOL ret;
	DWORD lBytesRead;
	char buffer[1024] = {0};
	DWORD dwRetCode;
	Sleep(100);
	if (GetExitCodeProcess(m_hCmd, &dwRetCode)){
		if (dwRetCode != STILL_ACTIVE)
			return -1;
	}
	while (true){
		Sleep(1);
		ret = ReadFile(hReadPipe, buffer, 1023, &lBytesRead, 0);
		if (ret == 0)
			return -1;
		buffer[lBytesRead] = 0;
		cmdResult += buffer;
		if(buffer[lBytesRead-1] == '>'){   // 增加判断条件
			std::string strDir = buffer;
			if (strDir.rfind("\r\n") != std::string::npos){
				strDir = strDir.substr(strDir.rfind("\r\n")+2);
			}

			if (strDir.find(">") != std::string::npos)
				strDir = strDir.substr(0, strDir.find(">"));
			if (PathIsDirectory(di_rest_client::StringToWchar(strDir).data()))
				return 0;
		}
		memset(buffer, 0, 1024);
	}
	return 0;
}
*/

typedef struct{
	HANDLE hReadPipe;
	std::string strCmdReslut;
	HANDLE hCmd;
	DWORD dwRetValue;
}THREADPARANODE;

DWORD WINAPI MyThreadFunction(LPVOID lpParam)
{
	BOOL ret;
	DWORD lBytesRead;
	char buffer[1024] = {0};
	DWORD dwRetCode;
	THREADPARANODE* pThreadParam = (THREADPARANODE*)lpParam;
	Sleep(100);
	if (GetExitCodeProcess(pThreadParam->hCmd, &dwRetCode)){
		if (dwRetCode != STILL_ACTIVE){
			pThreadParam->dwRetValue = -1;
			return -1;
		}
	}
	while (true){
		Sleep(1); 
		ret = ReadFile(pThreadParam->hReadPipe, buffer, 1023, &lBytesRead, 0);
		if (ret == 0){
			pThreadParam->dwRetValue = -1;
			return -1;
		}
		buffer[lBytesRead] = 0;
		pThreadParam->strCmdReslut += buffer;
		if(buffer[lBytesRead-1] == '>'){   // 增加判断条件
			std::string strDir = buffer;
			if (strDir.rfind("\r\n") != std::string::npos){
				strDir = strDir.substr(strDir.rfind("\r\n")+2);
			}

			if (strDir.find(">") != std::string::npos)
				strDir = strDir.substr(0, strDir.find(">"));
			if (PathIsDirectory(StringToUnicode(strDir).data())){
				pThreadParam->dwRetValue = 0;
				return 0;
			}
		}
		memset(buffer, 0, 1024);
	}
	return -1;
}

bool Repairation::DoCmd(char *pCmd, string &cmdResult){
	bool bRet = false;

	if (WriteCMD(pCmd, m_hWrite2) < 0){
		FreeAll();
		if (Init()){
			if (WriteCMD(pCmd, m_hWrite2) < 0)
				return false;
		}
		else
			return false;
	}

	THREADPARANODE* pThreadParam = new THREADPARANODE;
	pThreadParam->hReadPipe = m_hRead1;
	pThreadParam->hCmd = m_hCmd;
	DWORD dwTreadID;
	HANDLE hReadThread = CreateThread( 
		NULL,   
		0,
		MyThreadFunction,
		pThreadParam,
		0, 
		&dwTreadID);

	DWORD dwRet = WaitForSingleObject(hReadThread, 3000);  // 等待最长3秒
	switch (dwRet)
	{
	case WAIT_OBJECT_0:
		if (pThreadParam->dwRetValue < 0){
			FreeAll();
			Init();
		}
		else{
			cmdResult = pThreadParam->strCmdReslut;
			bRet = true;
		}
		break;
	case WAIT_TIMEOUT:
		TerminateThread(hReadThread, 0);    // 线程执行超时，终止线程
		break;
	default:
		break;
	}

	if (pThreadParam){
		delete pThreadParam;
		pThreadParam = NULL;
	}

  CloseHandle(hReadThread);

	return bRet;
}

bool Repairation::FreeAll()
{
	if (m_hRead1 != NULL){
		CloseHandle(m_hRead1);
		m_hRead1 = NULL;
	}

	if (m_hWrite1!=NULL){
		CloseHandle(m_hWrite1);
		m_hWrite1 = NULL;
	}

	if (m_hRead2!=NULL){
		CloseHandle(m_hRead2);
		m_hRead2 = NULL;
	}

	if (m_hWrite2!=NULL){
		CloseHandle(m_hWrite2);
		m_hWrite2 = NULL;
	}

	if (m_hCmd!=NULL){
		TerminateProcess(m_hCmd, 0);
		CloseHandle(m_hCmd);
		m_hCmd = NULL;
		m_dwPid = 0;
	}

	return true;
}

DWORD Repairation::GetPid()
{
	return m_dwPid;
}
}