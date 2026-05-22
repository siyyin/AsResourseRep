// Reparation.cpp : Defines the entry point for the console application.
//
#pragma once

#include <windows.h>
#include <iostream>
#include <string>
using namespace std;

namespace di_rest_client
{
class Repairation
{
public:
	Repairation(void);
	~Repairation(void);

  bool Init(unsigned short int iProcess = 0);
	bool DoCmd(char *pCmd,string &cmdResult);
	bool FreeAll();
	DWORD GetPid();

private:
	int WriteCMD(char* cmdBuffer, HANDLE hWritePipe);
	//int ReadCMD(HANDLE hReadPipe, string &cmdResult);

private:
	HANDLE m_hRead1;
	HANDLE m_hWrite1;
	HANDLE m_hRead2;
	HANDLE m_hWrite2;
	HANDLE m_hCmd;
	DWORD m_dwPid;
  unsigned short int m_iProcess;
};
}