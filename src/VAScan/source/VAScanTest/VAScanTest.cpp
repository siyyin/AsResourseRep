// AttackIOTest.cpp : Defines the entry point for the console application.
//

#include <stdlib.h>
#include "../include/VAScan.h"
#ifdef _WIN32
#include <windows.h>
#include <iostream>
#include <fstream>
#include <sstream>
#else
#include <stdio.h>
#include <string.h>
#include <dlfcn.h> 
#include <iostream>
#include <fstream>
using namespace std;

#define FALSE false
typedef wchar_t     _TCHAR;

void _wfopen_s(FILE ** _File, const wchar_t* _Filename, const wchar_t * _Mode)
{
	char szFileName[260] = { 0 };
	char szOpenMode[8] = { 0 };
	wcstombs(szFileName, _Filename, wcslen(_Filename) * sizeof(wchar_t));
	wcstombs(szOpenMode, _Mode, 2 * sizeof(wchar_t));
	*_File = fopen(szFileName, szOpenMode);
}


void strncpy_s(char* _Dst, size_t _SizeInBytes, const char * _Src, size_t _MaxCount)
{
	strncpy(_Dst, _Src, _MaxCount);
}

#endif

#define MAX_LEN_1024       1024
//wchar_t * g_pwszPatternPath = L"akg$0100.1001";
const char * g_pwszPatternPath = "vatest.lua";

int main(int argc, char* argv[])
{

	// 初始化引擎
#ifndef _WIN32
	void* handle = dlopen("./libvaeng.so", RTLD_LAZY);
	if (!handle)
	{
		cout << dlerror() << endl;
		return -1;
	}

	// 提取接口
	typedef VA_SCAN_CONTEXT* (*PVAInitialize)(void);
	PVAInitialize VAInitialize = (PVAInitialize)dlsym(handle, "VAInitialize");
	if (!VAInitialize)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef bool(*PVALoadPattern)(VA_SCAN_CONTEXT* pScanContext, const char* strPatternFilePath);
	PVALoadPattern VALoadPattern = (PVALoadPattern)dlsym(handle, "VALoadPattern");
	if (!VALoadPattern)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef bool(*PVAExecuteScan)(VA_SCAN_CONTEXT* pScanContext, VA_SCAN_RESULT* &pScanResult);
	PVAExecuteScan VAExecuteScan = (PVAExecuteScan)dlsym(handle, "VAExecuteScan");
	if (!VAExecuteScan)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef bool(*PVAFreeScanResult)(VA_SCAN_RESULT* &pScanResult);
	PVAFreeScanResult VAFreeScanResult = (PVAFreeScanResult)dlsym(handle, "VAFreeScanResult");
	if (!VAFreeScanResult)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef void(*PVAUnInitialize)(VA_SCAN_CONTEXT* pScanContext);
	PVAUnInitialize VAUnInitialize = (PVAUnInitialize)dlsym(handle, "VAUnInitialize");
	if (!VAUnInitialize)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef bool(*PVAGetPatternVersion)(VA_SCAN_CONTEXT* pScanContext, char* OutVersion, int OutSize);
	PVAGetPatternVersion VAGetPatternVersion = (PVAGetPatternVersion)dlsym(handle, "VAGetPatternVersion");
	if (!VAGetPatternVersion)
	{
		cout << dlerror() << endl;
		return -1;
	}

	typedef bool(*PVAGetEngineVersion)(char* OutVersion, int OutSize);
	PVAGetEngineVersion VAGetEngineVersion = (PVAGetEngineVersion)dlsym(handle, "VAGetEngineVersion");
	if (!VAGetEngineVersion)
	{
		cout << dlerror() << endl;
		return -1;
	}
/*	
	typedef bool(*PIOAGetPatternVersion)(IOA_SCAN_CONTEXT *pScanContext, char * OutVersion, int OutSize);
	PIOAGetPatternVersion IOAGetPatternVersion = (PIOAGetPatternVersion)dlsym(handle, "IOAGetPatternVersion");
	if (!IOAGetPatternVersion)
	{
		cout << dlerror() << endl;
		return -1;
	}*/
#endif
	char strEngineVer[MAX_LEN_64] = {0};
	char strPatternVer[MAX_LEN_64] = {0};
	bool bRet = VAGetEngineVersion(strEngineVer, MAX_LEN_64);
	if (!bRet)
		return -1;
	printf("VAScan engine version: %s\n", strEngineVer);

	VA_SCAN_CONTEXT* pVAScanContext = VAInitialize();
	if (!pVAScanContext)
		return -1;

	// 加载Pattern
	bool bVALoadPatternRet = false;
	//如果指定pattern路径
	if (argc == 2)
	{
		printf("load Pattern %s\n", argv[1]);
		bVALoadPatternRet = VALoadPattern(pVAScanContext, argv[1]);
	}
	//如果未指定pattern路径，
	else
	{
		printf("load Pattern %s\n", g_pwszPatternPath);
		bVALoadPatternRet = VALoadPattern(pVAScanContext, g_pwszPatternPath);
	}
	if (!bVALoadPatternRet)
	{
		std::cout << "LOAD PATTERN FAILED |" << pVAScanContext->pszErrorMsg << std::endl;
		return -2;
	}
	printf("LoadPattern End\n");

	bRet = VAGetPatternVersion(pVAScanContext, strPatternVer, MAX_LEN_64);
    if (!bRet)
		return -1;
	printf("Load pattern version: %s\n", strPatternVer);

    VA_SCAN_RESULT* pVAScanResult = NULL;
    bool bVAScanEventRet = VAExecuteScan(pVAScanContext, pVAScanResult);
    if (!bVAScanEventRet || !pVAScanResult->strResult || !pVAScanResult->dwLen)
    {
      std::cout << "VAScanEvent() failed!!! ErrorCode: " <<  std::endl;
      return -3;
    }

    // 取出扫描结果
    char* pszResult = new char[pVAScanResult->dwLen + 1];
    memset(pszResult, 0, pVAScanResult->dwLen + 1);
    strncpy_s(pszResult, pVAScanResult->dwLen + 1, pVAScanResult->strResult, pVAScanResult->dwLen);

    // 释放内存
    bool bVAFreeScanResultRet = VAFreeScanResult(pVAScanResult);
    if (!bVAFreeScanResultRet)
    {
      std::cout << "VAFreeScanResult() failed!!! ErrorCode: " << pVAScanContext->pszErrorMsg << std::endl;
    }
    // 打印，解析扫描结果
    printf("Execute retsult: %s\n", pszResult);
    if (pszResult)
    {
      delete[] pszResult;
      pszResult = NULL;
    }

	// 恢复IOA引擎状态
	VAUnInitialize(pVAScanContext);

#ifndef _WIN32
	dlclose(handle);
#endif // !_WIN32
	return 0;
}