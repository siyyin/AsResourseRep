// APPINFO.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "AppInfo.h"

int _tmain(int argc, _TCHAR* argv[])
{

  while (true) {
      //应用信息
      AppInfo *pAppInfo = new AppInfo( );
      std::string report = pAppInfo->GetAppInfo();

      //测试调试
      int i = 0;
      wchar_t tempFilePath[MAX_PATH] = {0};
      swprintf_s(tempFilePath, MAX_PATH, L"%d.tempreport", i);
      i++;
      HANDLE hTempTokenFile = CreateFile(tempFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (hTempTokenFile != INVALID_HANDLE_VALUE) {
        DWORD dwWritenSize = 0;
        BOOL bRet = WriteFile(hTempTokenFile, report.c_str(), (DWORD)report.length(),
          &dwWritenSize, NULL);
        FlushFileBuffers(hTempTokenFile);
        CloseHandle(hTempTokenFile);
      }

      if (pAppInfo!=NULL)
      {
        delete pAppInfo;
        pAppInfo = NULL;
      }
      Sleep(1);
  }

 
	return 0;
}

