// Assets.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include "Assetsinventory.h"
#include "Repairation.h"
#include "LogManager.h"

di_rest_client::Repairation *g_pRepairation=NULL;

int _tmain(int argc, _TCHAR* argv[])
{
  //命令
  if (g_pRepairation == NULL){
    g_pRepairation = new Repairation;
    if (!g_pRepairation)
      return 0;
    g_pRepairation->Init(0);
  }

  //日志
  if (!g_debugLogObj){
    g_debugLogObj = new (std::nothrow) CLogManagerDebugLog();
    if (!g_debugLogObj) {
      printf("Cannot create log.");
      return 1;
    }
    char szDebugLogPath[MAX_PATH] = ".\\assets.log";
    g_debugLogObj->Initialize(szDebugLogPath);
  }
  g_debugLogObj->SetDebugLevel(LOG_LEVEL_INFO);

  INT rc;
  WSADATA wsaData;
  rc = WSAStartup(MAKEWORD(2, 2), &wsaData);
  if (rc) {
    DI_LOG_DEBUG("wss: WSAStartup Failed.\n");
    return 1;
  }


  //资产 
  Assetsinventory *pAssetsinventory = new Assetsinventory("10.21.144.41","123123123124124","1.0.1015");//ip和deviceid,客户端版本号
  int i = 0;
  std::string sDeviceID;
  while (true) {
      pAssetsinventory->GetApplicationinfo();
      pAssetsinventory->GetAssetInfor();
      std::string json = pAssetsinventory->ConvertToJson();

      //测试调试
      wchar_t tempFilePath[MAX_PATH] = {0};
      swprintf_s(tempFilePath, MAX_PATH, L"%d.tempreport", i);
      i++;
      HANDLE hTempTokenFile = CreateFile(tempFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
      if (hTempTokenFile != INVALID_HANDLE_VALUE) {
        DWORD dwWritenSize = 0;
        BOOL bRet = WriteFile(hTempTokenFile, json.c_str(), (DWORD)json.length(),
          &dwWritenSize, NULL);
        FlushFileBuffers(hTempTokenFile);
        CloseHandle(hTempTokenFile);
      }

      pAssetsinventory->m_bFirstUpLoadAsserts = false;//第一次上报成功后

     // Sleep(30000);
    //Sleep(1000);
  }


  if (g_pRepairation != NULL){
    g_pRepairation->FreeAll();
    delete g_pRepairation;
    g_pRepairation = NULL;
  }

  WSACleanup();

	return 0;
}

