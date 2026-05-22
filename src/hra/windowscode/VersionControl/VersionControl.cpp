#include <windows.h>
#include <wchar.h>
#include <string>
#include <stdio.h>
#include "utility/version.hpp"
#include "HraIpcInterface/HraIpcCommDef.h"

#define MAX_LEN_32 32
#define MAX_LEN_64 64
#define MAX_LEN_1024 1024

int main()
{
    char scAppVersion[MAX_LEN_64];
    char scBuildVersion[MAX_LEN_64];
    char scIpcInterfaceVersion[MAX_LEN_64];
    char scTemp[MAX_LEN_1024];
	  wchar_t tempFilePath[MAX_PATH] = {0};

	  _snprintf_s(scAppVersion, sizeof(scAppVersion), "app_version = \"%d.%d.%d\"", HRA_VER_MAJOR, HRA_VER_MINOR,
                  HRA_VER_PATCH);
      _snprintf_s(scBuildVersion, sizeof(scBuildVersion), "build_version = \"%d\"", HRA_VER_BUILD);
      _snprintf_s(scIpcInterfaceVersion, sizeof(scIpcInterfaceVersion), "ipc_interface_version = \"%d\"",
                  HRA_IPC_INTERFACE_VERSION);
      _snprintf_s(scTemp, sizeof(scTemp), "%s\n%s\n%s", scAppVersion, scBuildVersion, scIpcInterfaceVersion);

      std::string strWriteVersionToFile = scTemp;
      
	  //写入版本信息到version.ini
      swprintf_s(tempFilePath, MAX_PATH, L"%s", "version.ini");
      HANDLE hTempTokenFile = CreateFile((const char*)tempFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

      if (hTempTokenFile != INVALID_HANDLE_VALUE) {
        DWORD dwWritenSize = 0;
        BOOL bRet = WriteFile(hTempTokenFile, strWriteVersionToFile.c_str(), (DWORD)strWriteVersionToFile.size(),
								&dwWritenSize, NULL);

        FlushFileBuffers(hTempTokenFile);
        CloseHandle(hTempTokenFile);
      }

	//system("pause");
	return 0;
}