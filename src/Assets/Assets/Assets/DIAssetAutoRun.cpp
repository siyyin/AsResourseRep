#include "DIAssetAutoRun.h"
#include "LogManager.h"
#include "StringUtils.h"
#include "DIUtils.h"
#include <strsafe.h>
#include <Shlwapi.h>
#include <shlobj.h>

#define MAX_KEY_LENGTH 255
#define MAX_VALUE_NAME 16383
#define MAX_BUFSIZE 1 * 1024 *1024

namespace di_rest_client
{
	std::map<std::string, DIAssetAutoRunItem> g_map_autorun_table;
	DIAssetAutoRun::DIAssetAutoRun(void)
	{
	}


	DIAssetAutoRun::~DIAssetAutoRun(void)
	{
		g_map_autorun_table.clear();
	}

	void DIAssetAutoRun::InitAutoRunRegList()
	{
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE,L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
	}

	void DIAssetAutoRun::InitAutoRunRegList32()
	{
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE,L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunServices"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_CURRENT_USER, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
		m_list_reg_autorun_table.push_back(RegPathItem(HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx"));
	}

	std::map<std::string, DIAssetAutoRunItem>& DIAssetAutoRun::GetDIAssetAutoRunList()
	{
		return g_map_autorun_table;
	}

  BOOL DIAssetAutoRun::GetLnkFileName(PWSTR pLnkName, PWSTR OepnFileNameBuufer, DWORD OpenFileNameBufferSize)
  {
    CoInitialize(0);
    BOOL bRet = FALSE; //返回值判断.
    IShellLinkW* shlink = 0;
    IPersistFile* persist = 0;
    WIN32_FIND_DATA wfd;

    if (NULL == OepnFileNameBuufer){
      DI_LOG_DEBUG("DIAssetAutoRun::GetLnkFileName: OepnFileNameBuufer is NULL");
      return FALSE;
    }

    HRESULT hr = CoCreateInstance(CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, IID_IShellLinkW, (void**)&shlink);
    if (SUCCEEDED(hr)) {
      hr = shlink->QueryInterface(IID_IPersistFile, (void**)&persist);
      if (SUCCEEDED(hr)) {
        hr = persist->Load(pLnkName, STGM_READ);
        if (SUCCEEDED(hr)) {    
          hr = shlink->GetPath(OepnFileNameBuufer, OpenFileNameBufferSize, &wfd, SLGP_RAWPATH);
        }
        persist->Release();
      }
      shlink->Release();
    }

    CoUninitialize();
    return TRUE; 
  }

	void DIAssetAutoRun::QueryKey(HKEY & hKey, std::string& strKeyPath)
  {
    //TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name
    DWORD    cbName = MAX_KEY_LENGTH;                   // size of name string
    TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name
    DWORD    cchClassName = MAX_PATH;  // size of class string
    DWORD    cSubKeys=0;               // number of subkeys
    DWORD    cbMaxSubKey;              // longest subkey size
    DWORD    cchMaxClass;              // longest class string
    DWORD    cValues;              // number of values for key
    DWORD    cchMaxValue;          // longest value name
    DWORD    cbMaxValueData;       // longest value data
    DWORD    cbSecurityDescriptor; // size of security descriptor
    FILETIME ftLastWriteTime;      // last write time
    DWORD i, retCode;
    //LONG lRet;
    TCHAR achValue[MAX_VALUE_NAME];
    DWORD cchValue = MAX_VALUE_NAME;
    DWORD dwRegType = REG_SZ;
    DWORD dwSize = sizeof(DWORD);
    DWORD dwType;
    retCode = RegQueryInfoKey(
      hKey,                    // key handle
      achClass,                // buffer for class name
      &cchClassName,           // size of class string
      NULL,                    // reserved
      &cSubKeys,               // number of subkeys
      &cbMaxSubKey,            // longest subkey size
      &cchMaxClass,            // longest class string
      &cValues,                // number of values for this key
      &cchMaxValue,            // longest value name
      &cbMaxValueData,         // longest value data
      &cbSecurityDescriptor,   // security descriptor
      &ftLastWriteTime);       // last write time
    // Enumerate the subkeys, until RegEnumKeyEx fails.
    if (cValues){
      DI_LOG_DEBUG("DIAssetAutoRun::QueryKey: Number of values: %d\n", cValues);
      for (i=0, retCode=ERROR_SUCCESS; i<cValues; i++)
      {
        cchValue = MAX_VALUE_NAME;
        achValue[0] = '\0';
        //unsigned char vari[70];
        retCode = RegEnumValue(hKey, i,
          achValue,
          &cchValue,
          NULL,
          NULL,
          NULL,
          NULL);
        if (retCode == ERROR_SUCCESS){
          TCHAR szBuffer[MAX_VALUE_NAME] = { 0 };
          DWORD dwNameLen = MAX_VALUE_NAME;
          DIAssetAutoRunItem reg_velue_item;
          reg_velue_item.strAutoRunName = "--";
          reg_velue_item.strAutoRunState = "--";
          reg_velue_item.strRegValue = "--";
          reg_velue_item.strBinPath = "--";
          reg_velue_item.strPublisher = "--";
          reg_velue_item.strRegType = "--";
          reg_velue_item.strUser = "--";
          reg_velue_item.strPid = "--";
          reg_velue_item.strRegPath = "--";
          std::string strTmp;
          std::string strAutoRunProductName;
          std::string strAutoRunDescription;
          std::string strAutoRunCompanyName;
          std::string strAutoRunName;
          DWORD rQ = RegQueryValueEx(hKey, achValue, 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
          strTmp = UnicodeToUtf8String(achValue);    // 自启动项名称
          if (!strTmp.empty())
            strAutoRunName = strTmp;

          switch ((int)dwType)  // 自启动项注册表类型
          {
          case REG_NONE:
            reg_velue_item.strRegType = ansi_to_utf8("REG_NONE");
            break;
          case REG_SZ:
            reg_velue_item.strRegType = ansi_to_utf8("REG_SZ");
            break;
          case REG_EXPAND_SZ:
            reg_velue_item.strRegType = ansi_to_utf8("REG_EXPAND_SZ");
            break;
          case REG_BINARY:
            reg_velue_item.strRegType = ansi_to_utf8("REG_BINARY");
            break;
          case REG_DWORD:
            reg_velue_item.strRegType = ansi_to_utf8("REG_DWORD");
            break;
          case REG_MULTI_SZ:
            reg_velue_item.strRegType = ansi_to_utf8("REG_MULTI_SZ");
            break;
          default:
            break;
          }

          strTmp = WcharToString(szBuffer);    // 自启动项命令行
          if (!strTmp.empty())
            reg_velue_item.strRegValue = strTmp;

          if (reg_velue_item.strRegValue.find(".exe") != std::string::npos){
            strTmp = reg_velue_item.strRegValue.substr(0, reg_velue_item.strRegValue.find(".exe")+4);
            if (strTmp[0] == '"')
              strTmp = strTmp.substr(1);
          }
          else{
            strTmp = reg_velue_item.strRegValue.substr(0, reg_velue_item.strRegValue.find(".EXE")+4);
            if (strTmp[0] == '"')
              strTmp = strTmp.substr(1);
          }

          if(!strTmp.empty()){
            if (strTmp.find("%") != std::string::npos){
              wchar_t szTempPath[MAX_PATH] = {0};
              DWORD dwRet = ExpandEnvironmentStrings(StringToUnicode(strTmp).data(), szTempPath, MAX_PATH - 1);
              if (dwRet != 0){
                reg_velue_item.strBinPath = WcharToString(szTempPath);
              }
            }
            else
              reg_velue_item.strBinPath = strTmp;

            reg_velue_item.strAutoRunState = ansi_to_utf8("1");   // 自启动项默认状态都是启动

            strAutoRunProductName = GetFileProductName(StringToUnicode(utf8_to_ansi(reg_velue_item.strBinPath.data())).data());
            strAutoRunDescription = GetFileDescription(StringToUnicode(utf8_to_ansi(reg_velue_item.strBinPath.data())).data());
            strAutoRunCompanyName = GetFileCompanyName(StringToUnicode(utf8_to_ansi(reg_velue_item.strBinPath.data())).data());

            if (!strAutoRunCompanyName.empty())
              reg_velue_item.strPublisher = strAutoRunCompanyName;   // 发布商

            if (!strKeyPath.empty())
              reg_velue_item.strRegPath = strKeyPath;   // 注册表路径

            /*
            *  这里需要根据不同系统来展示，来实现与windows启动菜单一致
            *  (1) winxp：二进制程序的名称
            *  (2) win7： 二进制程序属性中的产品名称
            *  (3) win10: 二进制程序属性中的描述
            */
            do {
              if (IsWinXPOrFormer()){   // winxp
                size_t pS = reg_velue_item.strBinPath.rfind("\\") + 1;
                size_t pE = reg_velue_item.strBinPath.rfind(".");
                if (pS != std::string::npos && pE != std::string::npos){
                  reg_velue_item.strAutoRunName = reg_velue_item.strBinPath.substr(pS, pE-pS);
                }
                else
                  reg_velue_item.strAutoRunName = strAutoRunName;
                break;
              }

              if (IsWin7OrWin08()){  // win7
                if (strAutoRunProductName.empty()){
                  reg_velue_item.strAutoRunName = strAutoRunName;
                }
                else
                  reg_velue_item.strAutoRunName = strAutoRunProductName;
                break;
              }

              if (IsWin8OrLater()){  // win8以上
                if (strAutoRunDescription.empty()){
                  size_t pS = reg_velue_item.strBinPath.rfind("\\");
                  if (pS != std::string::npos){
                    reg_velue_item.strAutoRunName = reg_velue_item.strBinPath.substr(pS + 1);
                  }
                  else
                    reg_velue_item.strAutoRunName = strAutoRunName;
                }
                else
                  reg_velue_item.strAutoRunName = strAutoRunDescription;
                break;
              }
            }while(false);

            std::string strKey = reg_velue_item.strAutoRunName + ":" + reg_velue_item.strRegValue;      // 类型和版本作为Key
            if (g_map_autorun_table.find(strKey) == g_map_autorun_table.end())
              g_map_autorun_table.insert(make_pair(strKey, reg_velue_item)); 
          }
          Sleep(1);
        }
      }
    }
  }

	bool DIAssetAutoRun::InitDIAssetAutoRun()
	{
		g_map_autorun_table.clear();
		InitAutoRunRegList();
#ifdef _WIN64
		InitAutoRunRegList32();
#endif

		auto it = m_list_reg_autorun_table.begin();
		auto itEnd = m_list_reg_autorun_table.end();
		LPWSTR lpSid = NULL;
		if (GetCurrentUserSid(&lpSid)){
			for (; it != itEnd; it++)
			{
				// 打开注册表项
				HKEY hKey;
				std::string strKeyPath;
				if (it->m_hRootKey == HKEY_CLASSES_ROOT)
					strKeyPath = "HKEY_CLASSES_ROOT\\" + WcharToString(it->m_strKeyPath);
				if (it->m_hRootKey == HKEY_CURRENT_USER){
					strKeyPath = "HKEY_CURRENT_USER\\" + WcharToString(it->m_strKeyPath);
					std::wstring strKeyPosition = (std::wstring)lpSid + L"\\" + it->m_strKeyPath;
					if (RegOpenKeyEx(HKEY_USERS, strKeyPosition.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
						QueryKey(hKey, strKeyPath);
						RegCloseKey(hKey);
					}
					else
						DI_LOG_DEBUG("DIAssetAutoRun::InitDIAssetAutoRun: RegOpenKeyEx(%s) error: %d", UnicodeToString(it->m_strKeyPath).data(), GetLastError());
					continue;
				}
				if (it->m_hRootKey == HKEY_LOCAL_MACHINE){
					strKeyPath = "HKEY_LOCAL_MACHINE\\" + WcharToString(it->m_strKeyPath);
					if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, it->m_strKeyPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
						QueryKey(hKey, strKeyPath);
						RegCloseKey(hKey);
					}
					else
						DI_LOG_DEBUG("DIAssetAutoRun::InitDIAssetAutoRun: RegOpenKeyEx(%s) error: %d", it->m_strKeyPath.data(), GetLastError());
					continue;
				}
				if (it->m_hRootKey == HKEY_USERS)
					strKeyPath = "HKEY_USERS\\" + WcharToString(it->m_strKeyPath);
				if (it->m_hRootKey == HKEY_CURRENT_CONFIG)
					strKeyPath = "HKEY_CURRENT_CONFIG\\" + WcharToString(it->m_strKeyPath);

				Sleep(1);
			}
			LocalFree(lpSid);
		}

    // 初始化启动目录下的自启动项
    BOOL bRet = EnumStartup();

		return true;
	}

  bool DIAssetAutoRun::IsWinXPOrFormer()
  {
    OSVERSIONINFO osvi;
    bool bIsWindowsXPorLater;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    bIsWindowsXPorLater = (osvi.dwMajorVersion <= 5);
    return bIsWindowsXPorLater;
  }

  bool DIAssetAutoRun::IsWin7OrWin08()
  {
    OSVERSIONINFO osvi;
    bool bIsWin7OrWin08;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    bIsWin7OrWin08 = ( (osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion <= 1) );
    return bIsWin7OrWin08;
  }

  bool DIAssetAutoRun::IsWin8OrLater()
  {
    OSVERSIONINFO osvi;
    bool bIsWin8OrLater;
    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);
    bIsWin8OrLater = ( (osvi.dwMajorVersion > 6) ||
       ( (osvi.dwMajorVersion == 6) && (osvi.dwMinorVersion >= 2) ));
    return bIsWin8OrLater;
  }

  BOOL DIAssetAutoRun::EnumStartup()
  {
		// 获取当前用户启动项目录
    do{
      LPWSTR lpSid = NULL;
      if (!GetCurrentUserSid(&lpSid))
        return FALSE;
      std::wstring strKeyPosition = (std::wstring)lpSid + L"\\" + L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders";
      HKEY hKey;
      DWORD dwResult = RegOpenKeyEx(HKEY_USERS, 
        strKeyPosition.data(),
        0, 
        KEY_READ, 
        &hKey);
      if (ERROR_SUCCESS != dwResult) {
        DI_LOG_DEBUG("DIAssetAutoRun::EnumStartup: RegOpenKeyEx(%s) error: %d", strKeyPosition.data(), GetLastError());
        break;
      }

      wchar_t Buffer[512] = {0};
      DWORD cbSize = sizeof(Buffer);
      dwResult = RegQueryValueEx(hKey, L"Startup", NULL, NULL, (PUCHAR)Buffer, &cbSize);
      if (ERROR_SUCCESS != dwResult) {
        DI_LOG_DEBUG("DIAssetAutoRun::EnumStartup: RegQueryValueEx(%s) error: %d", "Startup", GetLastError());
        RegCloseKey(hKey);
        break;
      }

      RegCloseKey(hKey);

      wchar_t StartupDir[512] = {0};
      ExpandEnvironmentStrings(Buffer, StartupDir, sizeof(StartupDir) - 1);

      wchar_t Keyword[512] = {0};
      wcsncpy_s(Keyword, StartupDir, sizeof(Keyword) - 1);
      PathAddBackslash(Keyword);
      wcsncat_s(Keyword, L"*.lnk", sizeof(Keyword) - wcslen(Keyword)*sizeof(wchar_t) - 1);

      //枚举文件数量
      WIN32_FIND_DATA FindFileData;
      ZeroMemory(&FindFileData, sizeof( WIN32_FIND_DATA ));
      HANDLE hFind = FindFirstFile(Keyword, &FindFileData);
      if( hFind == INVALID_HANDLE_VALUE )
        break;

      DIAssetAutoRunItem reg_velue_item;
      reg_velue_item.strAutoRunName = "--";
      reg_velue_item.strAutoRunState = "--";
      reg_velue_item.strRegValue = "--";
      reg_velue_item.strBinPath = "--";
      reg_velue_item.strPublisher = "--";
      reg_velue_item.strRegType = "--";
      reg_velue_item.strUser = "--";
      reg_velue_item.strPid = "--";
      reg_velue_item.strRegPath = "--";

      do{
        if (wcsncmp(FindFileData.cFileName, L"..", 2) == 0 || wcsncmp(FindFileData.cFileName, L".", 1) == 0)
          continue;

        //判断是否目录
        if( FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
          continue;

        //获取文件全路径
        wchar_t LinkFile[512] = {0};
        reg_velue_item.strAutoRunName = UnicodeToUtf8String(FindFileData.cFileName);   // 启动项名称

        wcsncpy_s(LinkFile, StartupDir, sizeof( LinkFile ) - 1);
        PathAddBackslash(LinkFile);
        wcsncat_s(LinkFile, FindFileData.cFileName, sizeof(LinkFile) - wcslen(LinkFile)*sizeof(wchar_t) - 1);
        wchar_t szLinkPath[MAX_PATH] = {0};
        GetLnkFileName(LinkFile, szLinkPath, MAX_PATH);

        wchar_t szImagePath[MAX_PATH] = {0};
        GetLongPathName(szLinkPath, szImagePath, sizeof(szImagePath) - 1);
        reg_velue_item.strBinPath = UnicodeToUtf8String(szImagePath);   // 启动项命令行

        reg_velue_item.strRegPath = UnicodeToUtf8String(StartupDir);    // 启动路径

        std::string strFileCompanyName = GetFileCompanyName(StringToUnicode(reg_velue_item.strBinPath ).data());
        if (!strFileCompanyName.empty())
          reg_velue_item.strPublisher = strFileCompanyName;

        reg_velue_item.strAutoRunState = "1";

        std::string strKey = reg_velue_item.strAutoRunName + ":" + reg_velue_item.strRegValue;      // 类型和版本作为Key
        if (g_map_autorun_table.find(strKey) == g_map_autorun_table.end())
          g_map_autorun_table.insert(make_pair(strKey, reg_velue_item)); 
      }while( FindNextFile( hFind, &FindFileData ) != 0 );

      FindClose( hFind );
    }while(false);

    // 获取公共启动目录
    do{
      wchar_t Buffer[512] = {0};
      if(S_OK != SHGetFolderPath(NULL, CSIDL_COMMON_STARTUP, NULL, 0, Buffer)){
        DI_LOG_DEBUG("DIAssetAutoRun::EnumStartup: SHGetFolderPath(CSIDL_COMMON_STARTUP) error");
        break;
      }

      wchar_t StartupDir[512] = {0};
      ExpandEnvironmentStrings(Buffer, StartupDir, sizeof(StartupDir) - 1);

      wchar_t Keyword[512] = {0};
      wcsncpy_s(Keyword, StartupDir, sizeof(Keyword) - 1);
      PathAddBackslash(Keyword);
      wcsncat_s(Keyword, L"*.lnk", sizeof(Keyword) - wcslen(Keyword)*sizeof(wchar_t) - 1);

      //枚举文件数量
      WIN32_FIND_DATA FindFileData;
      ZeroMemory(&FindFileData, sizeof( WIN32_FIND_DATA ));
      HANDLE hFind = FindFirstFile(Keyword, &FindFileData);
      if( hFind == INVALID_HANDLE_VALUE )
        break;

      DIAssetAutoRunItem reg_velue_item;
      reg_velue_item.strAutoRunName = "--";
      reg_velue_item.strAutoRunState = "--";
      reg_velue_item.strRegValue = "--";
      reg_velue_item.strBinPath = "--";
      reg_velue_item.strPublisher = "--";
      reg_velue_item.strRegType = "--";
      reg_velue_item.strUser = "--";
      reg_velue_item.strPid = "--";
      reg_velue_item.strRegPath = "--";

      do{
        if (wcsncmp(FindFileData.cFileName, L"..", 2) == 0 || wcsncmp(FindFileData.cFileName, L".", 1) == 0)
          continue;

        //判断是否目录
        if( FindFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
          continue;

        //获取文件全路径
        wchar_t LinkFile[512] = {0};
        reg_velue_item.strAutoRunName = UnicodeToUtf8String(FindFileData.cFileName);   // 启动项名称

        wcsncpy_s(LinkFile, StartupDir, sizeof( LinkFile ) - 1);
        PathAddBackslash(LinkFile);
        wcsncat_s(LinkFile, FindFileData.cFileName, sizeof(LinkFile) - wcslen(LinkFile)*sizeof(wchar_t) - 1);
        wchar_t szLinkPath[MAX_PATH] = {0};
        GetLnkFileName(LinkFile, szLinkPath, MAX_PATH);

        wchar_t szImagePath[MAX_PATH] = {0};
        GetLongPathName(szLinkPath, szImagePath, sizeof(szImagePath) - 1);
        reg_velue_item.strBinPath = UnicodeToUtf8String(szImagePath);   // 启动项命令行

        reg_velue_item.strRegPath = UnicodeToUtf8String(StartupDir);    // 启动路径

        std::string strFileCompanyName = GetFileCompanyName(StringToUnicode(reg_velue_item.strBinPath ).data());
        if (!strFileCompanyName.empty())
          reg_velue_item.strPublisher = strFileCompanyName;

        std::string strAutoRunProductName = GetFileProductName(StringToUnicode(reg_velue_item.strBinPath ).data());

        std::string strAutoRunDescription = GetFileDescription(StringToUnicode(reg_velue_item.strBinPath ).data());

        reg_velue_item.strAutoRunState = "1";

        /*
        *  这里需要根据不同系统来展示，来实现与windows启动菜单一致
        *  (1) winxp：二进制程序的名称
        *  (2) win7： 二进制程序属性中的产品名称
        *  (3) win10: 二进制程序属性中的描述
        */
        do {
          if (IsWinXPOrFormer()){   // winxp
            size_t pS = reg_velue_item.strBinPath.rfind("\\") + 1;
            size_t pE = reg_velue_item.strBinPath.rfind(".");
            if (pS != std::string::npos && pE != std::string::npos){
              reg_velue_item.strAutoRunName = reg_velue_item.strBinPath.substr(pS, pE-pS);
            }
            break;
          }

          if (IsWin7OrWin08()){  // win7
            if (!strAutoRunProductName.empty()){
              reg_velue_item.strAutoRunName = strAutoRunProductName;
            }
            break;
          }

          if (IsWin8OrLater()){  // win8以上
            if (strAutoRunDescription.empty()){
              size_t pS = reg_velue_item.strBinPath.rfind("\\") + 1;
              if (pS != std::string::npos){
                reg_velue_item.strAutoRunName = reg_velue_item.strBinPath.substr(pS);
              }
            }
            else
              reg_velue_item.strAutoRunName = strAutoRunDescription;
            break;
          }
        }while(false);

        std::string strKey = reg_velue_item.strAutoRunName + ":" + reg_velue_item.strBinPath;   // 启动目录的key=strAutoRunName+strBinPath
        if (g_map_autorun_table.find(strKey) == g_map_autorun_table.end())
          g_map_autorun_table.insert(make_pair(strKey, reg_velue_item)); 
      }while( FindNextFile( hFind, &FindFileData ) != 0 );

      FindClose( hFind );
    }while(false);

    return TRUE;
  }

  std::string DIAssetAutoRun::GetFileCompanyName(const wchar_t *pszFilePath)
  {
    std::string strCompanyName;
    if (!pszFilePath)
      return strCompanyName;

    DWORD dwSize = GetFileVersionInfoSize(pszFilePath, NULL);
    if (dwSize != 0 ){
      if (dwSize + 1 >= MAX_BUFSIZE){
        DI_LOG_WARN("GetFileCompanyName malloc a large buffer.");
      }
      char *pBuf = new char[dwSize + 1];
      if (pBuf){
        memset(pBuf, 0, dwSize + 1);
        DWORD dwRtn = GetFileVersionInfo(pszFilePath, NULL, dwSize, pBuf); 
        if (dwRtn != 0){
          LPVOID lpBuffer = NULL;
          UINT uLen = 0;
          HRESULT hr;

          struct LANGANDCODEPAGE {
            WORD wLanguage;
            WORD wCodePage;
          }*lpTranslate;

          // Read the list of languages and code pages.
          UINT cbTranslate = 0;
          VerQueryValue(pBuf, 
            TEXT("\\VarFileInfo\\Translation"),
            (LPVOID*)&lpTranslate,
            &cbTranslate);

          for (int i=0; i < (int)(cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
          {
            wchar_t SubBlock[MAX_PATH] = {0};
            hr = StringCchPrintf(SubBlock, 50,
              TEXT("\\StringFileInfo\\%04x%04x\\CompanyName"),
              lpTranslate[i].wLanguage,
              lpTranslate[i].wCodePage);
            if (FAILED(hr)){
              break;
            }

            dwRtn = VerQueryValue(pBuf, SubBlock, &lpBuffer, &uLen); 
            if (dwRtn != 0){
              std::string strTmp = UnicodeToUtf8String(std::wstring((wchar_t*)lpBuffer, uLen));    // 获取发布商
              if (!strTmp.empty()){
                if ((strTmp.find("trend_company_name") != std::string::npos) || (strTmp.find("Trend Micro") != std::string::npos)){
                  strTmp = "Asiainfo Security";
                }

                strCompanyName = strTmp;
              }
            }
          }
        }
        if (pBuf)
          delete []pBuf;
      }
    }
    else{
      DI_LOG_DEBUG("DIAssetAutoRun::GetFileCompanyName error: %d\n", GetLastError());
    }

    return strCompanyName;
  }

  std::string DIAssetAutoRun::GetFileProductName(const wchar_t *pszFilePath)
  {
    std::string strProductName;
    if (!pszFilePath)
      return strProductName;

    DWORD dwSize = GetFileVersionInfoSize(pszFilePath, NULL);
    if (dwSize != 0 ){
      if (dwSize + 1 >= MAX_BUFSIZE){
        DI_LOG_WARN("GetFileProductName malloc a large buffer.");
      }
      char *pBuf = new char[dwSize + 1];
      if (pBuf){
        memset(pBuf, 0, dwSize + 1);
        DWORD dwRtn = GetFileVersionInfo(pszFilePath, NULL, dwSize, pBuf); 
        if (dwRtn != 0){
          LPVOID lpBuffer = NULL;
          UINT uLen = 0;
          HRESULT hr;

          struct LANGANDCODEPAGE {
            WORD wLanguage;
            WORD wCodePage;
          }*lpTranslate;

          // Read the list of languages and code pages.
          UINT cbTranslate = 0;
          VerQueryValue(pBuf, 
            TEXT("\\VarFileInfo\\Translation"),
            (LPVOID*)&lpTranslate,
            &cbTranslate);

          for (int i=0; i < (int)(cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
          {
            wchar_t SubBlock[MAX_PATH] = {0};
            hr = StringCchPrintf(SubBlock, 50,
              TEXT("\\StringFileInfo\\%04x%04x\\ProductName"),
              lpTranslate[i].wLanguage,
              lpTranslate[i].wCodePage);
            if (FAILED(hr)){
              break;
            }

            lpBuffer = NULL;
            dwRtn = VerQueryValue(pBuf, SubBlock, &lpBuffer, &uLen); 
            if (dwRtn != 0){
              std::string strTmp = UnicodeToUtf8String(std::wstring((wchar_t*)lpBuffer, uLen));
              if (!strTmp.empty()){
                if ((strTmp.find("Trend Micro") != std::string::npos)){
                  replace_all_distinct(strTmp, "Trend Micro", "Asiainfo Security");
                }

                if ((strTmp.find("trend_product_name") != std::string::npos)){
                  replace_all_distinct(strTmp, "trend_product_name", "Asiainfo Security");
                }

                strProductName = strTmp;
              }
            }
          }
        }
        if (pBuf)
          delete []pBuf;
      }
    }
    else{
      DI_LOG_DEBUG("DIAssetAutoRun::GetFileProductName error: %d\n", GetLastError());
    }

    return strProductName;
  }

  std::string DIAssetAutoRun::GetFileDescription(const wchar_t *pszFilePath)
  {
    std::string strFileDescription;
    if (!pszFilePath)
      return strFileDescription;

    DWORD dwSize = GetFileVersionInfoSize(pszFilePath, NULL);
    if (dwSize != 0 ){
      if (dwSize + 1 >= MAX_BUFSIZE){
        DI_LOG_WARN("GetFileDescription malloc a large buffer.");
      }
      char *pBuf = new char[dwSize + 1];
      if (pBuf){
        memset(pBuf, 0, dwSize + 1);
        DWORD dwRtn = GetFileVersionInfo(pszFilePath, NULL, dwSize, pBuf); 
        if (dwRtn != 0){
          LPVOID lpBuffer = NULL;
          UINT uLen = 0;
          HRESULT hr;

          struct LANGANDCODEPAGE {
            WORD wLanguage;
            WORD wCodePage;
          }*lpTranslate;

          // Read the list of languages and code pages.
          UINT cbTranslate = 0;
          VerQueryValue(pBuf, 
            TEXT("\\VarFileInfo\\Translation"),
            (LPVOID*)&lpTranslate,
            &cbTranslate);

          for (int i=0; i < (int)(cbTranslate/sizeof(struct LANGANDCODEPAGE)); i++ )
          {
            wchar_t SubBlock[MAX_PATH] = {0};
            hr = StringCchPrintf(SubBlock, 50,
              TEXT("\\StringFileInfo\\%04x%04x\\FileDescription"),
              lpTranslate[i].wLanguage,
              lpTranslate[i].wCodePage);
            if (FAILED(hr)){
              break;
            }

            lpBuffer = NULL;
            dwRtn = VerQueryValue(pBuf, SubBlock, &lpBuffer, &uLen); 
            if (dwRtn != 0){
              std::string strTmp = UnicodeToUtf8String(std::wstring((wchar_t*)lpBuffer, uLen));
              if (!strTmp.empty())
                strFileDescription = strTmp;
            }

          }
        }
        if (pBuf)
          delete []pBuf;
      }
    }
    else{
      DI_LOG_DEBUG("DIAssetAutoRun::GetFileDescription error: %d\n", GetLastError());
    }

    return strFileDescription;
  }
}