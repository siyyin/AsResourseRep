#include "DIAssetDB.h"
#include <windows.h>
#include <Shlwapi.h>
#include "DIUtils.h"
#include "StringUtils.h"
#include "LogManager.h"
#include "Repairation.h"
#include "NetUtils.h"
#include "DIAssetExceSql.h"

extern di_rest_client::Repairation *g_pRepairation;

namespace di_rest_client
{
	std::map<std::string, DIAssetDBItem> g_map_database_table;
	DIAssetDB::DIAssetDB(void)
	{
	}


	DIAssetDB::~DIAssetDB(void)
	{
		g_map_database_table.clear();
	}

	std::map<std::string, DIAssetDBItem>& DIAssetDB::GetDataBaseList(void)
	{
		return g_map_database_table;
	}

	bool DIAssetDB::InitAssetDataBase(void)
	{
		g_map_database_table.clear();
		bool bRet = GetOracleDBInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetDB::InitAssetDataBase: GetOracleDBInfo return false.");

		bRet = GetMySQLDBInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetDB::InitAssetDataBase: GetMySQLDBInfo return false.");

		bRet = GetSqlServerDBInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetDB::InitAssetDataBase: GetSqlServerDBInfo return false.");

		bRet = GetRedisDBInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetDB::InitAssetDataBase: GetRedisDBInfo return false.");

		bRet = GetPostgreSQLDBInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetDB::InitAssetDataBase: GetPostgreSQLDBInfo return false.");
		return true;
	}

	bool DIAssetDB::GetOracleDBInfo(void)
	{
		/** update: 2020-11-12
		*      1. 获取所有的tnslsnr.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本和多实例
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"tnslsnr.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetOracleDBInfo: process tnslsnr.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetDBItem dbItem;
			dbItem.strStatus = "--";
			dbItem.strUser = "--";
			dbItem.strType = "--";
			dbItem.strVersion = "--";
			dbItem.strBindIP = "--";
			dbItem.strPort = "0";    // 如果没有获取到端口，默认值给0
			dbItem.strDataPath = "--";
			dbItem.strConfPath = "--";
			dbItem.strLogPath = "--";
			dbItem.strDBBinaryFilePath = "--";

			std::string strTmp;

			dbItem.strStatus = ansi_to_utf8("1");                 // 运行状态
			dbItem.strType = ansi_to_utf8("oracle");  			// 数据库类型

			std::string strCmdResult;
			std::string strCmd = "lsnrctl.exe version";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				size_t pS = strCmdResult.find("Version");
				size_t pE = strCmdResult.find("Production");
				if (pS != std::string::npos && pE != std::string::npos){
					std::string  strDBVersion = strCmdResult.substr(pS, pE-pS);
					pS = strDBVersion.find(" ");
					pE = strDBVersion.find_last_of(".");
					strDBVersion = strDBVersion.substr(pS+1, pE-pS-1);
					strTmp = ansi_to_utf8(strDBVersion.data());        			// 版本
          if (!strTmp.empty() && IsVersionNumber(strTmp))
						dbItem.strVersion= strTmp;
				}
			}

			// 通过命令行来获取监听端口和IP地址
			strCmdResult.clear();
			strCmd.clear();
      strCmd = "netstat -nao | findstr " + type2str(*it);
      if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
        if (strCmdResult.find("TCP") != std::string::npos){
          strCmdResult = strCmdResult.substr(strCmdResult.find("TCP"));
          size_t pS = strCmdResult.find(":");
          if (pS != std::string::npos){
            strTmp = ansi_to_utf8(strCmdResult.substr(pS+1).data());       // 端口号
            strTmp = strTmp.substr(0, strTmp.find(" "));
            if (!strTmp.empty()){
              // 端口增加校验
              if (AllisNum(strTmp)){
                dbItem.strPort = strTmp;
              }
            }

            strTmp = ansi_to_utf8(strCmdResult.substr(strCmdResult.find("TCP")+3).data());       // 监听IPV4
            strTmp = strTmp.substr(strTmp.find_first_not_of(" "));
            strTmp = strTmp.substr(0, strTmp.find(":"));
            if (!strTmp.empty())
              dbItem.strBindIP = strTmp;

            pS = strCmdResult.find("[");             // 监听IPV6
            if (pS != std::string::npos){
              strTmp = strCmdResult.substr(pS);
              pS = strTmp.find(" ");
              if (strTmp.find(" ") != std::string::npos)
                strTmp = strTmp.substr(0, pS);
              if (strTmp.find(dbItem.strPort) != std::string::npos){
                size_t pE = strTmp.find("]");
                strTmp = ansi_to_utf8(strTmp.substr(1, pE-1).data());
                dbItem.strBindIP = dbItem.strBindIP + "," + strTmp;
              }
            }
          }
				}
			}

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					dbItem.strUser = UnicodeToUtf8String(strRunUser);    		// 获取运行用户
			}

			// 解析主版本，用于构造注册表路径从注册表读取信息
			std::string strMainVer;
			strMainVer = dbItem.strVersion.substr(0, dbItem.strVersion.find("."));

			// 通过注册表获取用户名
			std::string strSID;
			std::string strDBHomePath;    // 获取到主目录
			std::string strDBOracleBase;
			if (!strMainVer.empty()){
				std::wstring strRegPath = L"SOFTWARE\\ORACLE\\KEY_OraDB" + StringToUnicode(strMainVer) + L"Home1";
				HKEY hKey;                
				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, strRegPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
					TCHAR szBuffer[MAX_PATH] = { 0 };
					DWORD dwNameLen = MAX_PATH;
					DWORD dwType;
					DWORD rQ = RegQueryValueEx(hKey, L"ORACLE_SVCUSER", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
					strTmp = UnicodeToUtf8String(szBuffer);  // 通过注册表获取运行用户
					if (dbItem.strUser.empty() && (!strTmp.empty()))
						dbItem.strUser = strTmp;  // 通过注册表获取运行用户

					// Oracle SID
					memset(szBuffer, 0, MAX_PATH);
					dwNameLen = MAX_PATH;
					rQ = RegQueryValueEx(hKey, L"ORACLE_SID", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
					strTmp = UnicodeToUtf8String(szBuffer);
					if (!strTmp.empty())
						strSID = strTmp;

					// strDBOracleBase
					memset(szBuffer, 0, MAX_PATH);
					dwNameLen = MAX_PATH;
					rQ = RegQueryValueEx(hKey, L"ORACLE_BASE", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
					strTmp = UnicodeToUtf8String(szBuffer);
					if (!strTmp.empty())
						strDBOracleBase = strTmp;

					if ((!strDBOracleBase.empty()) && (!strSID.empty())){
						dbItem.strDataPath = strDBOracleBase + ansi_to_utf8("\\oradata\\") + strSID;   		       // 数据路径
						dbItem.strLogPath = strDBOracleBase + "\\diag\\rdbms\\" + strSID + "\\" + strSID + "\\trace\\alert_" + strSID + ".log";      // 获取日志文件路径
					}

					// Oracle Home
					memset(szBuffer, 0, MAX_PATH);
					dwNameLen = MAX_PATH;
					rQ = RegQueryValueEx(hKey, L"ORACLE_HOME", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
					strTmp = UnicodeToUtf8String(szBuffer);
					if (!strTmp.empty()){
						strDBHomePath = strTmp; 
						dbItem.strConfPath = strDBHomePath + ansi_to_utf8("\\network\\admin\\listener.ora");   		// 配置文件路径
					}

          RegCloseKey(hKey);
				}
				else
					DI_LOG_DEBUG("DIAssetDB::GetOracleDBInfo: open the key SOFTWARE\\ORACLE\\KEY_OraDB**Home1 filed!");
			}

			TCHAR szProcessName[MAX_PATH] = {0};
			if (GetProcessFullPath(*it, szProcessName)){
				strTmp = UnicodeToUtf8String(szProcessName);
				if (!strTmp.empty())
					dbItem.strDBBinaryFilePath = strTmp;             // 二进制文件路径
			}
			else
				DI_LOG_DEBUG("error: get mysqld.exe image path error.");

			std::string strKey = dbItem.strVersion + ":" + dbItem.strPort;      // 版本和端口作为Key
			if (g_map_database_table.find(strKey) == g_map_database_table.end())
				g_map_database_table.insert(make_pair(strKey, dbItem));    
		}

		Sleep(1);
		return true;
	}

	bool DIAssetDB::GetMySQLDBInfo(void)
	{
		/** update: 2020-11-12
		*      1. 获取所有的mysqld.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本和多实例
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"mysqld.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetMySQLDBInfo: process mysqld.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetDBItem dbItem;
			dbItem.strStatus = "--";
			dbItem.strUser = "--";
			dbItem.strType = "--";
			dbItem.strVersion = "--";
			dbItem.strBindIP = "--";
			dbItem.strPort = "0";
			dbItem.strDataPath = "--";
			dbItem.strConfPath = "--";
			dbItem.strLogPath = "--";
			dbItem.strDBBinaryFilePath = "--";

			std::string strTmp;
			dbItem.strStatus = ansi_to_utf8("1");                // 运行状态
			dbItem.strType = ansi_to_utf8("mysql");  			 // 数据库类型

			TCHAR szProcessName[MAX_PATH] = {0};
			if (!GetProcessFullPath(*it, szProcessName)){
				DI_LOG_DEBUG("error: get mysqld.exe image path error.");
				return false;
			}

			std::string strHomeDir = UnicodeToUtf8String(szProcessName);
			if (!strHomeDir.empty()){
				dbItem.strDBBinaryFilePath = strHomeDir;             // 二进制文件路径
				strHomeDir = strHomeDir.substr(0, strHomeDir.rfind("\\"));
			}

			std::string strCmdResult;
			std::string strCmd = "\"" + UnicodeToString(szProcessName) + "\" -V";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				size_t pS = strCmdResult.find("Ver");
				size_t pE = strCmdResult.find("for");
				if (pS != std::string::npos && pE != std::string::npos){
					strTmp = ansi_to_utf8(strCmdResult.substr(pS+4, (pE-1)-(pS+4)).data());       // 版本
          if (strTmp.find("-") != std::string::npos)
            strTmp = strTmp.substr(0, strTmp.find("-"));   // 过滤php中mysqld.exe -v版本为5.5.53-log情况

          if (!strTmp.empty() && IsVersionNumber(strTmp))
						dbItem.strVersion = strTmp;
				}
			}

			//strCmd = "\"" + strHomeDir + "\\mysqld.exe\" --verbose --help | findstr /B /C:\"port \"";
			strCmdResult.clear();
			strCmd.clear();
      strCmd = "netstat -nao | findstr " + type2str(*it);
      if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
        if (strCmdResult.find("TCP") != std::string::npos){
          strCmdResult = strCmdResult.substr(strCmdResult.find("TCP"));
          size_t pS = strCmdResult.find(":");
          if (pS != std::string::npos){
            strTmp = ansi_to_utf8(strCmdResult.substr(pS+1).data());       // 端口号
            strTmp = strTmp.substr(0, strTmp.find(" "));
            if (!strTmp.empty()){
              // 端口增加校验
              if (AllisNum(strTmp)){
                dbItem.strPort = strTmp;
              }
            }

            strTmp = ansi_to_utf8(strCmdResult.substr(strCmdResult.find("TCP")+3).data());       // 监听IPV4
            strTmp = strTmp.substr(strTmp.find_first_not_of(" "));
            strTmp = strTmp.substr(0, strTmp.find(":"));
            if (!strTmp.empty())
              dbItem.strBindIP = strTmp;

            pS = strCmdResult.find("[");             // 监听IPV6
            if (pS != std::string::npos){
              strTmp = strCmdResult.substr(pS);
              pS = strTmp.find(" ");
              if (strTmp.find(" ") != std::string::npos)
                strTmp = strTmp.substr(0, pS);
              if (strTmp.find(dbItem.strPort) != std::string::npos){
                size_t pE = strTmp.find("]");
                strTmp = ansi_to_utf8(strTmp.substr(1, pE-1).data());
                dbItem.strBindIP = dbItem.strBindIP + "," + strTmp;
              }
            }
          }
        }
			}

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					dbItem.strUser = UnicodeToUtf8String(strRunUser);     // 用户
			}

			// 获取命令行
			wchar_t* pCmd = GetProcessCommandLine(*it);
      std::wstring strProcessCmd;
      if (pCmd){
        strProcessCmd = pCmd;
        delete []pCmd;
				pCmd = NULL;
      }

			if (strProcessCmd.find(L"--defaults-file=\"") != std::wstring::npos){
				strTmp = UnicodeToUtf8String(strProcessCmd);
				strTmp = strTmp.substr(strTmp.find("--defaults-file=\"")+17);
				strTmp = strTmp.substr(0, strTmp.find("\" "));
        if (!strTmp.empty() && PathFileExists(StringToUnicode(strTmp).data()))
					dbItem.strConfPath = strTmp;                          // 配置文件路径
			}
			else{   
				// 默认路径
				strTmp = dbItem.strDBBinaryFilePath.substr(0, dbItem.strDBBinaryFilePath.rfind("\\"));
				strTmp = strTmp.substr(0, strTmp.rfind("\\"));
				dbItem.strConfPath = strTmp + "\\my.ini";    // 配置文件路径
			}

			strCmdResult.clear();
			strCmd.clear();
      do {
        if ((strHomeDir.find("phpStudy") != std::string::npos)){
          strTmp = dbItem.strDBBinaryFilePath.substr(0, dbItem.strDBBinaryFilePath.rfind("\\"));
				  strTmp = strTmp.substr(0, strTmp.rfind("\\"));
          dbItem.strLogPath = strTmp + "\\data\\";    // 日志路径
          dbItem.strDataPath = strTmp + "\\data\\";    // 数据路径
          break;
        }

        strCmd = "\"" + strHomeDir + "\\mysqld.exe\" --verbose --help | findstr /B /C:\"general-log-file \"";
        if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
          size_t pS = strCmdResult.rfind("general-log-file    ");
          if (pS != std::string::npos){
            strCmdResult = strCmdResult.substr(pS + 16);
            strCmdResult = strCmdResult.substr(strCmdResult.find_first_not_of(" "));
            std::string sTemp = strCmdResult.substr(0, strCmdResult.find("\r\n"));
            strTmp = ansi_to_utf8(sTemp.data());         // 日志路径
            if (!strTmp.empty() && PathFileExists(StringToUnicode(sTemp).data()))
              dbItem.strLogPath = strTmp;
          }
        }

        strCmdResult.clear();
        strCmd.clear();
        strCmd = "\"" + strHomeDir + "\\mysqld.exe\" --verbose --help | findstr /B /C:\"datadir \"";
        if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
          size_t pS = strCmdResult.rfind("datadir    ");
          if (pS != std::string::npos){
            strCmdResult = strCmdResult.substr(pS + 7);
            strCmdResult = strCmdResult.substr(strCmdResult.find_first_not_of(" "));
            std::string sTemp = strCmdResult.substr(0, strCmdResult.find("\r\n"));
            strTmp = ansi_to_utf8(sTemp.data());         // 数据路径
            if (!strTmp.empty() && PathFileExists(StringToUnicode(sTemp).data()))
              dbItem.strDataPath = strTmp;
          }
        }
      }while(false);

			std::string strKey = dbItem.strVersion + ":" + dbItem.strPort;      // 版本和端口作为Key
			if (g_map_database_table.find(strKey) == g_map_database_table.end())
				g_map_database_table.insert(make_pair(strKey, dbItem));    
		}

		Sleep(1);
		return true;
	}

	bool DIAssetDB::GetSqlServerDBInfo(void)
	{
		/** update: 2020-11-12
		*      1. 获取所有的sqlservr.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本和多实例
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"sqlservr.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: process sqlservr.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetDBItem dbItem;
			dbItem.strStatus = "--";
			dbItem.strUser = "--";
			dbItem.strType = "--";
			dbItem.strVersion = "--";
			dbItem.strBindIP = "--";
			dbItem.strPort = "0";
			dbItem.strDataPath = "--";
			dbItem.strConfPath = "--";
			dbItem.strLogPath = "--";
			dbItem.strDBBinaryFilePath = "--";

			std::string strTmp;
			dbItem.strStatus = ansi_to_utf8("1");                         // 运行状态
			dbItem.strType = ansi_to_utf8("sqlserver");  			     // 数据库类型

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					dbItem.strUser = UnicodeToUtf8String(strRunUser);     // 用户
			}

			std::string strCmdResult;
      std::string strCmd = "netstat -nao | findstr " + type2str(*it);
      if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
        if (strCmdResult.find("TCP") != std::string::npos){
          strCmdResult = strCmdResult.substr(strCmdResult.find("TCP"));
          size_t pS = strCmdResult.find(":");
          if (pS != std::string::npos){
            strTmp = ansi_to_utf8(strCmdResult.substr(pS+1).data());       // 端口号
            strTmp = strTmp.substr(0, strTmp.find(" "));
            if (!strTmp.empty()){
              // 端口增加校验
              if (AllisNum(strTmp)){
                dbItem.strPort = strTmp;
              }
            }

            strTmp = ansi_to_utf8(strCmdResult.substr(strCmdResult.find("TCP")+3).data());       // 监听IP
            strTmp = strTmp.substr(strTmp.find_first_not_of(" "));
            strTmp = strTmp.substr(0, strTmp.find(":"));
            if (!strTmp.empty())
              dbItem.strBindIP = strTmp;

            pS = strCmdResult.find("[");             // 监听IPV6
            if (pS != std::string::npos){
              strTmp = strCmdResult.substr(pS);
              pS = strTmp.find(" ");
              if (strTmp.find(" ") != std::string::npos)
                strTmp = strTmp.substr(0, pS);
              if (strTmp.find(dbItem.strPort) != std::string::npos){
                size_t pE = strTmp.find("]");
                strTmp = ansi_to_utf8(strTmp.substr(1, pE-1).data());
                dbItem.strBindIP = dbItem.strBindIP + "," + strTmp;
              }
            }
          }
        }
			}

			// 获取数据库实例名
			HKEY hKey; 
			std::string strDBInstance;
			std::wstring strInstanceRoot;
			std::wstring strRegPath;
			TCHAR szBuffer[MAX_PATH] = { 0 };
			DWORD dwNameLen = MAX_PATH;
			DWORD dwType;
			DWORD rQ = 0;
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Microsoft SQL Server", 0, KEY_READ, &hKey) == ERROR_SUCCESS){
				DWORD rQ = RegQueryValueEx(hKey, L"InstalledInstances", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				strDBInstance = UnicodeToUtf8String(szBuffer);
				RegCloseKey(hKey);

				// 获取启动的协议               
				if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL", 0, KEY_READ, &hKey) == ERROR_SUCCESS){
					memset(szBuffer, 0, dwNameLen);
					dwNameLen = MAX_PATH;
					rQ = RegQueryValueEx(hKey, StringToWchar(strDBInstance.data()).data(), 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
					strRegPath = L"SOFTWARE\\Microsoft\\Microsoft SQL Server\\";
					strInstanceRoot = strRegPath + std::wstring(szBuffer) + L"\\";
					RegCloseKey(hKey);
				} 
				else
					DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: open the key SOFTWARE\\Microsoft\\Microsoft SQL Server\\Instance Names\\SQL filed!");
			}        
			else
				DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: open the key SOFTWARE\\Microsoft\\Microsoft SQL Server filed!");

			strRegPath = strInstanceRoot + L"\\Setup";
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, strRegPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
				memset(szBuffer, 0, dwNameLen);
				dwNameLen = MAX_PATH;
				rQ = RegQueryValueEx(hKey, L"SQLDataRoot", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				strTmp = UnicodeToUtf8String(szBuffer);        		// 数据目录
				if (!strTmp.empty() && PathFileExists(szBuffer))
					dbItem.strDataPath = strTmp + "\\DATA";
				RegCloseKey(hKey);
			}                
			else
				DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: open the key SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLServer\\Setup filed!");

			// 日志路径
			strRegPath = strInstanceRoot + L"MSSQLServer\\Parameters";
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, strRegPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
				memset(szBuffer, 0, dwNameLen);
				dwNameLen = MAX_PATH;
				rQ = RegQueryValueEx(hKey, L"SQLArg2", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				strTmp = UnicodeToUtf8String(std::wstring(szBuffer).substr(2));
				if (!strTmp.empty() && PathFileExists(szBuffer))
					dbItem.strLogPath = strTmp;     // 日志文件路径
				RegCloseKey(hKey);
			}                
			else
				DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: open the key SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLServer\\Parameters filed!");

			// 版本
			strRegPath = strInstanceRoot + L"MSSQLServer\\CurrentVersion";
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, strRegPath.data(), 0, KEY_READ, &hKey) == ERROR_SUCCESS){
				memset(szBuffer, 0, dwNameLen);
				dwNameLen = MAX_PATH;
				rQ = RegQueryValueEx(hKey, L"CurrentVersion", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				strTmp = UnicodeToUtf8String(szBuffer);
        if (!strTmp.empty() && IsVersionNumber(strTmp))
					dbItem.strVersion = strTmp;     // 版本
				RegCloseKey(hKey);
			}                
			else
				DI_LOG_DEBUG("DIAssetDB::GetSqlServerDBInfo: open the key SOFTWARE\\Microsoft\\Microsoft SQL Server\\MSSQLServer\\CurrentVersion filed!");

			TCHAR pszFullPath[MAX_PATH] = {0};
			std::string strRootDir;
			if (GetProcessFullPath(*it, pszFullPath)){
				strTmp = UnicodeToUtf8String(pszFullPath);
				if (!strTmp.empty()){
					dbItem.strDBBinaryFilePath = strTmp;    // 二进制路径
					strRootDir = strTmp.substr(0, strTmp.rfind("\\"));
					dbItem.strConfPath = strRootDir + "\\perf-" + strDBInstance + "sqlctr.ini";    // 配置文件路径
				}
			}

			std::string strKey = dbItem.strVersion + ":" + dbItem.strPort;      // 版本和端口作为Key
			if (g_map_database_table.find(strKey) == g_map_database_table.end())
				g_map_database_table.insert(make_pair(strKey, dbItem)); 
		}

		Sleep(1);
		return true;
	}

	bool DIAssetDB::GetRedisDBInfo(void)
	{
		/** update: 2020-11-12
		*      1. 获取所有的redis-server.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本和多实例
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"redis-server.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetRedisDBInfo: process redis-server.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetDBItem dbItem;
			dbItem.strStatus = "--";
			dbItem.strUser = "--";
			dbItem.strType = "--";
			dbItem.strVersion = "--";
			dbItem.strBindIP = "--";
			dbItem.strPort = "0";
			dbItem.strDataPath = "--";
			dbItem.strConfPath = "--";
			dbItem.strLogPath = "--";
			dbItem.strDBBinaryFilePath = "--";

			std::string strTmp;

			dbItem.strStatus = ansi_to_utf8("1");              // 运行状态
			dbItem.strType = ansi_to_utf8("redis");  		   // 数据库类型

			TCHAR szProcessName[MAX_PATH] = {0};
			if (!GetProcessFullPath(*it, szProcessName)){
				DI_LOG_DEBUG("error: get redis-server image path error.");
				return false;
			}

			std::string strHomeDir = UnicodeToUtf8String(szProcessName);
			if (!strHomeDir.empty()){
				dbItem.strDBBinaryFilePath = strHomeDir;                      // 二进制文件路径
				strHomeDir = strHomeDir.substr(0, strHomeDir.rfind("\\")); 
			}

			std::string strCmdResult;
			std::string strCmd = "\"" + UnicodeToString(szProcessName) + "\" -v";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				size_t pS = strCmdResult.find("v=");
				if (pS != std::string::npos){
					strTmp = ansi_to_utf8(strCmdResult.substr(pS+2).data());       // 版本
					strTmp = strTmp.substr(0, strTmp.find(" "));
          if (!strTmp.empty() && IsVersionNumber(strTmp))
						dbItem.strVersion = strTmp;
				}
			}

			// 读取配置文件路径,通过命令行或者注册表获取
			LPCTSTR pCmd = NULL;
			if (CheckProcessExist(L"redis-server.exe", L"--service-run", *it, pCmd)){
				if (pCmd){
					std::wstring strCmd(pCmd);
					strCmd = strCmd.substr(strCmd.find(L"--service-run"));
					strCmd = strCmd.substr(strCmd.find(L" \"")+2);
					strCmd = strCmd.substr(0, strCmd.find(L"\""));
					strTmp = UnicodeToUtf8String(strCmd);
					if (!strTmp.empty())
						dbItem.strConfPath = strTmp;   //配置文件路径
					delete pCmd;
					pCmd = NULL;
				}
			}

			// 通过命令行netstat命令设置pid为过滤条件来获取监听端口
			strCmdResult.clear();
			strCmd.clear();
      strCmd = "netstat -nao | findstr " + type2str(*it);
      if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
        if (strCmdResult.find("TCP") != std::string::npos){
          strCmdResult = strCmdResult.substr(strCmdResult.find("TCP"));
          size_t pS = strCmdResult.find(":");
          if (pS != std::string::npos){
            strTmp = ansi_to_utf8(strCmdResult.substr(pS+1).data());       // 端口号
            strTmp = strTmp.substr(0, strTmp.find(" "));
            if (!strTmp.empty()){
              // 端口增加校验
              if (AllisNum(strTmp)){
                dbItem.strPort = strTmp;
              }
            }

            strTmp = ansi_to_utf8(strCmdResult.substr(strCmdResult.find("TCP")+3).data());       // 监听IP
            strTmp = strTmp.substr(strTmp.find_first_not_of(" "));
            strTmp = strTmp.substr(0, strTmp.find(":"));
            if (!strTmp.empty())
              dbItem.strBindIP = strTmp;

            pS = strCmdResult.find("[");             // 监听IPV6
            if (pS != std::string::npos){
              strTmp = strCmdResult.substr(pS);
              pS = strTmp.find(" ");
              if (strTmp.find(" ") != std::string::npos)
                strTmp = strTmp.substr(0, pS);
              if (strTmp.find(dbItem.strPort) != std::string::npos){
                size_t pE = strTmp.find("]");
                strTmp = ansi_to_utf8(strTmp.substr(1, pE-1).data());
                dbItem.strBindIP = dbItem.strBindIP + "," + strTmp;
              }
            }
          }
        }
      }

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){ 
				if (!strRunUser.empty())
					dbItem.strUser = UnicodeToUtf8String(strRunUser);     // 用户;
			}

			if (!strHomeDir.empty())
				dbItem.strLogPath = strHomeDir + ansi_to_utf8("\\server_log.txt");         // 日志路径

			strCmdResult.clear();
			strCmd.clear();
			std::string strDataPath;
			strCmd = "\"" + strHomeDir + "\\redis-cli.exe\" config get dir | findstr \\";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				if (!strCmdResult.empty()){
					strCmdResult = strCmdResult.substr(strCmdResult.find("\r\n")+2);
          // 考虑兼容性
          size_t pE = strCmdResult.find("\r\n\r\n");
          if (pE == std::string::npos)
            pE = strCmdResult.find("\n\r\n");
          strCmdResult = strCmdResult.substr(0, pE);
					strTmp = ansi_to_utf8(strCmdResult.data());
          if (!strTmp.empty() && PathFileExists(StringToUnicode(strCmdResult).data()))
						strDataPath = strTmp;         // 数据路径
				}
			}

			strCmdResult.clear();
			strCmd.clear();
			std::string strDataFileName;
			strCmd = "\"" + strHomeDir + "\\redis-cli.exe\" config get dbfilename | findstr .rdb";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				if (!strCmdResult.empty()){
					strCmdResult = strCmdResult.substr(strCmdResult.find("\r\n")+2);
          size_t pE = strCmdResult.find("\r\n\r\n");
          if (pE == std::string::npos)
            pE = strCmdResult.find("\n\r\n");
					strCmdResult = strCmdResult.substr(0, pE);
					strTmp = ansi_to_utf8(strCmdResult.data());
          if (!strTmp.empty() && PathFileExists(StringToUnicode(strCmdResult).data()))
						strDataFileName = strTmp;         // 数据路径
				}
			}

			dbItem.strDataPath = strDataPath + "\\" + strDataFileName;

			std::string strKey = dbItem.strVersion + ":" + dbItem.strPort;      // 版本和端口作为Key
			if (g_map_database_table.find(strKey) == g_map_database_table.end())
				g_map_database_table.insert(make_pair(strKey, dbItem));    
		}

		Sleep(1);
		return true;
	}

	bool DIAssetDB::GetPostgreSQLDBInfo(void)
	{
		/** update: 2020-11-12
		*      1. 获取所有的pg_ctl.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本和多实例
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"pg_ctl.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetPostgreSQLDBInfo: process pg_ctl.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetDBItem dbItem;
			dbItem.strStatus = "--";
			dbItem.strUser = "--";
			dbItem.strType = "--";
			dbItem.strVersion = "--";
			dbItem.strBindIP = "--";
			dbItem.strPort = "0";
			dbItem.strDataPath = "--";
			dbItem.strConfPath = "--";
			dbItem.strLogPath = "--";
			dbItem.strDBBinaryFilePath = "--";

			std::string strTmp;

			dbItem.strStatus = ansi_to_utf8("1");              // 运行状态
			dbItem.strType = ansi_to_utf8("postgresql");  			 // 数据库类型

			TCHAR szProcessName[MAX_PATH] = {0};
			if (!GetProcessFullPath(*it, szProcessName)){
				DI_LOG_DEBUG("error: get pg_ctl.exe image path error.");
				return false;
			}

			std::string strHomeDir = UnicodeToUtf8String(szProcessName);
			if (!strHomeDir.empty()){
				dbItem.strDBBinaryFilePath = strHomeDir;     // 二进制文件路径
				strHomeDir = strHomeDir.substr(0, strHomeDir.rfind("\\")); 
				strTmp = strHomeDir.substr(0, strHomeDir.rfind("\\"));
				if (!strTmp.empty()){
					dbItem.strConfPath = strTmp + "\\data\\postgresql.conf";    	   // 配置路径
					dbItem.strLogPath = strTmp + "\\data\\log\\postgresql-*.log";;     // 日志路径
				}
			}

			std::string strCmdResult;
			std::string strCmd = "\"" + UnicodeToString(szProcessName) + "\" -V";
			if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
				size_t pS = strCmdResult.find("PostgreSQL)");
				if (pS != std::string::npos){
					strCmdResult = strCmdResult.substr(pS+12);
					strTmp = ansi_to_utf8(strCmdResult.substr(0, strCmdResult.find("\r\n")).data());
					if (!strTmp.empty())
						dbItem.strVersion = strTmp;       // 版本
				}
			}

			LPCTSTR pCmd = NULL;
			if (CheckProcessExist(L"postgres.exe", L"-D", *it, pCmd)){
				strCmdResult.clear();
				strCmd.clear();
				strCmd = "netstat -ano | findstr " + type2str(*it);
        if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
          if (strCmdResult.find("TCP") != std::string::npos){
            strCmdResult = strCmdResult.substr(strCmdResult.find("TCP"));
            size_t pS = strCmdResult.find(":");
            if (pS != std::string::npos){
              strTmp = ansi_to_utf8(strCmdResult.substr(pS+1).data());       // 端口号
              strTmp = strTmp.substr(0, strTmp.find(" "));
              if (!strTmp.empty()){
                // 端口增加校验
                if (AllisNum(strTmp)){
                  dbItem.strPort = strTmp;
                }
              }

              strTmp = ansi_to_utf8(strCmdResult.substr(strCmdResult.find("TCP")+3).data());       // 监听IP
              strTmp = strTmp.substr(strTmp.find_first_not_of(" "));
              strTmp = strTmp.substr(0, strTmp.find(":"));
              if (!strTmp.empty())
                dbItem.strBindIP = strTmp;

              pS = strCmdResult.find("[");             // 监听IPV6
              if (pS != std::string::npos){
                strTmp = strCmdResult.substr(pS);
                pS = strTmp.find(" ");
                if (strTmp.find(" ") != std::string::npos)
                  strTmp = strTmp.substr(0, pS);
                if (strTmp.find(dbItem.strPort) != std::string::npos){
                  size_t pE = strTmp.find("]");
                  strTmp = ansi_to_utf8(strTmp.substr(1, pE-1).data());
                  dbItem.strBindIP = dbItem.strBindIP + "," + strTmp;
                }
              }
            }
          }
        }
      }
			else 
				DI_LOG_DEBUG("DIAssetWebService::GetWebLogicWebServiceInfo: process postgres.exe don't be existing.");

			if (pCmd){
				strTmp = UnicodeToUtf8String(pCmd);
				strTmp = strTmp.substr(strTmp.find("-D ")+4);
				strTmp = strTmp.substr(0, strTmp.rfind("\""));
				if (!strTmp.empty())
					dbItem.strDataPath = strTmp;
				delete []pCmd;
				pCmd = NULL;
			}

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					dbItem.strUser = UnicodeToUtf8String(strRunUser);     // 用户
			}

			std::string strKey = dbItem.strVersion + ":" + dbItem.strPort;      // 版本和端口作为Key
			if (g_map_database_table.find(strKey) == g_map_database_table.end())
				g_map_database_table.insert(make_pair(strKey, dbItem));
		}

		Sleep(1);
		return true;
	}
}
