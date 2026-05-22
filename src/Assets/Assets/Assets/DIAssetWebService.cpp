#include "DIAssetWebService.h"
#include <windows.h>
#include <Shlwapi.h>
#include "DIUtils.h"
#include "StringUtils.h"
#include "LogManager.h"

#define MAX_LEN_256         256

extern di_rest_client::Repairation *g_pRepairation;

namespace di_rest_client
{
	std::map<std::string, DIAssetWebServiceItem> g_map_webservice_table;
	DIAssetWebService::DIAssetWebService(void)
	{
	}


	DIAssetWebService::~DIAssetWebService(void)
	{
		g_map_webservice_table.clear();
	}

	std::map<std::string, DIAssetWebServiceItem>& DIAssetWebService::GetWebServiceList(void)
	{
		return g_map_webservice_table;
	}

	void DIAssetWebService::InitAssetWebService(void)
	{
		g_map_webservice_table.clear();

		bool bRet = GetIISWebServiceInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetWebService::InitAssetWebService: GetIISWebServiceInfo return false.");

		bRet = GetNginxWebServiceInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetWebService::InitAssetWebService: GetNginxWebServiceInfo return false.");

		bRet = GetHttpdWebServiceInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetWebService::InitAssetWebService: GetHttpdWebServiceInfo return false.");

		bRet = GetWebLogicWebServiceInfo();
		if (!bRet)
			DI_LOG_DEBUG("DIAssetWebService::InitAssetWebService: GetWebSphereWebServiceInfo return false.");
	}

	bool DIAssetWebService::GetIISWebServiceInfo(void)
	{
		/** update: 2020-11-13
		*      1. 获取所有的inetinfo.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"inetinfo.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetIISWebServiceInfo: process inetinfo.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetWebServiceItem WebSrvItem;
			WebSrvItem.strServiceType = "--";
			WebSrvItem.strVersion = "--";
			WebSrvItem.strSha1 = "--";
			WebSrvItem.strUser = "--";
			WebSrvItem.strBinPath = "--";
			WebSrvItem.strConfPath = "--";
			WebSrvItem.strPort = "--";

			std::string strTmp;
			WebSrvItem.strServiceType = ansi_to_utf8("IIS");                                            // 服务类型
			HKEY hKey;                
			if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\InetStp", 0, KEY_READ, &hKey) == ERROR_SUCCESS){
				TCHAR szBuffer[MAX_PATH] = { 0 };
				DWORD dwNameLen = MAX_PATH;
				DWORD dwType;
				DWORD rQ = RegQueryValueEx(hKey, L"VersionString", 0, &dwType, (LPBYTE)szBuffer, &dwNameLen);
				strTmp = UnicodeToUtf8String(szBuffer);             // 服务版本
				if (!strTmp.empty()){
					WebSrvItem.strVersion = strTmp;
          if (WebSrvItem.strVersion.find("Version") != std::string::npos){
            WebSrvItem.strVersion = WebSrvItem.strVersion.substr(WebSrvItem.strVersion.find("Version") + 8);
          }
        }
				RegCloseKey(hKey);
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetIISWebServiceInfo：RegOpenKeyEx to Get VersionString info filed!");

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					WebSrvItem.strUser = UnicodeToUtf8String(strRunUser);                            // 获取运行用户
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetIISWebServiceInfo：ExtractProcessOwner to Get user info filed!");

			TCHAR szProcessName[MAX_PATH] = {0};
			std::string strHomeDir;
			if (GetProcessFullPath(*it, szProcessName)){
				strTmp = UnicodeToUtf8String(szProcessName);
				if (!strTmp.empty()){
					strHomeDir = strTmp.substr(0, strTmp.rfind("\\"));
					WebSrvItem.strBinPath = strHomeDir + ansi_to_utf8("\\iisw3adm.dll");                     // 获取二进制路径
					WebSrvItem.strConfPath = strHomeDir + ansi_to_utf8("\\config\\applicationHost.config");  // 获取配置文件路径
				}
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetIISWebServiceInfo：Get ProcessFullPath info filed!");

			byte sha1Buf[20] = {0};
			char sha1Str[MAX_LEN_256] = {0};
			DWORD dwBufSize = sizeof(sha1Buf);
			if (CalcFileSha1Entity(WebSrvItem.strBinPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
				ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
				strTmp = ansi_to_utf8(sha1Str);                                 // 获取服务二进制文件Sha1
				if (!strTmp.empty())
					WebSrvItem.strSha1 = strTmp;
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetIISWebServiceInfo：Get Process SHA1 filed!");

			std::string strCmdResult;
      std::string strAppCmdPath = strHomeDir + "\\appcmd.exe";
      if (CheckFileExist(strAppCmdPath)){
        std::string strCmd = "\"" + strAppCmdPath + "\" list site /config | findstr \"protocol=\\\"http\\\"\"";
        if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
          size_t pS = strCmdResult.find("bindingInformation");
          if (pS != std::string::npos)
            strCmdResult = strCmdResult.substr(pS);
          pS = strCmdResult.find(":");
          if (pS != std::string::npos)
            strCmdResult = strCmdResult.substr(pS+1); 
          pS = strCmdResult.find(":");
          if (pS != std::string::npos){
            strTmp = ansi_to_utf8(strCmdResult.substr(0, pS).data());       // 端口
            if (!strTmp.empty()){
              // 端口增加校验
              if (AllisNum(strTmp)){
                WebSrvItem.strPort = strTmp;
              }
            }
          }
        }
      }
      else{
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
                  WebSrvItem.strPort = strTmp;
                }
              }
            }
          }
          else
            continue;
        }
      }


			std::string strKey = WebSrvItem.strServiceType + ":" + WebSrvItem.strVersion;      // 类型和版本作为Key
			if (g_map_webservice_table.find(strKey) == g_map_webservice_table.end())
				g_map_webservice_table.insert(make_pair(strKey, WebSrvItem)); 
		}

		Sleep(1);
		return true;
	}

	bool DIAssetWebService::GetNginxWebServiceInfo(void)
	{
		/** update: 2020-11-13
		*      1. 获取所有的nginx.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"nginx.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetNginxWebServiceInfo: process nginx.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetWebServiceItem WebSrvItem;
			WebSrvItem.strServiceType = "--";
			WebSrvItem.strVersion = "--";
			WebSrvItem.strSha1 = "--";
			WebSrvItem.strUser = "--";
			WebSrvItem.strBinPath = "--";
			WebSrvItem.strConfPath = "--";
			WebSrvItem.strPort = "--";

			std::string strTmp;
			WebSrvItem.strServiceType = ansi_to_utf8("nginx");                     // 获取服务类型         

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					WebSrvItem.strUser = UnicodeToUtf8String(strRunUser);      // 获取运行用户
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetNginxWebServiceInfo：Get user info filed!");

			TCHAR szProcessName[MAX_PATH] = {0};
			std::string strHomeDir;
			if (GetProcessFullPath(*it, szProcessName)){
				strTmp = UnicodeToUtf8String(szProcessName);
				if (!strTmp.empty()){
					WebSrvItem.strBinPath = strTmp;                   // 获取二进制路径
					strHomeDir = strTmp.substr(0, strTmp.rfind("\\"));
					WebSrvItem.strConfPath = strHomeDir + ansi_to_utf8("\\conf\\nginx.conf");   // 获取配置文件路径

					// 获取服务二进制文件Sha1
					byte sha1Buf[20] = {0};
					char sha1Str[MAX_LEN_256] = {0};
					DWORD dwBufSize = sizeof(sha1Buf);
					if (CalcFileSha1Entity(WebSrvItem.strBinPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
						ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
						strTmp = ansi_to_utf8(sha1Str);                  // 获取服务二进制文件Sha1
						if (!strTmp.empty())
							WebSrvItem.strSha1 = strTmp;
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetNginxWebServiceInfo：Get Process SHA1 filed!");

					std::string strCmdResult;
					std::string strCmd = "\"" + WebSrvItem.strBinPath + "\" -v";
					if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
						size_t pS = strCmdResult.rfind("nginx/");
						if (pS != std::string::npos){
							strCmdResult = strCmdResult.substr(pS + 6);
							strTmp = ansi_to_utf8(strCmdResult.substr(0, strCmdResult.find("\r\n")).data());    // 服务版本
              if (!strTmp.empty() && IsVersionNumber(strTmp))
								WebSrvItem.strVersion = strTmp;
						}
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetNginxWebServiceInfo：Get service version filed!");
				}
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetNginxWebServiceInfo：Get ProcessFullPath info filed!");

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
                WebSrvItem.strPort = strTmp;
              }
            }
          }
        }
        else
          continue;
			}

			std::string strKey = WebSrvItem.strServiceType + ":" + WebSrvItem.strVersion;      // 类型和版本作为Key
			if (g_map_webservice_table.find(strKey) == g_map_webservice_table.end())
				g_map_webservice_table.insert(make_pair(strKey, WebSrvItem));
		}

		Sleep(1);
		return true;
	}

	bool DIAssetWebService::GetHttpdWebServiceInfo(void)
	{
		/** update: 2020-11-13
		*      1. 获取所有的httpd.exe进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"httpd.exe");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetHttpdWebServiceInfo: process httpd.exe don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetWebServiceItem WebSrvItem;
			WebSrvItem.strServiceType = "--";
			WebSrvItem.strVersion = "--";
			WebSrvItem.strSha1 = "--";
			WebSrvItem.strUser = "--";
			WebSrvItem.strBinPath = "--";
			WebSrvItem.strConfPath = "--";
			WebSrvItem.strPort = "--";

			std::string strTmp;
			WebSrvItem.strServiceType = ansi_to_utf8("httpd");                         // 获取服务类型             

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){                  // 获取运行用户
				if (!strRunUser.empty())
					WebSrvItem.strUser = UnicodeToUtf8String(strRunUser);
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetHttpdWebServiceInfo：Get user info filed!");

			TCHAR szProcessName[MAX_PATH] = {0};
			std::string strHomeDir;
			if (GetProcessFullPath(*it, szProcessName)){
				strTmp = UnicodeToUtf8String(szProcessName);
				if (!strTmp.empty()){
					WebSrvItem.strBinPath = strTmp;
					strHomeDir = strTmp.substr(0, strTmp.rfind("\\bin"));        // 获取二进制路径
					WebSrvItem.strConfPath = strHomeDir + ansi_to_utf8("\\conf\\httpd.conf");          // 获取配置文件路径

					byte sha1Buf[20] = {0};
					char sha1Str[MAX_LEN_256] = {0};
					DWORD dwBufSize = sizeof(sha1Buf);
					if (CalcFileSha1Entity(WebSrvItem.strBinPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
						ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
						strTmp = ansi_to_utf8(sha1Str);                  // 获取服务二进制文件Sha1
						if (!strTmp.empty())
							WebSrvItem.strSha1 = strTmp;
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetHttpdWebServiceInfo：Get Process SHA1 filed!");

					std::string strCmdResult;
					std::string strCmd = "\"" + WebSrvItem.strBinPath + "\" -v";
					if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
						size_t pS = strCmdResult.rfind("Apache/");
						if (pS != std::string::npos){
							strCmdResult = strCmdResult.substr(pS + 7);
							strTmp = ansi_to_utf8(strCmdResult.substr(0, strCmdResult.find(" ")).data());  // 服务版本
              if (!strTmp.empty() && IsVersionNumber(strTmp))
								WebSrvItem.strVersion = strTmp;
						}
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetHttpdWebServiceInfo：Get service version filed!");
				}
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetHttpdWebServiceInfo：Get ProcessFullPath info filed!");

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
                WebSrvItem.strPort = strTmp;
              }
            }
          }
        }
        else
          continue;
			}

			std::string strKey = WebSrvItem.strServiceType + ":" + WebSrvItem.strVersion;      // 类型和版本作为Key
			if (g_map_webservice_table.find(strKey) == g_map_webservice_table.end())
				g_map_webservice_table.insert(make_pair(strKey, WebSrvItem));
		}

		Sleep(1);
		return true;
	}

	bool DIAssetWebService::GetWebLogicWebServiceInfo(void)
	{
		/** update: 2020-11-13
		*      1. 获取所有的java.exe且命令行包含"weblogic.Server"进程列表
		*      2. 根据不同的进程id来分别解析相关字段，适用于多版本
		*/
		std::vector<DWORD> vcPID;
		vcPID = GetPidListByProcessName(L"java.exe", L"weblogic.Server");   // 监听程序
		if (vcPID.empty()){     
			DI_LOG_DEBUG("DIAssetDB::GetWebLogicWebServiceInfo: the process java.exe which cmd hold \"weblogic.Server\" don't be existing.");
			return false;
		}

		auto itEnd = vcPID.end();
		for (auto it = vcPID.begin(); it != itEnd; it++)
		{
			DIAssetWebServiceItem WebSrvItem;
			WebSrvItem.strServiceType = "--";
			WebSrvItem.strVersion = "--";
			WebSrvItem.strSha1 = "--";
			WebSrvItem.strUser = "--";
			WebSrvItem.strBinPath = "--";
			WebSrvItem.strConfPath = "--";
			WebSrvItem.strPort = "--";

      DWORD dwPid = *it;

			std::string strTmp;
			WebSrvItem.strServiceType = ansi_to_utf8("weblogic");                          // 获取服务类型              

			std::wstring strRunUser;
			if (ExtractProcessOwner(*it, strRunUser)){
				if (!strRunUser.empty())
					WebSrvItem.strUser = UnicodeToUtf8String(strRunUser);               // 获取运行用户
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetWebLogicWebServiceInfo：Get user info filed!");

			TCHAR szProcessName[MAX_PATH] = {0};
			std::string strHomeDir;   // 通过命令行参数解析HomeDir
			LPCTSTR pCmd = GetProcessCommandLine(*it);
			if (pCmd){
				std::wstring strCmd(pCmd);
				strCmd = strCmd.substr(strCmd.find(L"Dwls.home=") + 10);
				strCmd = strCmd.substr(0, strCmd.find(L"-Dweblogic")-1);
				// 8.5标准短的路径转为长路径
				TCHAR achLongPath[MAX_PATH] = { 0 };
				::GetLongPathName( strCmd.data(), achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
				if (PathFileExists(achLongPath)){
          strHomeDir = UnicodeToUtf8String(achLongPath);
        }
        
				delete[] pCmd;
				pCmd = NULL;
			}

			if (GetProcessFullPath(*it, szProcessName)){
        TCHAR achLongPath[MAX_PATH] = { 0 };
				::GetLongPathName(szProcessName, achLongPath, sizeof(achLongPath)/sizeof(TCHAR) ); 
				strTmp = UnicodeToUtf8String(achLongPath);
        if (!strTmp.empty() && PathFileExists(achLongPath) && !strHomeDir.empty()){
					WebSrvItem.strBinPath = strTmp;        // 获取二进制路径

					// 通过HomeDir获取配置文件路径
          strTmp = strHomeDir.substr(0, strHomeDir.find("wlserver"));
          if (!strTmp.empty())
            WebSrvItem.strConfPath = strTmp + "user_projects\\domains\\base_domain\\config\\config.xml";

					byte sha1Buf[20] = {0};
					char sha1Str[MAX_LEN_256] = {0};
					DWORD dwBufSize = sizeof(sha1Buf);
					if (CalcFileSha1Entity(WebSrvItem.strBinPath.data(), sha1Buf, dwBufSize) && dwBufSize > 0){
						ConvertHexToString(sha1Buf, dwBufSize, sha1Str, MAX_LEN_256);
						strTmp = ansi_to_utf8(sha1Str);                      // 获取服务二进制文件Sha1
						if (!strTmp.empty())
							WebSrvItem.strSha1 = strTmp;
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetWebLogicWebServiceInfo：Get Process SHA1 filed!");

					std::string strCmdResult;
					std::string strCmd = "java.exe -cp " + strHomeDir + "\\lib\\weblogic.jar weblogic.version | findstr /B /C:\"WebLogic \"";
					if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
						size_t pS = strCmdResult.find("WebLogic Server ");
						if (pS != std::string::npos){
							strCmdResult = strCmdResult.substr(pS + 16);
							strTmp = ansi_to_utf8(strCmdResult.substr(0, strCmdResult.find(" ")).data());    // 服务版本
              if (!strTmp.empty() && IsVersionNumber(strTmp))
								WebSrvItem.strVersion = strTmp;
						}
					}
					else
						DI_LOG_DEBUG("DIAssetWebService::GetWebLogicWebServiceInfo：Get service version filed!");
				}
			}
			else
				DI_LOG_DEBUG("DIAssetWebService::GetWebLogicWebServiceInfo：Get ProcessFullPath info filed!");

			std::string strCmdResult;
			std::string strCmd = "netstat -nao | findstr " + type2str(dwPid);
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
                WebSrvItem.strPort = strTmp;
              }
            }
          }
        }
        else
          continue;
			}

			std::string strKey = WebSrvItem.strServiceType + ":" + WebSrvItem.strVersion;      // 类型和版本作为Key
			if (g_map_webservice_table.find(strKey) == g_map_webservice_table.end())
				g_map_webservice_table.insert(make_pair(strKey, WebSrvItem));
		}

		Sleep(1);
		return true;
	}
}