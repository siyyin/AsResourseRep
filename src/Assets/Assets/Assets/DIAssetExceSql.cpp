#include "DIAssetExceSql.h"
#include <windows.h>

extern di_rest_client::Repairation *g_pRepairation;

namespace di_rest_client
{
	DIAssetExceSql::DIAssetExceSql(void)
	{
	}


	DIAssetExceSql::~DIAssetExceSql(void)
	{
	}

	bool DIAssetExceSql::ExceSqlOracle(char* szSql, std::string& strResult)
	{
		// 创建临时sql文件
		std::lock_guard<std::recursive_mutex> lock_guard(m_mutex);
		LPCWSTR pwszSQLTemp = L"DIAssetSql.tmp";
		HANDLE hTempSqlFile =
			CreateFile(pwszSQLTemp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hTempSqlFile != INVALID_HANDLE_VALUE) {
			DWORD dwWritenSize = 0;
			std::string strContent = "conn /as sysdba;\r\n";
			strContent += szSql;
			strContent += "\r\nquit";
			BOOL bRet = WriteFile(hTempSqlFile, strContent.c_str(), (DWORD)strContent.length(), &dwWritenSize, NULL);
			FlushFileBuffers(hTempSqlFile);
			CloseHandle(hTempSqlFile);
			if (bRet != TRUE) {
				return false;
			}
		} else {
			return false;
		}

		// 执行sql查询
		std::string strCmdResult;
		std::string strCmd = "sqlplus.exe /nolog @";
		if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
			strResult = strCmdResult;
		}

		if (!DeleteFile(pwszSQLTemp))
			return false;

		return true;
	}

	bool DIAssetExceSql::ExceSqlSQLServer(char* szSql, std::string& strResult)
	{
		// 创建临时sql文件
		std::lock_guard<std::recursive_mutex> lock_guard(m_mutex);
		LPCWSTR pwszSQLTemp = L"DIAssetSql.tmp";
		HANDLE hTempSqlFile =
			CreateFile(pwszSQLTemp, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hTempSqlFile != INVALID_HANDLE_VALUE) {
			DWORD dwWritenSize = 0;
			std::string strContent = szSql;
			strContent += "\r\nGO";
			BOOL bRet = WriteFile(hTempSqlFile, strContent.c_str(), (DWORD)strContent.length(), &dwWritenSize, NULL);
			FlushFileBuffers(hTempSqlFile);
			CloseHandle(hTempSqlFile);
			if (bRet != TRUE) {
				return false;
			}
		} else {
			return false;
		}

		// 执行sql查询
		std::string strCmdResult;
		std::string strCmd = "sqlcmd.exe /i ";
		if (g_pRepairation->DoCmd((char*)strCmd.data(), strCmdResult)){
			strResult = strCmdResult;
		}

		if (!DeleteFile(pwszSQLTemp))
			return false;

		return true;
	}
}
