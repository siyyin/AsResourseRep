#pragma once
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <windows.h>

namespace di_rest_client
{
	class DIAssetAutoRunItem
	{
	public:
		// 关键字段
		std::string strAutoRunName;         // 启动项名称
		std::string strAutoRunState;        // 启用或者停用，0：未启动，1：启动
		std::string strRegValue;            // 自启动命令行
		std::string strBinPath;             // 可执行文件路径
    std::string strRegPath;             // 注册表路径

		// 扩展字段
		std::string strPublisher;           // 发布者
		std::string strRegType;             // 注册表中的值类型
		std::string strUser;                // 运行级别(windows提供用户名)
		std::string strPid;                 // 如果已经启动，则记录pid
	};

	class RegPathItem
	{
	public:
		RegPathItem(HKEY hKey, const std::wstring& strKeyPath):
      m_hRootKey(hKey), 
      m_strKeyPath(strKeyPath)
    {}

		HKEY m_hRootKey;
		std::wstring m_strKeyPath;
	};

	class DIAssetAutoRun
	{
	public:
		DIAssetAutoRun(void);
		~DIAssetAutoRun(void);

		bool InitDIAssetAutoRun();
		std::map<std::string, DIAssetAutoRunItem>& GetDIAssetAutoRunList();

	private:
		void QueryKey(HKEY & hKey, std::string& strKeyPath);
		void InitAutoRunRegList();
		void InitAutoRunRegList32();

    bool IsWinXPOrFormer();
    bool IsWin7OrWin08();
    bool IsWin8OrLater();

    BOOL EnumStartup(void);
    BOOL GetLnkFileName(PWSTR pLnkName, PWSTR OepnFileNameBuufer, DWORD OpenFileNameBufferSize);
    std::string GetFileCompanyName(const wchar_t *pszFilePath);
    std::string GetFileProductName(const wchar_t *pszFilePath);
    std::string GetFileDescription(const wchar_t *pszFilePath);

	private:
		std::vector<RegPathItem> m_list_reg_autorun_table;
	};
}

