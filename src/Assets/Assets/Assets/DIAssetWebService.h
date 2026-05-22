#pragma once
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include "Repairation.h"

namespace di_rest_client
{
	class DIAssetWebServiceItem
	{
	public:
		// 关键字段
		std::string strServiceType;                // Web服务类型
		std::string strVersion;                    // 版本
		std::string strSha1;                       // sha1
		std::string strUser;                       // 运行用户
		std::string strBinPath;                    // 二进制路径
		std::string strConfPath;                   // 配置文件路径

		// 扩展字段
		std::string strPort;                       // 监听端口
	};

	class DIAssetWebService
	{
	public:
		DIAssetWebService(void);
		~DIAssetWebService(void);

		void InitAssetWebService(void);        // 初始化
		std::map<std::string, DIAssetWebServiceItem>& GetWebServiceList(void);    // 获取数据库列表
	private:

		bool GetIISWebServiceInfo(void);       // 获取IIS WebService的信息
		bool GetNginxWebServiceInfo(void);     // 获取nginx WebService的信息
		bool GetHttpdWebServiceInfo(void);     // 获取httpd WebService的信息
		bool GetWebLogicWebServiceInfo(void);  // 获取Weblogic WebService的信息
	};
}

