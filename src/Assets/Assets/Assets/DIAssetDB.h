#pragma once

#include <string>
#include <iostream>
#include <vector>
#include <map>
#include "Repairation.h"

namespace di_rest_client
{
	class DIAssetDBItem
	{
	public:
		// 关键字段
		std::string strStatus;                // 数据库状态
		std::string strUser;                  // 用户
		std::string strType;                  // 类型
		std::string strVersion;               // 版本
		std::string strBindIP;                // 绑定IP
		std::string strPort;                  // 监听端口
		std::string strDataPath;              // 数据文件路径
		std::string strConfPath;              // 配置文件路径
		std::string strLogPath;               // 日志文件路径

		// 扩展字段
		std::string strDBBinaryFilePath;      // 二进制文件路径
	};

	class DIAssetDB
	{
	public:
		DIAssetDB(void);
		~DIAssetDB(void);

		bool InitAssetDataBase(void);                       // 初始化
		std::map<std::string, DIAssetDBItem>& GetDataBaseList(void);  // 获取数据库列表

	private:
		bool GetOracleDBInfo(void);           // 获取oracle数据库的信息
		bool GetMySQLDBInfo(void);            // 获取mysql数据库的信息
		bool GetSqlServerDBInfo(void);        // 获取SQL Server数据库信息
		bool GetRedisDBInfo(void);            // 获取Redis数据库信息
		bool GetPostgreSQLDBInfo(void);       // 获取PostgreSQL数据库信息
	};
}

