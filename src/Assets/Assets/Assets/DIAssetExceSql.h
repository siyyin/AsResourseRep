#pragma once
#include <mutex>
#include "Repairation.h"

namespace di_rest_client
{
	class DIAssetExceSql
	{
	public:
		DIAssetExceSql(void);
		~DIAssetExceSql(void);

		bool ExceSqlOracle(char* szSql, std::string& strResult);
		bool ExceSqlSQLServer(char* szSql, std::string& strResult);

	private:
		std::recursive_mutex m_mutex;
	};
}

