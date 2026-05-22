#pragma once
#include <string>
#include "comm.h"

class HRA_UTILITY_EXPORT StdOutRedirectHelper
{
public:
	StdOutRedirectHelper();
	~StdOutRedirectHelper();

public:
	bool RedirectTo(const std::string& strRedirectTo);
	bool Restore();

private:
	// old stdout fd
	int m_fdOld;

	// new file 
	FILE* m_ptrNewFile;
};

