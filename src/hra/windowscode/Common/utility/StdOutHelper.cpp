#include "StdOutHelper.h"
#include "Logger.h"

#include <io.h>

StdOutRedirectHelper::StdOutRedirectHelper()
	: m_fdOld(-1), m_ptrNewFile(nullptr)
{
	
}

StdOutRedirectHelper::~StdOutRedirectHelper()
{
}

bool StdOutRedirectHelper::RedirectTo(const std::string & strRedirectTo)
{
	// Duplicate stdout and give it a new file descriptor
	m_fdOld = _dup(_fileno(stdout));
	if (m_fdOld == -1)
	{
		LOGW_ERROR(L"_dup failed");
		return false;
	}

	if (fopen_s(&m_ptrNewFile, strRedirectTo.c_str(), "w") != 0)
	{
		LOGW_ERROR(L"can't open file");
		return false;
	}

	// stdout now refers to file
	if (_dup2(_fileno(m_ptrNewFile), _fileno(stdout)) == -1)
	{
		LOGW_ERROR(L"can't dup2 stdout");
		return false;
	}

	return true;
}

bool StdOutRedirectHelper::Restore()
{
	if (m_ptrNewFile != nullptr)
	{
		// Flush stdout stream buffer so it goes to correct file
		fflush(stdout);
		fclose(m_ptrNewFile);
	}

	if (m_fdOld != -1)
	{
		_dup2(m_fdOld, _fileno(stdout));

		_flushall();
	}

	return true;
}
