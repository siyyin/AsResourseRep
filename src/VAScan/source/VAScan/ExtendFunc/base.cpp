#ifdef _WIN32
#include "base.h"
#include <stdio.h>
#include "psapi.h"
#pragma comment(lib,"psapi.lib")
#ifdef _MSC_VER
#define snprintf _snprintf
#endif

LPWSTR ConverStringToUnicode(const char * Str)
{
	int BufferSize = 0;

	LPWSTR UnicodeStr = NULL;
	if (Str == NULL)
		return NULL;

	BufferSize = MultiByteToWideChar(CP_UTF8, 0, Str, (int)strlen(Str), NULL, 0);
	if (BufferSize == 0)
		return NULL;

	UnicodeStr = (LPWSTR)VirtualAlloc(NULL, (BufferSize+1) * sizeof(WCHAR), MEM_COMMIT, PAGE_READWRITE);
	if (UnicodeStr == NULL)
		return NULL;

	BufferSize = MultiByteToWideChar(CP_UTF8, 0, Str, (int)strlen(Str), UnicodeStr, (BufferSize+1)*sizeof(WCHAR));
	if (BufferSize == 0) {
		// 
		VirtualFree(UnicodeStr, 0, MEM_RELEASE);
		return NULL;
	}

	return UnicodeStr;
}


LPSTR ConvertUnicodeString(WCHAR * Str) 
{
	int BufferSize = 0;
	LPSTR OutputBuffer = NULL;
	if (Str == NULL)
		return NULL;

	BufferSize = WideCharToMultiByte(GetACP(), 0, Str, (int)wcslen(Str), NULL, 0, NULL, NULL);
	if (BufferSize == 0)
		return NULL;

	OutputBuffer = (LPSTR)VirtualAlloc(NULL, BufferSize + 1, MEM_COMMIT, PAGE_READWRITE);
	if (OutputBuffer == NULL)
		return NULL;

	BufferSize = WideCharToMultiByte(GetACP(), 0, Str, (int)wcslen(Str), OutputBuffer, BufferSize + 1, NULL, NULL);
	if ( GetLastError() == 0 ) {
		return OutputBuffer;
	} else {
		VirtualFree(OutputBuffer, 0, MEM_RELEASE);
		return NULL;
	}
}

void ConvertSlashSymbol(char * str)
{
	_strlwr_s(str, strlen(str) + 1);
	char * ptr = str;
	while (*ptr++)
	{
		if (*ptr == '\\')
			* ptr = '/';
	}
}

void ConvertBackSlashSymbol(char * str)
{
	char * ptr = str;
	while (*ptr++)
	{
		if (*ptr == '/')
			* ptr = '\\';
	}
}
#endif