#ifdef _WIN32
#include <windows.h>

LPWSTR ConverStringToUnicode(const char * Str);
LPSTR ConvertUnicodeString(WCHAR * Str);
void ConvertSlashSymbol(char * str);
void ConvertBackSlashSymbol(char * Str);

#endif