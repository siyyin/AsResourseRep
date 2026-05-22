#include "CommonDefine.h"
#include <Windows.h>

// 函数定义
std::string UnicodeToString(std::wstring& src)
{
  int iTextLen = WideCharToMultiByte(CP_ACP, 0, src.c_str(), -1, NULL, 0, NULL, NULL);
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_ACP, 0, src.c_str(), -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
}

std::string UnicodeToString(const wchar_t* src)
{
  int iTextLen = WideCharToMultiByte(CP_ACP, 0, src, -1, NULL, 0, NULL, NULL);
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_ACP, 0, src, -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
}

std::wstring StringToUnicode(std::string& src)
{
  int unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, NULL, 0);
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_ACP, 0, src.c_str(), -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
}

std::wstring StringToUnicode(const char* src)
{
  int unicodeLen = ::MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_ACP, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
}