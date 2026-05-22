#ifndef COMMONDEFINE_H
#define COMMONDEFINE_H

#ifdef _WIN32
#include <string>
#include <iostream>

using namespace std;

// 函数声明
std::string UnicodeToString(std::wstring& src);
std::string UnicodeToString(const wchar_t* src);
std::wstring StringToUnicode(std::string& src);
std::wstring StringToUnicode(const char* src);
#endif
#endif