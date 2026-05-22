#include "StringUtils.h"
#include <vector>
#ifdef _WIN32
#include <Windows.h>
#else
#include <cstring>
#endif

#include <sstream>
#include "LogManager.h"

#define MAX_BUFSIZE 1 * 1024 *1024

namespace di_rest_client
{

std::string WcharToString(std::wstring& src)
{
// wide char to multi char
#ifdef _WIN32
  int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src.c_str(), -1, NULL, 0, NULL, NULL);
  if (iTextLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("WcharToString malloc a large buffer.");
  }
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_UTF8, 0, src.c_str(), -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
#else
  std::string out;
  const wchar_t* pSrc = src.c_str();
  size_t len = wcslen(pSrc);
  size_t size = wcsnrtombs(NULL, &pSrc, len, 0, NULL);
  if (size == std::string::npos) return out;
  out.resize(size);
  wcsnrtombs(&out[0], &pSrc, len, out.length(), NULL);
  return out;
#endif
}

#ifdef _WIN32
std::string UnicodeToString(std::wstring& src)
{
  int iTextLen = WideCharToMultiByte(CP_ACP, 0, src.c_str(), -1, NULL, 0, NULL, NULL);
  if (iTextLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("UnicodeToString malloc a large buffer.");
  }
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
  if (iTextLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("UnicodeToString malloc a large buffer.");
  }
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
  if (unicodeLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("StringToUnicode malloc a large buffer.");
  }
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
  if (unicodeLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("StringToUnicode malloc a large buffer.");
  }
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_ACP, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
}
#endif

std::string WcharToString(const wchar_t* src)
{
// wide char to multi char
#ifdef _WIN32
  int iTextLen = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
  if (iTextLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("WcharToString malloc a large buffer.");
  }
  char* pElementText = new char[iTextLen + 1];
  memset((void*)pElementText, 0, sizeof(char) * (iTextLen + 1));
  ::WideCharToMultiByte(CP_UTF8, 0, src, -1, pElementText, iTextLen, NULL, NULL);
  std::string strText(pElementText);
  delete[] pElementText;
  return strText;
#else
  std::string out;
  size_t len = wcslen(src);
  size_t size = wcsnrtombs(NULL, &src, len, 0, NULL);
  if (size == std::string::npos) return out;
  out.resize(size);
  wcsnrtombs(&out[0], &src, len, out.length(), NULL);
  return out;
#endif
}

std::wstring StringToWchar(std::string& src)
{
#ifdef _WIN32
  int unicodeLen = ::MultiByteToWideChar(CP_UTF8, 0, src.c_str(), -1, NULL, 0);
  if (unicodeLen + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("StringToWchar malloc a large buffer.");
  }
  wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
  memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
  ::MultiByteToWideChar(CP_UTF8, 0, src.c_str(), -1, (LPWSTR)pUnicode, unicodeLen);
  std::wstring rt(pUnicode);
  delete[] pUnicode;
  return rt;
#else
    const char* pSrc = src.c_str();
    size_t len = strlen(pSrc);
    size_t size = mbsnrtowcs(NULL, &(pSrc), len, 0, NULL);
    if (size == -1) return std::wstring(L"");
    wchar_t* pUnicode = new wchar_t[size + 1];
    mbsnrtowcs(pUnicode, &(pSrc), len, size, NULL);
    pUnicode[size] = L'\0';
    std::wstring out(pUnicode);
    delete[] pUnicode;
    return out;
#endif
}

std::wstring StringToWchar(const char* src)
{
#ifdef _WIN32
    int unicodeLen = ::MultiByteToWideChar(CP_UTF8, 0, src, -1, NULL, 0);
    wchar_t* pUnicode = new wchar_t[unicodeLen + 1];
    memset(pUnicode, 0, (unicodeLen + 1) * sizeof(wchar_t));
    ::MultiByteToWideChar(CP_UTF8, 0, src, -1, (LPWSTR)pUnicode, unicodeLen);
    std::wstring rt(pUnicode);
    delete[] pUnicode;
    return rt;
#else
    size_t len = strlen(src);
    size_t size = mbsnrtowcs(NULL, &src, len, 0, NULL);
    if (size == -1) return std::wstring(L"");
    wchar_t* pUnicode = new wchar_t[size + 1];
    mbsnrtowcs(pUnicode, &src, len, size, NULL);
    pUnicode[size] = L'\0';
    std::wstring out(pUnicode);
    delete[] pUnicode;
    return out;
#endif
}

bool StrEqual(const char* pszText1, const char* pszText2)
{
    if (pszText1 == NULL || pszText2 == NULL) {
        return false;
    }
    if (strlen(pszText1) != strlen(pszText2)) {
        return false;
    }
    return strcmp(pszText1, pszText2) == 0;
}

bool StrEqual(const wchar_t* pszText1, const wchar_t* pszText2)
{
    if (pszText1 == NULL || pszText2 == NULL) {
        return false;
    }
    if (wcslen(pszText1) != wcslen(pszText2)) {
        return false;
    }
    return wcscmp(pszText1, pszText2) == 0;
}

#ifdef _WIN32
bool StartWithIgnoreCase(const wchar_t* pszText, const wchar_t* pszPrefix)
{
    if (pszText == NULL || pszPrefix == NULL) return false;
    size_t nTextLen = wcslen(pszText);
    size_t nPrefixLen = wcslen(pszPrefix);
    return nTextLen >= nPrefixLen && _wcsnicmp(pszText, pszPrefix, nPrefixLen) == 0;
}
#endif

bool EndWithIgnoreCase(const wchar_t* pszText, const wchar_t* pszSuffix)
{
    if (pszText == NULL || pszSuffix == NULL) return false;
    size_t nTextLen = wcslen(pszText);
    size_t nSuffixLen = wcslen(pszSuffix);
#ifdef _WIN32
    return nTextLen >= nSuffixLen && _wcsicmp(pszText + nTextLen - nSuffixLen, pszSuffix) == 0;
#else
    return nTextLen >= nSuffixLen && wcscmp(pszText + nTextLen - nSuffixLen, pszSuffix) == 0;
#endif
}

bool StrEndWith(const char* pszText, const char* pszPostfix)
{
    if (pszText == NULL || pszPostfix == NULL) return false;
    size_t nTextLen = strlen(pszText);
    size_t nSuffixLen = strlen(pszPostfix);
    return nTextLen >= nSuffixLen && strcmp(pszText + nTextLen - nSuffixLen, pszPostfix) == 0;
}

void RemovePrefix(wchar_t* pszText, const wchar_t* pszPrefix)
{
    if (pszText == NULL || pszPrefix == NULL) return;
    const size_t nPrefixSize = wcslen(pszPrefix);
    if (wcsncmp(pszText, pszPrefix, nPrefixSize) == 0) {
        wmemmove(pszText, pszText + nPrefixSize, wcslen(pszText) - nPrefixSize + 1);
    }
}

void SplitString(const std::string& content, const std::string& delimiter, std::vector<std::string>* result)
{
    size_t last = 0;
    size_t index = content.find_first_of(delimiter, last);
    while (index != std::string::npos) {
        result->push_back(content.substr(last, index - last));
        last = index + 1;
        index = content.find_first_of(delimiter, last);
    }
    if (index - last > 0) {
        result->push_back(content.substr(last, index - last));
    }
}

bool SplitString(std::string str, const char * spit, std::string & before, std::string & after)
{
	bool	bret = false;
	size_t	slen = 0;

	if (str.empty() || NULL == spit) 
	{
		return false;
	}

	if (spit[0] == 0)
	{
		return false;
	}

	slen = str.find(spit);
	if (slen == str.npos)
	{
		return false;
	}
	bret = true;
	if (slen > 0)
	{
		before = str.substr(0, slen);
	}
	slen += strlen(spit);
	if (slen < str.length())
	{
		after = str.substr(slen);
	}

	return bret;
}

std::string & StrReplace(std::string & str, const std::string & old_value, const std::string & new_value)
{
	while (true)
	{
		std::string::size_type pos = 0;
		pos = str.find(old_value);
		if (pos == std::string::npos)
		{
			break;
		}

		str.replace(pos, old_value.length(), new_value);
	}

	return str;
}

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string Base64Encode(unsigned char const* buffer, unsigned len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];

    while (len--) {
        char_array_3[i++] = *(buffer++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; (i < 4); i++) ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++) char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;

        for (j = 0; (j < i + 1); j++) ret += base64_chars[char_array_4[j]];

        while ((i++ < 3)) ret += '=';
    }

    return ret;
}

const char* str0to127[] = {
    "\\0", "\\x01", "\\x02", "\\x03", "\\x04", "\\x05", "\\x06", "\\a", "\\b", "\\t", "\\n", "\\v", "\\f",
    "\\r", "\\x0E", "\\x0F", "\\x10", "\\x11", "\\x12", "\\x13", "\\x14", "\\x15", "\\x16", "\\x17", "\\x18", "\\x19",
    "\\x1A", "\\x1B", "\\x1C", "\\x1D", "\\x1E", "\\x1F", " ", "!", "\"", "#", "$", "%", "&",
    "\'", "(", ")", "*", "+", ",", "-", ".", "/", "0", "1", "2", "3",
    "4", "5", "6", "7", "8", "9", ":", ";", "<", "=", ">", "?", "@",
    "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
    "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
    "[", "\\", "]", "^", "_", "`", "a", "b", "c", "d", "e", "f", "g",
    "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t",
    "u", "v", "w", "x", "y", "z", "{", "|", "}", "~", "\\x7F", "\\x80", "\\x81",
    "\\x82", "\\x83", "\\x84", "\\x85", "\\x86", "\\x87", "\\x88", "\\x89", "\\x8A", "\\x8B", "\\x8C", "\\x8D", "\\x8E",
    "\\x8F", "\\x90", "\\x91", "\\x92", "\\x93", "\\x94", "\\x95", "\\x96", "\\x97", "\\x98", "\\x99", "\\x9A", "\\x9B",
    "\\x9C", "\\x9D", "\\x9E", "\\x9F", "\\xA0", "\\xA1", "\\xA2", "\\xA3", "\\xA4", "\\xA5", "\\xA6", "\\xA7", "\\xA8",
    "\\xA9", "\\xAA", "\\xAB", "\\xAC", "\\xAD", "\\xAE", "\\xAF", "\\xB0", "\\xB1", "\\xB2", "\\xB3", "\\xB4", "\\xB5",
    "\\xB6", "\\xB7", "\\xB8", "\\xB9", "\\xBA", "\\xBB", "\\xBC", "\\xBD", "\\xBE", "\\xBF", "\\xC0", "\\xC1", "\\xC2",
    "\\xC3", "\\xC4", "\\xC5", "\\xC6", "\\xC7", "\\xC8", "\\xC9", "\\xCA", "\\xCB", "\\xCC", "\\xCD", "\\xCE", "\\xCF",
    "\\xD0", "\\xD1", "\\xD2", "\\xD3", "\\xD4", "\\xD5", "\\xD6", "\\xD7", "\\xD8", "\\xD9", "\\xDA", "\\xDB", "\\xDC",
    "\\xDD", "\\xDE", "\\xDF", "\\xE0", "\\xE1", "\\xE2", "\\xE3", "\\xE4", "\\xE5", "\\xE6", "\\xE7", "\\xE8", "\\xE9",
    "\\xEA", "\\xEB", "\\xEC", "\\xED", "\\xEE", "\\xEF", "\\xF0", "\\xF1", "\\xF2", "\\xF3", "\\xF4", "\\xF5", "\\xF6",
    "\\xF7", "\\xF8", "\\xF9", "\\xFA", "\\xFB", "\\xFC", "\\xFD", "\\xFE", "\\xFF"};

int Binary2CStr(const unsigned char* inbuff, unsigned int inlen, char* outbuff, unsigned int outlen)
{
    unsigned char cc = 0;
    unsigned int ioffset = 0;
    unsigned int ilen = 0;

    if (inbuff == NULL || inlen == 0 || outbuff == NULL || outlen == 0) {
        return 0;
    }

    *outbuff = 0;
    for (unsigned int i = 0; i < inlen; ++i) {
        cc = inbuff[i];
        ilen = (unsigned char)strlen((char*)str0to127[cc]);
        if ((unsigned int)ioffset + ilen >= outlen) {
            return ioffset;
        }
        memcpy(outbuff + ioffset, str0to127[cc], ilen);
        ioffset = ioffset + ilen;
    }

    return ioffset;
}

int StringIsUTF8(unsigned char* str, int length)
{
    int i, mode = 0, m2;
    unsigned long ucs;
    unsigned ch;

    for (i = 0; i < length; i++) {
        ch = str[i];
        if (mode == 0) {
            if ((ch & 0x80) == 0)
                continue;
            if ((ch & 0xe0) == 0xc0) {
                mode = m2 = 1;
                ucs = (ch & 0x1f);
                continue;
            }
            if ((ch & 0xf0) == 0xe0) {
                mode = m2 = 2;
                ucs = (ch & 0x0f);
                continue;
            }
            if ((ch & 0xf8) == 0xf0) {
                mode = m2 = 3;
                ucs = (ch & 0x07);
                continue;
            }
            if ((ch & 0xfc) == 0xf8) {
                mode = m2 = 4;
                ucs = (ch & 0x03);
                continue;
            }
            if ((ch & 0xfe) == 0xfc) {
                mode = m2 = 5;
                ucs = (ch & 0x01);
                continue;
            }
            return -1;
        } else {
            if ((ch & 0xc0) != 0x80) {
                return -1;
            }
            ucs <<= 6;
            ucs += (ch & 0x3f);
            mode--;
            if (!mode) {
                if (m2 == 1 && ucs < 0x0000080) {
                    return -1;
                }
                if (m2 == 2 && ucs < 0x0000800) {
                    return -1;
                }
                if (m2 == 3 && ucs < 0x0010000) {
                    return -1;
                }
                if (m2 == 4 && ucs < 0x0200000) {
                    return -1;
                }
                if (m2 == 5 && ucs < 0x4000000) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

std::string ansi_to_utf8(const char* strAnsiA)
{
#ifdef _WIN32
  int len = MultiByteToWideChar(CP_ACP, 0, strAnsiA, -1, NULL,0);
  if (len + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("ansi_to_utf8 malloc a large buffer for wszUtf8.");
  }
  unsigned short *wszUtf8 = new unsigned short[len + 1];
  memset(wszUtf8, 0, (len+1) * sizeof(unsigned short));
  MultiByteToWideChar(CP_ACP, 0, strAnsiA, -1, (LPWSTR)wszUtf8, len);
  len = WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, NULL, 0, NULL, NULL);
  if (len + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("ansi_to_utf8 malloc a large buffer for szUtf8.");
  }
  char *szUtf8 = new char[len + 1];
  memset(szUtf8, 0, len + 1);
  WideCharToMultiByte(CP_UTF8, 0, (LPCWSTR)wszUtf8, -1, (LPSTR)szUtf8, len, NULL,NULL);
  std::string strUtf8(szUtf8);
  delete []wszUtf8;
  delete []szUtf8;
  return strUtf8;
#else
  std::string strUtf8(strAnsiA);
  return strUtf8;
#endif
}

std::string utf8_to_ansi(const char* strUtf8A)
{
#ifdef _WIN32
  int len = MultiByteToWideChar(CP_UTF8, 0, strUtf8A, -1, NULL,0);
  if (len + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("utf8_to_ansi malloc a large buffer for wszUtf8.");
  }
  unsigned short *wszUtf8 = new unsigned short[len + 1];
  memset(wszUtf8, 0, (len+1) * sizeof(unsigned short));
  MultiByteToWideChar(CP_UTF8, 0, strUtf8A, -1, (LPWSTR)wszUtf8, len);
  len = WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wszUtf8, -1, NULL, 0, NULL, NULL);
  if (len + 1 >= MAX_BUFSIZE){
    DI_LOG_WARN("utf8_to_ansi malloc a large buffer for szUtf8.");
  }
  char *szUtf8 = new char[len + 1];
  memset(szUtf8, 0, len + 1);
  WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)wszUtf8, -1, (LPSTR)szUtf8, len, NULL,NULL);
  std::string strUtf8(szUtf8);
  delete []wszUtf8;
  delete []szUtf8;
  return strUtf8;
#else
  std::string strAnsi(strUtf8A);
  return strAnsi;
#endif
}

void trimString(std::string & str )
{
    int s = (int)str.find_first_not_of(" ");
    int e = (int)str.find_last_not_of(" ");
    str = str.substr(s,e-s+1);
    return;
}

#ifdef _WIN32
std::string UnicodeToUtf8String(std::wstring& src)
{
  return WcharToString(src);
}
std::string UnicodeToUtf8String(const wchar_t* src)
{
	return WcharToString(src);
}

std::string byteToHexStr(unsigned char* byte_arr, int arr_len)
{
	std::string hexstr;
	for (int i = 0; 0 != byte_arr && i < arr_len; ++i)
	{
		char hex1;
		char hex2;
 
		/*借助C++支持的unsigned和int的强制转换，把unsigned char赋值给int的值，那么系统就会自动完成强制转换*/
		int value = byte_arr[i];
		int S = value / 16;
		int Y = value % 16;
 
		//将C++中unsigned char和int的强制转换得到的商转成字母
		if (S >= 0 && S <= 9)
			hex1 = (char)(48 + S);
		else
			hex1 = (char)(55 + S);
 
		//将C++中unsigned char和int的强制转换得到的余数转成字母
		if (Y >= 0 && Y <= 9)
			hex2 = (char)(48 + Y);
		else
			hex2 = (char)(55 + Y);
 
		//最后一步的代码实现，将所得到的两个字母连接成字符串达到目的
		hexstr = hexstr + hex1 + hex2;
	}
	return hexstr;
}

int hexStrToByte(char *s, unsigned char* bits)
{
    int i, n = 0;
    for(i = 0; s[i]; i += 2) 
	{
        if(s[i] >= 'A' && s[i] <= 'F')
            bits[n] = s[i] - 'A' + 10;
        else 
			bits[n] = s[i] - '0';
        if(s[i + 1] >= 'A' && s[i + 1] <= 'F')
            bits[n] = (bits[n] << 4) | (s[i + 1] - 'A' + 10);
        else 
			bits[n] = (bits[n] << 4) | (s[i + 1] - '0');
        ++n;
    }

    return n;
}

void splitstr(const std::string& str, char tag, std::vector<std::string>& list)
{
    std::string subStr;
 
    //遍历字符串，同时将i位置的字符放入到子串中，当遇到tag（需要切割的字符时）完成一次切割
    //遍历结束之后即可得到切割后的字符串数组
    for(size_t i = 0; i < str.length(); i++)
    {
        if(tag == str[i]) //完成一次切割
        {
            if(!subStr.empty())
            {
                list.push_back(subStr);
                subStr.clear();
            }
        }
        else //将i位置的字符放入子串
        {
            subStr.push_back(str[i]);
        }
    }
 
    if(!subStr.empty()) //剩余的子串作为最后的子字符串
    {
        list.push_back(subStr);
    }
}

void splitstr_v2(const std::string& str, const std::string& pattern, std::vector<std::string>& list)
{
    std::string subStr;
    std::string tPattern;
    size_t      patternLen =pattern.length();
    size_t      strLen     = str.length();
 
    for(size_t i = 0; i < str.length(); i++)
    {
        if(pattern[0] == str[i] && ((strLen - i) >= patternLen))
        {
            if(memcmp(&pattern[0],&str[i], patternLen) == 0)
            {
                i += patternLen - 1;
                if(!subStr.empty())
                {
                    list.push_back(subStr);
                    subStr.clear();
                }
            }
            else
            {
                subStr.push_back(str[i]);
            }
        }
        else
        {
            subStr.push_back(str[i]);
        }
    }
 
    if(!subStr.empty())
    {
        list.push_back(subStr);
    }
}

std::string dec2hex(int i, int width)
{
	std::stringstream ioss;     //定义字符串流
	std::string s_temp;         //存放转化后字bai符
	ioss << std::hex << i;      //以十六制形式输du出
	ioss >> s_temp;
	std::string s(width - s_temp.size(), '0');    //补0
	s += s_temp;                //合并
	return s;
}

std::string& replace_all_distinct(std::string& str, const std::string& old_value, const std::string& new_value)
{
    for (std::string::size_type pos(0); pos != std::string::npos; pos += new_value.length()) {
        if ((pos = str.find(old_value, pos)) != std::string::npos)
            str.replace(pos, old_value.length(), new_value);
        else
            break;
    }
    return str;
}

bool AllisNum(std::string str)  
{  
    for (size_t i = 0; i < str.size(); i++)
    {
        int tmp = (int)str[i];
        if (tmp >= 48 && tmp <= 57)
        {
            continue;
        }
        else
        {
            return false;
        }
    } 
    return true;
}



bool IsVersionNumber(std::string sParam)
{
  bool bRet = false;
  do{
    std::string sSrc = sParam;
    if (sSrc.find(".") == std::string::npos){
      return bRet;
    }

    std::vector<std::string> vNumber;
    SplitString(sSrc, ".", &vNumber);
    if (vNumber.size() < 2){
      return bRet;
    }

    std::vector<std::string>::iterator it = vNumber.begin();
    for ( ; it != vNumber.end(); it++)
    {
      if (!AllisNum(*it)){
        return bRet;
      }
    }

    bRet = true;
  }while(false);

  return bRet;
}

#endif
}  // namespace di_rest_client
