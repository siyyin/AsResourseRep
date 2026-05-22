#pragma once
#include <string>

#define SUFFIX_LUA "lua"

/// <summary>
/// 加密单个lua文件
/// </summary>
/// <param name="strPath"></param>
/// <param name="nVersion"></param>
/// <returns></returns>
bool encode_lua_file(const std::string& strPath, int nVersion);

/// <summary>
/// 加密单个lua文件
/// </summary>
/// <param name="strPath"></param>
/// <returns></returns>
bool decode_lua_file(const std::string& strPath);
