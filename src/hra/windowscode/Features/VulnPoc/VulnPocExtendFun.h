#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"

int FunPrintLog(lua_State* L);
int FunCmdPopen(lua_State* L);
int FunGetHraConfigValue(lua_State* L);
int FunSleep(lua_State* L);
int FunGetCtrlCmd(lua_State* L);
int FunGetAssets(lua_State* L);
int FunHttpRequest(lua_State* L);
int FunSocketConnect(lua_State* L);
int FunSocketSend(lua_State* L);
int FunSocketReceive(lua_State* L);
int FunSocketClose(lua_State* L);
int FunGetOsName(lua_State* L);
int FunGetOsBits(lua_State* L);
int FunGetZipFileList(lua_State* L);

//定义扩展函数表
static const struct luaL_Reg extendFunc[] = {
    {"Sleep", FunSleep},
    {"PrintLog", FunPrintLog},
    {"CmdPopen", FunCmdPopen},
    {"GetHraConfigValue", FunGetHraConfigValue},
    {"GetCtrlCmd", FunGetCtrlCmd}, 
    {"GetAssets", FunGetAssets},
    {"HttpRequest", FunHttpRequest},
    {"SocketConnect", FunSocketConnect},
    {"SocketSend", FunSocketSend},
    {"SocketReceive", FunSocketReceive},
    {"SocketClose", FunSocketClose},
    {"GetOsName", FunGetOsName},
    {"GetOsBits", FunGetOsBits},
    {"GetZipFileList", FunGetZipFileList},
    {NULL, NULL} //数组中最后一对必须是{NULL, NULL}，用来表示结束
};

#ifdef __cplusplus
}
#endif