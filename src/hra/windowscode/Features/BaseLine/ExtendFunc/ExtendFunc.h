#ifndef EXTERNFUNC_H
#define EXTERNFUNC_H

extern "C" {
#include "lua/lua.h"
#include "lua/lualib.h"
#include "lua/lauxlib.h"
}

int PrintLog(lua_State* L);
int PrintDbgMsgA(lua_State *L);
int PrintDbgMsgW(lua_State *L);
int FunCmdPopen(lua_State *L);
int FunGetRegStr(lua_State *L);
int FunGetRegInt(lua_State *L);
int FunUsersIdentification(lua_State *L);
int FunGetShareAccount(lua_State *L);
int FunGetAccountDisableAndExceptGuest(lua_State *L);
int FunGetTcpTable(lua_State *L);
int FunGetGPOInRegistryFileStr(lua_State *L);
int FunGetPathUsers(lua_State *L);
int FunGetPathAccountsPrivilege(lua_State *L);
int FunGetAdminUsers(lua_State *L);
int FunGetUserNameByProcessId(lua_State* L);
int FunGetInfoByWMISql(lua_State* L);
int FunGetDomainUserAccount(lua_State* L);
int FunGetFileVersion(lua_State* L);
int FunGetHraConfigValue(lua_State* L);
int FunGetIniValue(lua_State* L);
int FunGetInstalledSoftware(lua_State* L);
int FunGetRunningProcess(lua_State* L);
int FunRequestKbData(lua_State* L);
int FunGetKbData(lua_State* L);
int FunSleep(lua_State* L);
int FunGetCtrlCmd(lua_State* L);
int FunWqlExecQuery(lua_State* L);

//定义扩展函数表
static const struct luaL_Reg extendFunc[] =
{
    {"Sleep",                               FunSleep},
    {"PrintLog",		                    PrintLog},
    {"PrintDbgMsgA",		                PrintDbgMsgA},
    {"PrintDbgMsgW",		                PrintDbgMsgW},
    {"CmdPopen",		                    FunCmdPopen},
    {"GetRegStr",		                    FunGetRegStr},
    {"GetRegInt",		                    FunGetRegInt},
    {"GetUsersIdentification",		        FunUsersIdentification},
    {"GetShareAccount",		                FunGetShareAccount},
    {"GetAccountDisableAndExceptGuest",	    FunGetAccountDisableAndExceptGuest},
    {"GetTcpTable",		                    FunGetTcpTable},
    {"GetGPOInRegistryFileStr",             FunGetGPOInRegistryFileStr},
    {"GetPathUsers",                        FunGetPathUsers},
    {"GetPathAccountsPrivilege",            FunGetPathAccountsPrivilege},
    {"GetAdminUsers",                       FunGetAdminUsers},
    {"GetUserNameByProcessId",              FunGetUserNameByProcessId},
    {"GetInfoByWMISql",                     FunGetInfoByWMISql},
    {"GetDomainUserAccount",                FunGetDomainUserAccount},
    {"GetFileVersion",                      FunGetFileVersion},
    {"GetHraConfigValue",                   FunGetHraConfigValue},
    {"GetIniValue",                         FunGetIniValue},
    {"GetInstalledSoftware",                FunGetInstalledSoftware},
    {"GetRunningProcess",                   FunGetRunningProcess},
    {"RequestKbData",                       FunRequestKbData},
    {"GetKbData",                           FunGetKbData},
    {"GetCtrlCmd",                          FunGetCtrlCmd},
    {"WqlExecQuery",                        FunWqlExecQuery},
    {NULL, NULL}       //数组中最后一对必须是{NULL, NULL}，用来表示结束      
};

#endif
