#pragma once

#ifdef HRA_RPC_COMM_API_COMPILED
#ifdef WIN32
#define HRA_RPCCOMM_EXPORT __declspec(dllexport)
#else
#define HRA_RPCCOMM_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_RPCCOMM_EXPORT __declspec(dllimport)
#else
#define HRA_RPCCOMM_EXPORT extern
#endif
#endif

