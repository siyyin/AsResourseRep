#pragma once


#ifndef S8
#define S8  char
#endif

#ifndef U8
#define U8 unsigned char
#endif

#ifndef S16
#define S16 short
#endif

#ifndef U16
#define U16 unsigned short
#endif

#ifndef S32
#define S32 int
#endif

#ifndef U32
#define U32 unsigned int
#endif

#ifndef S64
#define S64 long long int
#endif

#ifndef WORD64
#define WORD64 unsigned long long
#endif

#ifndef LF64
#define LF64 double
#endif


#ifndef ENABLED
#define ENABLED      1
#endif
#ifndef DISABLED
#define DISABLED     0
#endif

#ifndef MAINLOOP_FINISHED
#define MAINLOOP_FINISHED 1
#endif

#ifndef MAINLOOP_NOT_FINISHED
#define MAINLOOP_NOT_FINISHED 0
#endif

#ifndef HRA_CODE_E
#define HRA_CODE_E
typedef enum {
    HRA_OK = 0,
    HRA_FAILED,             
    HRA_NOT_SUPPORTED,
    HRA_NULL_PTR,
    HRA_OPEN_FAIL,
    HRA_MALLOC_FAIL,
    HRA_DATA_PARSE_FAIL,
    HRA_BAD_PARAM,
    HRA_SOCKET_ERROR,
    HRA_COND_CHK_FAIL,
    HRA_OUT_OF_RANGE,
    HRA_NOT_FOUND,
    HRA_TIMEOUT,
    HRA_IOCTL_FAILED,
    HRA_ALREADY_EXIST,
    HRA_FULL,
    HRA_EMPTY,
    HRA_BUSY,
    HRA_BAD_FILE,
    HRA_CMD_FAILED,
    HRA_OP_IN_PROGRESS,
    HRA_CONNECT_FAILED,
    HRA_USER_CANCEL = 50,
    HRA_NOT_INIT,
    HRA_LAST /* never use! */
} HRA_Code;
#endif /* HRA_CODE_E */

#ifdef HRA_UTILITY_API_COMPILED
#ifdef WIN32
#define HRA_UTILITY_EXPORT __declspec(dllexport)
#else
#define HRA_UTILITY_EXPORT
#endif
#else
#ifdef WIN32
#define HRA_UTILITY_EXPORT __declspec(dllimport)
#else
#define HRA_UTILITY_EXPORT extern
#endif
#endif

