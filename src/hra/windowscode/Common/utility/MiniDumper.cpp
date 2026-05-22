#include <windows.h>
#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>
#include <tchar.h>
#include <strsafe.h>
#include <dbghelp.h>
#include "MiniDumper.h"
#include "Logger.h"
 
#ifdef UNICODE
    #define _tcssprintf wsprintf
    #define tcsplitpath _wsplitpath
#else
    #define _tcssprintf sprintf
    #define tcsplitpath _splitpath
#endif
 
const int USER_DATA_BUFFER_SIZE = 4096;
 
//-----------------------------------------------------------------------------
// GLOBALS
//-----------------------------------------------------------------------------
CMiniDumper* CMiniDumper::s_pMiniDumper = NULL;
LPCRITICAL_SECTION CMiniDumper::s_pCriticalSection = NULL;
 
// Based on dbghelp.h
typedef BOOL (WINAPI *MINIDUMPWRITEDUMP)(HANDLE hProcess,
                                         DWORD dwPid,
                                         HANDLE hFile,
                                         MINIDUMP_TYPE DumpType,
                                         CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                         CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                         CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
 
//-----------------------------------------------------------------------------
// Name: CMiniDumper()
// Desc: Constructor
//-----------------------------------------------------------------------------
CMiniDumper::CMiniDumper( /*bool bPromptUserForMiniDump*/ )
{
	// Our CMiniDumper should act alone as a singleton.
	assert( !s_pMiniDumper );
 
    s_pMiniDumper = this;
    //m_bPromptUserForMiniDump = bPromptUserForMiniDump;
 
    // The SetUnhandledExceptionFilter function enables an application to 
    // supersede the top-level exception handler of each thread and process.
    // After calling this function, if an exception occurs in a process 
    // that is not being debugged, and the exception makes it to the 
    // unhandled exception filter, that filter will call the exception 
    // filter function specified by the lpTopLevelExceptionFilter parameter.
    m_pExceptionInfo = NULL;
	::SetUnhandledExceptionFilter( unhandledExceptionHandler );
 
    // Since DBGHELP.dll is not inherently thread-safe, making calls into it 
    // from more than one thread simultaneously may yield undefined behavior. 
    // This means that if your application has multiple threads, or is 
    // called by multiple threads in a non-synchronized manner, you need to  
    // make sure that all calls into DBGHELP.dll are isolated via a global
    // critical section.
    s_pCriticalSection = new CRITICAL_SECTION;
 
    if( s_pCriticalSection )
        InitializeCriticalSection( s_pCriticalSection );
}
 
//-----------------------------------------------------------------------------
// Name: ~CMiniDumper()
// Desc: Destructor
//-----------------------------------------------------------------------------
CMiniDumper::~CMiniDumper( void )
{
    if( s_pCriticalSection )
    {
        DeleteCriticalSection( s_pCriticalSection );
        delete s_pCriticalSection;
    }
}
 
//-----------------------------------------------------------------------------
// Name: unhandledExceptionHandler()
// Desc: Call-back filter function for unhandled exceptions
//-----------------------------------------------------------------------------
LONG CMiniDumper::unhandledExceptionHandler( _EXCEPTION_POINTERS *pExceptionInfo )
{
	if( !s_pMiniDumper )
		return EXCEPTION_CONTINUE_SEARCH;

    s_pMiniDumper->StackBacktrack(pExceptionInfo);

	return s_pMiniDumper->writeMiniDump( pExceptionInfo );
}
 
//-----------------------------------------------------------------------------
// Name: setMiniDumpFileName()
// Desc: 
//-----------------------------------------------------------------------------
void CMiniDumper::setMiniDumpFileName( void )
{
    time_t currentTime;
    time(&currentTime);
 
    wsprintf(m_szMiniDumpPath, L"%s%s.dmp", m_szAppPath, m_szAppBaseName);
}
 
//-----------------------------------------------------------------------------
// Name: getImpersonationToken()
// Desc: The method acts as a potential workaround for the fact that the 
//       current thread may not have a token assigned to it, and if not, the 
//       process token is received.
//-----------------------------------------------------------------------------
bool CMiniDumper::getImpersonationToken( HANDLE* phToken )
{
    *phToken = NULL;
 
    if( !OpenThreadToken( GetCurrentThread(),
                          TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                          TRUE,
                          phToken) )
    {
        if( GetLastError() == ERROR_NO_TOKEN )
        {
            // No impersonation token for the current thread is available. 
            // Let's go for the process token instead.
            if( !OpenProcessToken( GetCurrentProcess(),
                                   TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES,
                                   phToken) )
                return false;
        }
        else
            return false;
    }
 
    return true;
}
 
//-----------------------------------------------------------------------------
// Name: enablePrivilege()
// Desc: Since a MiniDump contains a lot of meta-data about the OS and 
//       application state at the time of the dump, it is a rather privileged 
//       operation. This means we need to set the SeDebugPrivilege to be able 
//       to call MiniDumpWriteDump.
//-----------------------------------------------------------------------------
BOOL CMiniDumper::enablePrivilege( LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld )
{
    BOOL bOk = FALSE;
 
    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    bOk = LookupPrivilegeValue( 0, pszPriv, &tp.Privileges[0].Luid );
 
    if( bOk )
    {
        DWORD cbOld = sizeof(*ptpOld);
        bOk = AdjustTokenPrivileges( hToken, FALSE, &tp, cbOld, ptpOld, &cbOld );
    }
 
    return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}
 
//-----------------------------------------------------------------------------
// Name: restorePrivilege()
// Desc: 
//-----------------------------------------------------------------------------
BOOL CMiniDumper::restorePrivilege( HANDLE hToken, TOKEN_PRIVILEGES* ptpOld )
{
    BOOL bOk = AdjustTokenPrivileges(hToken, FALSE, ptpOld, 0, NULL, NULL);
    return ( bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()) );
}
 
//-----------------------------------------------------------------------------
// Name: writeMiniDump()
// Desc: 
//-----------------------------------------------------------------------------
LONG CMiniDumper::writeMiniDump( _EXCEPTION_POINTERS *pExceptionInfo )
{
	LONG retval = EXCEPTION_CONTINUE_SEARCH;
	m_pExceptionInfo = pExceptionInfo;
 
    HANDLE hImpersonationToken = NULL;
    if( !getImpersonationToken( &hImpersonationToken ) )
        return FALSE;
 
	// You have to find the right dbghelp.dll. 
	// Look next to the EXE first since the one in System32 might be old (Win2k)
	
	HMODULE hDll = NULL;
	TCHAR szDbgHelpPath[MAX_PATH];
 
	if( GetModuleFileName( NULL, m_szAppPath, _MAX_PATH ) )
	{
		TCHAR *pSlash = wcsrchr( m_szAppPath, '\\' );
 
		if( pSlash )
		{
			_tcscpy_s( m_szAppBaseName, sizeof(m_szAppBaseName)/sizeof(TCHAR), pSlash + 1);
			*(pSlash+1) = 0;
		}
 
		_tcscpy_s( szDbgHelpPath, sizeof(szDbgHelpPath)/sizeof(TCHAR), m_szAppPath );
        _tcscat_s( szDbgHelpPath, sizeof(szDbgHelpPath)/sizeof(TCHAR), L"DBGHELP.DLL");
		hDll = ::LoadLibrary( szDbgHelpPath );
	}
 
	if( hDll == NULL )
	{
		// If we haven't found it yet - try one more time.
		hDll = ::LoadLibrary( L"DBGHELP.DLL");
	}
 
	LPCTSTR szResult = NULL;
 
	if( hDll )
	{
        // Get the address of the MiniDumpWriteDump function, which writes 
        // user-mode mini-dump information to a specified file.
		MINIDUMPWRITEDUMP MiniDumpWriteDump = 
            (MINIDUMPWRITEDUMP)::GetProcAddress( hDll, "MiniDumpWriteDump" );
 
		if( MiniDumpWriteDump != NULL )
        {
			TCHAR szScratch[USER_DATA_BUFFER_SIZE];
 
			setMiniDumpFileName();
 
			// Ask the user if he or she wants to save a mini-dump file...
			wsprintf( szScratch,
                         L"There was an unexpected error:\n\nWould you "
                         L"like to create a mini-dump file?\n\n%s ",
                         m_szMiniDumpPath);
 
			// Create the mini-dump file...
			HANDLE hFile = ::CreateFile( m_szMiniDumpPath, 
                                            GENERIC_WRITE, 
                                            FILE_SHARE_WRITE, 
                                            NULL, 
                                            CREATE_ALWAYS, 
                                            FILE_ATTRIBUTE_NORMAL, 
                                            NULL );
 
			if( hFile != INVALID_HANDLE_VALUE )
			{
				_MINIDUMP_EXCEPTION_INFORMATION ExInfo;
				ExInfo.ThreadId          = ::GetCurrentThreadId();
				ExInfo.ExceptionPointers = pExceptionInfo;
				ExInfo.ClientPointers    = NULL;
 
                // We need the SeDebugPrivilege to be able to run MiniDumpWriteDump
                TOKEN_PRIVILEGES tp;
                BOOL bPrivilegeEnabled = enablePrivilege( SE_DEBUG_NAME, hImpersonationToken, &tp );
 
                BOOL bOk;
 
                // DBGHELP.dll is not thread-safe, so we need to restrict access...
                EnterCriticalSection( s_pCriticalSection );
                {
					// Write out the mini-dump data to the file...
                    bOk = MiniDumpWriteDump( GetCurrentProcess(),
                                                GetCurrentProcessId(),
                                                hFile,
                                                MiniDumpWithFullMemory,
                                                &ExInfo,
                                                NULL,
                                                NULL );
                }
                LeaveCriticalSection( s_pCriticalSection );
 
                // Restore the privileges when done
                if( bPrivilegeEnabled )
	                restorePrivilege( hImpersonationToken, &tp );
 
                if( bOk )
				{
					szResult = NULL;
					retval = EXCEPTION_EXECUTE_HANDLER;
				}
				else
				{
					wsprintf( szScratch,
                                    L"Failed to save the mini-dump file to '%s' (error %lu)",
                                    m_szMiniDumpPath,
                                    GetLastError() );
 
					szResult = szScratch;
				}
 
				::CloseHandle( hFile );
			}
			else
			{
				wsprintf( szScratch,
                                L"Failed to create the mini-dump file '%s' (error %lu)",
                                m_szMiniDumpPath,
                                GetLastError() );
 
				szResult = szScratch;
			}
		}
		else
		{
			szResult = L"Call to GetProcAddress failed to find MiniDumpWriteDump. "
                       L"The DBGHELP.DLL is possibly outdated." ;
		}
	}
	else
	{
		szResult = L"Call to LoadLibrary failed to find DBGHELP.DLL.";
	}
 
	//if( szResult && m_bPromptUserForMiniDump )
	//	::MessageBox( NULL, szResult, NULL, MB_OK );
 
	TerminateProcess( GetCurrentProcess(), 0 );
 
	return retval;
}

// 向日志文件打印堆栈信息
void CMiniDumper::StackBacktrack(_EXCEPTION_POINTERS* pExceptionInfo)
{
    const int maxStackTraceFrames = 20;
    std::wstring stackTraceStr;
    HANDLE process = GetCurrentProcess();
    HANDLE thread  = GetCurrentThread();
    // 初始化进程符号引擎
    if (!SymInitializeW(process, NULL, TRUE))
    {
        return;
    }

    // 微软要求:数据的总大小为 SizeOfStruct + (MaxNameLen - 1) * sizeof(TCHAR)
    // SYMBOL_INFOW* symbolInfo = (SYMBOL_INFOW*)malloc(sizeof(SYMBOL_INFOW) + 256 * sizeof(wchar_t));
    wchar_t buffer[sizeof(SYMBOL_INFOW) + 256 * sizeof(wchar_t)];
    PSYMBOL_INFOW symbolInfo = (PSYMBOL_INFOW)buffer;
    symbolInfo->MaxNameLen   = 255;
    symbolInfo->SizeOfStruct = sizeof(SYMBOL_INFOW);

#ifdef _WIN64
    void* stackTrace[maxStackTraceFrames];
    USHORT frames = CaptureStackBackTrace(0, maxStackTraceFrames, stackTrace, NULL);

    // 打印堆栈信息
    for (USHORT i = 0; i < frames; ++i)
    {
        // 获取指定堆栈的符号信息
        if (!SymFromAddrW(process, (DWORD64)(stackTrace[i]), 0, symbolInfo))
        {
            continue;
        }
        // 获取源文件和行号信息
        IMAGEHLP_LINEW64 lineInfo;
        lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
        DWORD displacement;
        if (SymGetLineFromAddrW64(process, (DWORD64)(stackTrace[i]), &displacement, &lineInfo))
        {
            stackTraceStr += std::to_wstring(i) + L": " + symbolInfo->Name + L" - " + lineInfo.FileName + L" (" +
                             std::to_wstring(lineInfo.LineNumber) + L")\n";
        }
        else
        {
            stackTraceStr += std::to_wstring(i) + L": " + symbolInfo->Name + L"\n";
        }
    }
#else
    CONTEXT* context            = pExceptionInfo->ContextRecord;
    STACKFRAME stackFrame       = {};
    stackFrame.AddrPC.Offset    = context->Eip;
    stackFrame.AddrPC.Mode      = AddrModeFlat;
    stackFrame.AddrFrame.Offset = context->Ebp;
    stackFrame.AddrFrame.Mode   = AddrModeFlat;
    stackFrame.AddrStack.Offset = context->Esp;
    stackFrame.AddrStack.Mode   = AddrModeFlat;

    for (int i = 0; i < maxStackTraceFrames; ++i)
    {
        // 获取堆栈跟踪
        if (!StackWalk(IMAGE_FILE_MACHINE_I386, process, thread, &stackFrame, context, NULL, SymFunctionTableAccess,
                       SymGetModuleBase, NULL))
        {
            break;
        }

        if (!SymFromAddrW(process, stackFrame.AddrPC.Offset, 0, symbolInfo))
        {
            continue;
        }

        IMAGEHLP_LINEW64 lineInfo;
        lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINEW64);
        DWORD displacement;
        if (SymGetLineFromAddrW64(process, stackFrame.AddrPC.Offset, &displacement, &lineInfo))
        {
            stackTraceStr += std::to_wstring(i) + L": " + symbolInfo->Name + L" - " + lineInfo.FileName + L" (" +
                             std::to_wstring(lineInfo.LineNumber) + L")\n";
        }
        else
        {
            stackTraceStr += std::to_wstring(i) + L": " + symbolInfo->Name + L"\n";
        }
    }
#endif // _WIN64
    //free(symbolInfo);
    SymCleanup(process);
    LOGW_ERROR(L"Crash detected. Stack Trace:\n%s", stackTraceStr.c_str());
}
