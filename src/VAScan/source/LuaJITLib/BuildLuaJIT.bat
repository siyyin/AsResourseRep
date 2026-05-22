@ECHO OFF
REM The following arguments will be passed in
REM
REM %1 = Solution Directory
REM %2 = VC Installation Directory
REM %3 = Release | Debug
REM %4 = win32 | x64
REM %5 = static | nothing

REM 

SET SOLUTIONDIR=%~1
SET VCINSTALLDIR=%~2
SET MODE=%~3
SET PLATFORM=%~4
REM SET LINK=%~5

IF /I "%PLATFORM%" EQU "win32" (
	ECHO call "%VCINSTALLDIR%vcvarsall.bat" x86
	call "%VCINSTALLDIR%vcvarsall.bat" x86 
) ELSE (
	IF /I "%PLATFORM%" EQU "x64" (
		ECHO call "%VCINSTALLDIR%vcvarsall.bat" x86_amd64
		call "%VCINSTALLDIR%vcvarsall.bat" x86_amd64
	) ELSE (
		ECHO Invalid parameter for Platform
		GOTO ERROR_HANDLE
	)
)

CD %SOLUTIONDIR%3rd-party\lua\luajit\LuaJIT-2.0.5\src
IF /I "%MODE%" EQU "Release" (
	ECHO call "%SOLUTIONDIR%3rd-party\lua\luajit\LuaJIT-2.0.5\src\msvcbuild.bat" static
	call "%SOLUTIONDIR%3rd-party\lua\luajit\LuaJIT-2.0.5\src\msvcbuild.bat" static
) ELSE (
	IF /I "%MODE%" EQU "Debug" (
		ECHO call "%SOLUTIONDIR%3rd-party\lua\luajit\LuaJIT-2.0.5\src\msvcbuild.bat" debug static
		call "%SOLUTIONDIR%3rd-party\lua\luajit\LuaJIT-2.0.5\src\msvcbuild.bat" debug static
	) ELSE (
			ECHO Invalid parameter for Mode
			GOTO ERROR_HANDLE
	)
)

:END_HANDLE
EXIT /B

:ERROR_HANDLE
ECHO Error found!
EXIT %ERRORLEVEL%
