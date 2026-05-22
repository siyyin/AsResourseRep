@echo on

@rem  example: build.bat Relase/Debug Win32/x64
@echo %~dp0
@rem the .bat path
set build_root=%~dp0 
@rem @echo %build_root% > tempdata.txt
set realbuild_root=%build_root:~0,-1%
set tempzip=bin\HRA*.zip
set zipfiles=%realbuild_root%%tempzip%

@rem @echo %build_root% >> tempdata.txt
@rem @echo %realbuild_root% >> tempdata.txt
@echo %zipfiles% >> tempdata.txt

@echo clean all zip_dir.
@rem cd C:\build\workspace\HRA-build-windows_x64-149.145\windowscode\bin
@rem  /q /f C:\build\workspace\HRA-build-windows_x64-149.145\windowscode\bin\HRA*.zip 2>NUL
del /q /f %zipfiles% 2>NUL
@echo end clean.

@rem set build_config="Debug|Win32"
@rem set build_config=$ALL
@rem set build_config="Release|Win32"
setlocal
set build=Release
set platform=x64
set build_config="%build%|%platform%"

@echo %1
@echo %2


set templib=bin\x64\
set lib_dir=%realbuild_root%%templib%
@echo %lib_dir% >> tempdata.txt 

set vcvars="C:\Program Files (x86)\Microsoft Visual Studio 11.0\VC\vcvarsall.bat"
 
set devenv="C:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\IDE\devenv.exe"
 
@rem set sln path
set thesln=hra.sln
 
@rem set build environment
@rem set vs2012 cli environment
@rem call "%VS90COMNTOOLS%VSVARS32.BAT"
if "%platform%"=="Win32" call %vcvars% x86
if "%platform%"=="x64"	call %vcvars% x86_amd64

echo on 
@echo start build
@echo build_config:%build_config%, Please waiting

rd /s /q %lib_dir% 2>NUL
@%devenv% %thesln% /Clean %build_config% /out build.log
@%devenv% %thesln% /rebuild %build_config% /out build.log
@echo end build
exit /B 0