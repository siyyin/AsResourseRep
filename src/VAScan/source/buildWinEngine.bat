@echo off

SET VS2012_DIR=%~1\Common7\IDE\devenv
SET WorkingSpace=%~2

"%VS2012_DIR%" %WorkingSpace%\source\VAScan.sln /rebuild "Release|win32"
"%VS2012_DIR%" %WorkingSpace%\source\VAScan.sln /rebuild "Release|x64"


E:\build\workspace\sign_tool\Sign_Client\Sign.pl xsha2 en "%WorkingSpace%\output\win32\libvaeng.dll"
E:\build\workspace\sign_tool\Sign_Client\Sign.pl xsha2 en "%WorkingSpace%\output\x64\libvaeng.dll"


cd %WorkingSpace%
cd output
mkdir win32
mkdir x64
cd ..
cd %WorkingSpace%\source\pattern
copy vawinp$* ..\..\output\x64\
copy vawinp$* ..\..\output\win32\