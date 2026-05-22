# On the command-line the following macros need to be set, with the versions set to match
# the versions in the 3rdParty directory:
#
#  PLATFORM=Win32|x64
#  SLNDIR=Solution Dir
#  3PDIR=<path of '3rdParty' folder>
#  BUILD=Debug|Release
#  PostBuildPrep=<some file to create when done>
#  OUTPUTDIR=HRA_Windows_V1.0.0_x64.zip|HRA_Windows_V1.0.0_x86.zip

#hra version
HRA_VER_MAJOR = 3
HRA_VER_MINOR = 3
HRA_VER_PATCH = 0
HRA_VER_BUILD = 1


!if "$(PLATFORM)" == "x64"
ARCH   = x64
X64X86 = x64
!else
ARCH   = win32
X64X86 = x86
!endif

HRA_VERSION = HRA_Windows_V$(HRA_VER_MAJOR).$(HRA_VER_MINOR).$(HRA_VER_PATCH)_$(HRA_VER_BUILD)_$(X64X86)

ZIP = 7z.exe
ZIPPARA = a

SLN_BIN_DIR = $(SLNDIR)bin\$(ARCH)
HRA_VERSION_DIR = $(SLNDIR)bin\$(HRA_VERSION)
DOLPHIN_VERSION_DIR = $(SLNDIR)bin\$(HRA_VERSION)_dolphin

all: PostBuildPrep
    @echo "ALL"

rebuild: clean all

clean:
    -rd /q /s "$(SLN_BIN_DIR)\patterns\" 2>NUL
    -rd /q /s "$(SLNDIR)\bin\$(HRA_VERSION)" 2>NUL
    -del /q /f "$(SLNDIR)\bin\$(HRA_VERSION).zip" 2>NUL
    -del /q /f "$(SLNDIR)\bin\$(HRA_VERSION)_symbols.zip" 2>NUL
    -rd /q /s "$(DOLPHIN_VERSION_DIR)" 2>NUL
    -del /q /f "$(SLNDIR)bin\$(HRA_VERSION)_dolphin.zip" 2>NUL

PostBuildPrep: PrepareBin SignFile CreateHraZip CreateDolphinZip CreateSymbolsZip
    @-echo %DATE% %TIME%>$@

PrepareBin:
#    copy /y "$(3PDIR)\jsoncpp\$(ARCH)\$(BUILD)\*.dll" "$(SLN_BIN_DIR)\"
    copy /y "$(3PDIR)\openssl\$(ARCH)\$(BUILD)\*.dll" "$(SLN_BIN_DIR)\"
#    copy /y "$(3PDIR)\sqlite3\$(ARCH)\$(BUILD)\*.dll" "$(SLN_BIN_DIR)\"
    copy /y "$(3PDIR)\pugixml\$(ARCH)\$(BUILD)\*.dll" "$(SLN_BIN_DIR)\"
    copy /y "$(3PDIR)\Vaeng\$(ARCH)\*.dll"            "$(SLN_BIN_DIR)\"

    -cd $(SLNDIR)\VersionControl\$(ARCH) && VersionControl.exe
    IF NOT EXIST "$(SLN_BIN_DIR)\config" md "$(SLN_BIN_DIR)\config"
    copy /y "$(SLNDIR)\VersionControl\$(ARCH)\version.ini" "$(SLN_BIN_DIR)\config\"

    IF NOT EXIST "$(SLN_BIN_DIR)\patterns" md "$(SLN_BIN_DIR)\patterns"
    xcopy "$(SLNDIR)\patterns\*" "$(SLN_BIN_DIR)\patterns" /s /e /y

SignFile:
    $(SLNDIR)\signtool\host_check_sign.bat "$(SLN_BIN_DIR)\"

CreateHraZip:
    -rd /q /s "$(SLNDIR)\bin\$(HRA_VERSION)" 2>NUL
    -del /q /f "$(SLNDIR)\bin\$(HRA_VERSION).zip" 2>NUL

    IF NOT EXIST "$(HRA_VERSION_DIR)\Setup" md "$(HRA_VERSION_DIR)\Setup"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\bin" md "$(HRA_VERSION_DIR)\export\bin"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\lib" md "$(HRA_VERSION_DIR)\export\lib"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common" md "$(HRA_VERSION_DIR)\export\include\Common"

    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcClientPlugin.dll" "$(HRA_VERSION_DIR)\export\bin\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcServerPlugin.dll" "$(HRA_VERSION_DIR)\export\bin\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcInterface.dll" "$(HRA_VERSION_DIR)\export\bin\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraInstall.dll" "$(HRA_VERSION_DIR)\export\bin\"

    copy /y "$(SLNDIR)\lib\$(ARCH)\HraIpcClientPlugin.lib" "$(HRA_VERSION_DIR)\export\lib\"
    copy /y "$(SLNDIR)\lib\$(ARCH)\HraIpcServerPlugin.lib" "$(HRA_VERSION_DIR)\export\lib\"
    copy /y "$(SLNDIR)\lib\$(ARCH)\HraIpcInterface.lib" "$(HRA_VERSION_DIR)\export\lib\"
    copy /y "$(SLNDIR)\lib\$(ARCH)\HraInstall.lib" "$(HRA_VERSION_DIR)\export\lib\"

    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcClientPlugin" md "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcClientPlugin"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcServerPlugin" md "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcServerPlugin"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common\HraIpcInterface" md "$(HRA_VERSION_DIR)\export\include\Common\HraIpcInterface"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common\include" md "$(HRA_VERSION_DIR)\export\include\Common\include"
    IF NOT EXIST "$(HRA_VERSION_DIR)\export\include\Common\HraInstall" md "$(HRA_VERSION_DIR)\export\include\Common\HraInstall"

    copy /y "$(SLNDIR)\Common\AsiEsmIpcClientPlugin\*.h" "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcClientPlugin\"
    copy /y "$(SLNDIR)\Common\AsiEsmIpcServerPlugin\*.h" "$(HRA_VERSION_DIR)\export\include\Common\AsiEsmIpcServerPlugin\"
    copy /y "$(SLNDIR)\Common\HraIpcInterface\*.h" "$(HRA_VERSION_DIR)\export\include\Common\HraIpcInterface\"
    copy /y "$(SLNDIR)\Common\include\*.h" "$(HRA_VERSION_DIR)\export\include\Common\include\"
    copy /y "$(SLNDIR)\Common\HraInstall\*.h" "$(HRA_VERSION_DIR)\export\include\Common\HraInstall\"

    copy /y "$(SLNDIR)\bin\$(ARCH)\hra.exe" "$(HRA_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\*.dll" "$(HRA_VERSION_DIR)\Setup\"

    IF NOT EXIST "$(HRA_VERSION_DIR)\Setup\patterns" md "$(HRA_VERSION_DIR)\Setup\patterns"
    xcopy "$(SLNDIR)\patterns\*" "$(HRA_VERSION_DIR)\Setup\patterns\" /s /e /y

    IF NOT EXIST "$(HRA_VERSION_DIR)\Setup\config" md "$(HRA_VERSION_DIR)\Setup\config"
    copy /y  "$(SLNDIR)\VersionControl\$(ARCH)\version.ini" "$(HRA_VERSION_DIR)\Setup\config\"

    -cd C:\Program Files\7-Zip
    $(ZIP) $(ZIPPARA) $(SLNDIR)bin\$(HRA_VERSION).zip $(SLNDIR)bin\$(HRA_VERSION)\\
    
CreateDolphinZip:
    -rd /q /s "$(DOLPHIN_VERSION_DIR)" 2>NUL
    -del /q /f "$(DOLPHIN_VERSION_DIR).zip" 2>NUL

    IF NOT EXIST "$(DOLPHIN_VERSION_DIR)\Setup" md "$(DOLPHIN_VERSION_DIR)\Setup"
    copy /y "$(SLNDIR)\bin\$(ARCH)\hra_dolphin.exe" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\DolphinCore.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraInstall.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcClientPlugin.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcInterface.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\HraIpcServerPlugin.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
#    copy /y "$(SLNDIR)\bin\$(ARCH)\jsoncpp.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
#    copy /y "$(SLNDIR)\bin\$(ARCH)\sqlite3.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"
    copy /y "$(SLNDIR)\bin\$(ARCH)\utility.dll" "$(DOLPHIN_VERSION_DIR)\Setup\"

    -cd C:\Program Files\7-Zip
    $(ZIP) $(ZIPPARA) $(DOLPHIN_VERSION_DIR).zip $(DOLPHIN_VERSION_DIR)\\

CreateSymbolsZip:
    -del /q /f "$(SLNDIR)\bin\$(HRA_VERSION)_symbols.zip" 2>NUL

    -cd C:\Program Files\7-Zip
    $(ZIP) $(ZIPPARA) $(SLNDIR)\bin\$(HRA_VERSION)_symbols.zip $(SLNDIR)\bin\$(ARCH)\\

