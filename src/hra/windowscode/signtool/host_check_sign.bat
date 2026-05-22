@echo off
setlocal enabledelayedexpansion
set target_dir=%~1

set /a is_on_same_network_segment=0

REM 读取server_cache.txt文件中的IP地址
for /f "usebackq tokens=1 delims=| " %%a in ("%~d0%~p0\server_cache.txt") do (
    set "ip_address=%%a"
)

REM 移除可能存在的空格
set "ip_address=!ip_address: =!"

REM 提取IP地址的前三个数字
for /f "tokens=1-3 delims=." %%b in ("!ip_address!") do (
    set "ip_subnet=%%b.%%c.%%d"
)

REM 获取本机IP地址和子网掩码
for /f "tokens=2 delims=:" %%f in ('chcp 65001 ^| ipconfig ^| findstr /c:"IPv4 Address"') do (
    set "local_ip=%%f"
    set "local_ip=!local_ip: =!"

    for /f "tokens=1-3 delims=." %%g in ("!local_ip!") do (
        set "local_subnet=%%g.%%h.%%i"
    )

    if "!ip_subnet!"=="!local_subnet!" (
        set /a is_on_same_network_segment=1
        echo The compiler and server are on the same network segment, server IP:!ip_address!, local IP:!local_ip!
    ) else (
        echo The compiler and server are not on the same network segment, server IP:!ip_address!, local IP:!local_ip!
    )
)

if !is_on_same_network_segment!==1 (
    echo is_on_same_network_segment:!is_on_same_network_segment!
    call %~d0%~p0\hrasign.bat !target_dir!
) else (
    echo is_on_same_network_segment:!is_on_same_network_segment!
)

endlocal
