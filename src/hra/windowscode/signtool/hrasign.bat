@echo off
set target_dir=%~1
if not exist %target_dir% (
    echo ERROR:Path not exist! path:%target_dir%
    exit /b
)

for /R %target_dir% %%s in (*.exe *.dll) do (
    call perl %~d0%~p0Sign.pl sha2 en %%s
)

exit /b 0