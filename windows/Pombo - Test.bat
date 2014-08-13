@echo off
python\svchost.exe pombo.py check
if "%1" == "/silent" goto end

echo.
echo.
pause

:end
exit
