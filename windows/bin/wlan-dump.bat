@echo off

rem Pombo - a try to list wireless networks on Windows XP using wlan.exe.
rem Tool: www.symantec.com/connect/sites/default/files/WLAN.zip
rem Use : copy wlan.exe into C:\WINDOWS\system32\ and launch this script.

for /f "tokens=1,2" %%A in ('wlan ei ^| findstr "GUID:"') do (
	set eth=%%A
	if "%%A" == "GUID:" set eth=%%B
	if not "%eth%" == "GUID:" call :_dump
)
if "%eth%" == "" echo No interface found.
exit 0

:_dump
echo Interface %eth%
wlan qi %eth%
echo.
wlan gvl %eth%
echo.
echo.
goto :eof