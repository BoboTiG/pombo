Set WshShell = WScript.CreateObject("WScript.Shell")
obj = WshShell.Run("C:\pombo\python\svhost.exe C:\pombo\pombo.py", 0)
set WshShell = Nothing
