Const HIDDEN_WINDOW = 12 
 
strComputer = "." 
Set objWMIService = GetObject("winmgmts:" _ 
    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2") 
Set objStartup = objWMIService.Get("Win32_ProcessStartup") 
 
Set objConfig = objStartup.SpawnInstance_ 
objConfig.ShowWindow = HIDDEN_WINDOW 
Set objProcess = GetObject("winmgmts:root\cimv2:Win32_Process") 
errReturn = objProcess.Create("C:\pombo\python\python.exe C:\pombo\pombo.py", null, objConfig, intProcessID) 
