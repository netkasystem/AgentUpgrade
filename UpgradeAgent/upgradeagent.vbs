Dim WShell
Set WShell = CreateObject("WScript.Shell")
WShell.Run "C:\UpgradeAgent\upgrade_agent.exe", 0
Set WShell = Nothing