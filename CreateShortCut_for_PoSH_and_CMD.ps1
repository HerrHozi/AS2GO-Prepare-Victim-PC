#Set-ExecutionPolicy -ExecutionPolicy RemoteSigned

$SourceFilePath = "%SystemRoot%\system32\WindowsPowerShell\v1.0\powershell.exe"
$ShortcutPath = "C:\Users\Public\Desktop\PowerShell.lnk"
$WScriptObj = New-Object -ComObject ("WScript.Shell")
$shortcut = $WscriptObj.CreateShortcut($ShortcutPath)
$shortcut.TargetPath = $SourceFilePath
$shortcut.Save()

$SourceFilePath = "%SystemRoot%\system32\cmd.exe"
$ShortcutPath = "C:\Users\Public\Desktop\CMD.lnk"
$WScriptObj = New-Object -ComObject ("WScript.Shell")
$shortcut = $WscriptObj.CreateShortcut($ShortcutPath)
$shortcut.TargetPath = $SourceFilePath
$shortcut.Save()
