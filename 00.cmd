rem save in c:\windows\system32 on VICTIM PC
mode con:cols=150 lines=300
cd c:\temp\AS2Go
color 08
title Attack Scenario to GO - along the kill-chain
cls
whoami
dir %logonserver%\c$
dir \\admin-pc\c$
dsquery group -samid "Schema Admins" | dsget group -members -expand
pause
cls
powershell.exe -file .\AS2Go.ps1

