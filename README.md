# AS2GO-Prepare-Victim-PC
Files to prepare the AS2GO | Victim PC
Find more information here in my blog post [AS2Go | Lab Setup | Victim PC](https://herrhozi.com/2022/01/06/as2go-lab-setup-victim-pc/). 

Download the zip file and extract them to c:\Temp\AS2Go


## More Tools needed


Warning
  ```sh
  The following tools are presented for research purposes only. 
  I cannot and does not guarantee or warranty their behavior. 
  They are subject to change without notice. 
  These tools should be run in a test lab environment only.
  ```


- [latest release of Mimikatz.exe](https://github.com/gentilkiwi/mimikatz/releases/)
- [latest release of NetSees.exe](https://www.joeware.net/freetools/tools/netsess/)
- [latest release of Psexec.exe](https://docs.microsoft.com/en-us/sysinternals/downloads/psexec/)
- [latest release of Certify.exe](https://github.com/GhostPack/Certify/)
- [latest release of Rubeus.exe](https://github.com/GhostPack/Rubeus/)
- [latest release of OpenSSL.exe](https://www.openssl.org//)




## Quick Start Guide
Open a Admin PowerShell terminal. The following command simulate some domain activities creates valid tickets.
```PowerShell
AS2Go.ps1
```


![2022-09-20_213311](https://user-images.githubusercontent.com/96825160/191348294-84299b4b-f070-4a4e-8e94-196752335d6d.png)


## What's New 

### .... with v3.0:

- add a new Domain Compromise & Persistence action
  - Manipulating Group Policy Templates (GPT) files
    - setting User Rights Assignment
    - adding Domain Users to Local Admins
    - adding a Schedule Task

### .... with v2.9:

- Update and Improve Function Get-VulnerableCertificateTemplate

### .... with v2.8:
- Attack Compatibility Matrix – 
- New Privilege Escalation – Credential Theft through Memory Access
- many  improvements, e.g. da-xxxx.pem file will be automatically created during Force Authentication Certificate attack
- Update AS2Go.xml schema
- Update Golden Ticket Attack

### .... with v2.6:

- New Cyber Attacks Methods
  - Steal or Forge Authentication Certificates
  - Kerberoasting
  - Password Spray
- new color schema (syntax highlighting, especially for the commands)
- many  improvements, e.g. added switch ‘| out-host’ to see the results from sub functions directy
- Update setup scripts
  - New-AS2GoUsers.ps1, creates a new set of AS2Go Users – see more details here
  - New-AS2GoOUs.ps1, create the  AS2Go OU structure incl. Tiering Model – see more details here

![As2Go-Preview-01](https://user-images.githubusercontent.com/96825160/203348771-4aa6f28c-6136-419f-989c-a206ceac6d1f.gif)

