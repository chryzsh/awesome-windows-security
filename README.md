# awesome-windows-security
![Pirate](https://3.bp.blogspot.com/-DaVaDpv87-I/WB4SQ4hyZ7I/AAAAAAAAA6w/TamjA3s98FUmp4SXsxoDH0YeoNycV8EYgCLcB/s1600/win.jpg)
List of awesome Windows security resources

This list is for anyone wishing to learn offensive Windows security. The list will for the most part consist of tools available on Github.

The tools are categorized according to Adversarial Tactics and Techniques based on [Mitre ATT&CK](https://attack.mitre.org/wiki/Main_Page). Some tools fit several technqiues and some doesn't quite fit anywhere. I appreciate any help with finding the right tactics and techniques.

You can contribute by sending pull requests, create issues with suggestions or write to me on Twitter [@chryzsh](https://twitter.com/chryzsh).


Table of Contents
=================

* [Initial Access](#-initial-access)
* [Execution](#-execution)
* [Persistence](#-persistence)
* [Privilege Escalation](#-privilege-escalation)
* [Defense Evasion](#-defense-evasion)
* [Credential Access](#-credential-access)
* [Discovery](#-discovery)
* [Lateral Movement](#-lateral-movement)
* [Collection](#-collection)
* [Exfiltration](#-exfiltration)
* [Command and Control](#-command-and-control)
--- 
* [Misc](#-misc)
* [Gitbooks](#-gitbooks)
* [Ebooks](#-ebooks)
* [Defense](#-defense)
* [Twitter](#-twitter)

## [↑](#table-of-contents) Initial Access
### T1203 - Exploitation for Client Execution
* [ruler](https://github.com/sensepost/ruler) - Gain shell through Exchange rules
 
## [↑](#table-of-contents) Execution
### T1047 - Windows Management Instrumentation
* [SharpWMI](https://github.com/GhostPack/SharpWMI) - C# implementation of various WMI functionality.
 
## [↑](#table-of-contents) Persistence
* [WheresMyImplant](https://github.com/0xbadjuju/WheresMyImplant) - Contains the tooling nessessary to gaining and maintain access to target system. It can also be installed as WMI provider for covert long term persistence.

 
## [↑](#table-of-contents) Privilege Escalation 
### General
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/blob/dev/Privesc/PowerUp.ps1) - PowerUp aims to be a clearinghouse of common Windows privilege escalation vectors that rely on misconfigurations.
* [SharpUp](https://github.com/GhostPack/SharpUp) - C# port of various PowerUp functionality.


### [T1068 - Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/)
* [alpc-diaghub](https://github.com/realoriginal/alpc-diaghub) - Utilizing the ALPC Flaw in combiniation with Diagnostics Hub as found in Server 2016 and Windows 10.

### [T1134 - Access Token Manipulation](https://attack.mitre.org/techniques/T1134/)
* [juicy-potato](https://github.com/ohpe/juicy-potato) - Local Privilege Escalation tool, from a Windows Service Accounts to NT AUTHORITY\SYSTEM.
  * [Procedure](https://hunter2.gitbook.io/darthsidious/privilege-escalation/juicy-potato)
  * [Article](https://ohpe.it/juicy-potato/)
* [Tokenvator](https://github.com/0xbadjuju/Tokenvator) - A tool to elevate privilege with Windows Tokens 



## [↑](#table-of-contents) Defense Evasion
* [Invoke-Phant0m](https://github.com/hlldz/Invoke-Phant0m) - This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running.

### T1027 - Obfuscated Files or Information
* [mimikatz_obfuscator.sh](https://gist.github.com/imaibou/92feba3455bf173f123fbe50bbe80781) - Obfuscation tool for Mimikatz.

### T1055 - Process Injection
* [SharpCradle](https://github.com/anthemtotheego/SharpCradle) - Download and execute .NET binaries into memory.

## [↑](#table-of-contents) Credential Access
### [T1208 - Kerberoasting](https://attack.mitre.org/techniques/T1208/)
* [Rubeus](https://github.com/GhostPack/Rubeus) - C# toolset for raw Kerberos interaction and abuses.
  * [Procedure](https://github.com/GhostPack/Rubeus) - Github page
  * [Article](https://www.harmj0y.net/blog/redteaming/from-kekeo-to-rubeus/)
 

### T1081 - Credentials in Files
* [KeeThief](https://github.com/HarmJ0y/KeeThief) - Methods for attacking KeePass 2.X databases, including extracting of encryption key material from memory.
* [SharpCloud](https://github.com/chrismaddalena/SharpCloud) - C# utility for checking for the existence of credential files related to Amazon Web Services, Microsoft Azure, and Google Compute.
* [credgrap_ie_edge](https://github.com/HanseSecure/credgrap_ie_edge) - Extract stored credentials from Internet Explorer and Edge.

### T1214 - Credentials in Registry
* [windows_sshagent_extract](https://github.com/ropnop/windows_sshagent_extract) - PoC code to extract private keys from Windows 10's built in ssh-agent service.

### [↑](#table-of-contents) T1110 - Brute Force
* [MailSniper](https://github.com/dafthack/MailSniper) - Searching through email in a Microsoft Exchange environment for specific terms (passwords, insider intel, network architecture information, etc.)
* [DomainPasswordSpray](https://github.com/dafthack/DomainPasswordSpray) -  PowerShell tool to perform a password spray attack against users of a domain.
* [SprayingToolkit](https://github.com/byt3bl33d3r/SprayingToolkit) - Scripts to make password spraying attacks against Lync/S4B & OWA a lot quicker, less painful and more efficient

### T1003 - Credential Dumping
* [mimikatz](https://github.com/gentilkiwi/mimikatz) - Dumping credentials in Windopws
* [Internal-Monologue](https://github.com/eladshamir/Internal-Monologue) - Retrieving NTLM Hashes without Touching LSASS.
* [lazykatz](https://github.com/bhdresh/lazykatz) - Lazykatz is an automation developed to extract credentials from remote targets protected with AV and/or application whitelisting software.
* [poshkatz](https://github.com/STEALTHbits/poshkatz) - PowerShell module for Mimikatz
* [Powerdump.ps1](https://github.com/rapid7/metasploit-framework/blob/master/data/exploits/powershell/powerdump.ps1) - Dumping SAM from Powershell


### T1171 - LLMNR/NBT-NS Poisoning
* [Responder](https://github.com/lgandx/Responder) - Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
* [Inveigh](https://github.com/Kevin-Robertson/Inveigh) - Windows PowerShell ADIDNS/LLMNR/mDNS/NBNS spoofer/man-in-the-middle tool.
* [InveighZero](https://github.com/Kevin-Robertson/InveighZero) - C# LLMNR/NBNS spoofer

## [↑](#table-of-contents) Discovery
* [PowerView Dev Branch](https://github.com/PowerShellMafia/PowerSploit/tree/dev/Recon) - Enumerating AD with Powershell. The dev branch is specifically recommended for its ability to specify credentials using the `-Credential` option.
* [SharpView](https://github.com/tevora-threat/SharpView) - C# implementation of harmj0y's PowerView
* [BloodHound](https://github.com/BloodHoundAD/BloodHound) - Graphically map Active Directory environment.
* [SharpHound](https://github.com/BloodHoundAD/SharpHound) - The BloodHound C# Ingestor

### T1135 - Network Share Discovery
* [SmbScanner](https://github.com/vletoux/SmbScanner) - A Smb Scanner written in powershell Extracted from PingCastle and adapted to fit in a script. Checks for SMBv1 and SMBv2 (SMBv3 is a dialect of SMBv2).


### T1082 - System Information Discovery
* [Windows-Exploit-Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester) - This tool compares a targets patch levels against the Microsoft vulnerability database in order to detect potential missing patches on the target. It also notifies the user if there are public exploits and Metasploit modules available for the missing bulletins.

* [Watson](https://github.com/rasta-mouse/Watson) - C# implementation for quickly finding missing software patches for local privilege escalation vulnerabilities.


## [↑](#table-of-contents) Lateral Movement
* [Mimikatz Pass-The-Hash](https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa#pth) - `mimikatz` can perform the well-known operation 'Pass-The-Hash' to run a process under another credentials with NTLM hash of the user's password, instead of its real password.
* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) - A swiss army knife for pentesting networks


## [↑](#table-of-contents) Collection
### T1005 - Data from Local System
* [mimikittenz](https://github.com/putterpanda/mimikittenz) - A post-exploitation powershell tool for extracting juicy info from memory.
* [SlackExtract](https://github.com/clr2of8/SlackExtract) - A PowerShell script to download all files, messages and user profiles that a user has access to in slack.



## [↑](#table-of-contents) Exfiltration
### T1048 - Exfiltration Over Alternative Protocol
* [SharpBox](https://github.com/P1CKLES/SharpBox) - C# tool for compressing, encrypting, and exfiltrating data to DropBox using the DropBox API.



## [↑](#table-of-contents) Command and Control
* [Empire](https://github.com/EmpireProject/Empire) - Empire is a PowerShell and Python post-exploitation agent.
* [SILENTTRINITY](https://github.com/byt3bl33d3r/SILENTTRINITY) - A post-exploitation agent powered by Python, IronPython, C#/.NET

## [↑](#table-of-contents) Defense
* [awesome-windows-domain-hardening](https://github.com/PaulSec/awesome-windows-domain-hardening) - A curated list of awesome Security Hardening techniques for Windows.
* [UncoverDCShadow](https://github.com/AlsidOfficial/UncoverDCShadow) - Detect the use of the DCShadow attack.
* [Seatbelt](https://github.com/GhostPack/Seatbelt) - Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives.
* [Pingcastle](https://github.com/vletoux/pingcastle) - Ping Castle is a tool designed to assess quickly the Active Directory security level with a methodology based on risk assessment and a maturity framework.
* [WindowsDefenderATP-Hunting-Queries](https://github.com/Microsoft/WindowsDefenderATP-Hunting-Queries) - Sample queries for Advanced hunting in Windows Defender ATP


## [↑](#table-of-contents) Misc
### Post Exploitation Frameworks & Tools
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit) - A PowerShell Post-Exploitation Framework
* [SharpSploit](https://github.com/cobbr/SharpSploit) - .NET post-exploitation library written in C# that aims to highlight the attack surface of .NET and make the use of offensive .NET easier for red teamers.
* [SharpSploitConsole](https://github.com/anthemtotheego/SharpSploitConsole) - Console Application designed to interact with SharpSploit.
* [SharpAttack](https://github.com/jaredhaight/SharpAttack) - A simple wrapper for C# tools. It contains commands for domain enumeration, code execution, and other fun things.
* [LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) -  every binary, script, and library that can be used for Living Off The Land techniques.
* [DeathStar](https://github.com/byt3bl33d3r/DeathStar) - Automate getting Domain Admin using Empire


### Exploit Development
* [awesome-windows-kernel-security-development](https://github.com/ExpLife0011/awesome-windows-kernel-security-development)
* [awesome-windows-exploitation](https://github.com/enddo/awesome-windows-exploitation) - A curated list of awesome Windows Exploitation resources, and shiny things.
* [PowerShellArsenal](https://github.com/mattifestation/PowerShellArsenal) - A PowerShell Module Dedicated to Reverse Engineering
* [SharpCompile](https://github.com/SpiderLabs/SharpCompile) - SharpCompile is an aggressor script for Cobalt Strike which allows you to compile and execute C# in realtime.
* [SharpGen](https://github.com/cobbr/SharpGen) - SharpGen is a .NET Core console application that utilizes the Rosyln C# compiler to quickly cross-compile .NET Framework console applications or libraries.

## [↑](#table-of-contents) Red Team
* [Awesome-Red-Teaming](https://github.com/yeyintminthuhtut/Awesome-Red-Teaming)
* [Red Tips of Vysec](https://github.com/vysec/RedTips)
* [Planning a Red Team exercise](https://github.com/magoo/redteam-plan)
* [atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
* [Red-Team-Infrastructure-Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)

## [↑](#table-of-contents) Gitbooks
* [Vincentyiu](https://vincentyiu.co.uk)
* [ired.team](https://ired.team)
* [DarthSidious](https://hunter2.gitbook.io/darthsidious)

## [↑](#table-of-contents) Ebooks
* [Advanced Penetration Testing: Hacking the World's Most Secure Networks](https://www.amazon.com/Advanced-Penetration-Testing-Hacking-Networks/dp/1119367689)
* [Windows Internals, Part 1: System architecture, processes, threads, memory management, and more (7th Edition)](https://www.amazon.com/Windows-Internals-Part-architecture-management/dp/0735684189)



## [↑](#table-of-contents) Twitter
* [Nikhil Mittal - @nikhil_mitt](https://twitter.com/nikhil_mitt)
* [Marcello - @byt3bl33d3r](https://twitter.com/byt3bl33d3r)
* [Sean Metcalf - @PyroTek3](https://twitter.com/PyroTek3)
* [Vincent Yiu - @vysecurity](https://twitter.com/vysecurity)
* [Cn33liz - @Cneelis](https://twitter.com/Cneelis)
* [Rasta Mouse - @_RastaMouse](https://twitter.com/_RastaMouse)
* [SpecterOps - @SpecterOps](https://twitter.com/SpecterOps)
