# Public_Disclosure
Sharing POC's of latest discovery


# MSI Dragon Center EOP 


**Vulnerability** – Local Privilege escalation due to weak ACL

**Vulnerabile Version** – 2.6.2003.2401 

**Vulnerable Binaries** – Dragon Center.exe (C:\Program Files (x86)\MSI\MSI Remind Manager)

**Vulnerability Description** – There are insecure file permissions on "C:\ProgramData\MSI\Dragon Center" folder in Dragon Center Software, shipped with MSI Gaming laptops, allowing local authenticated users to overwrite system files and gain escalated privileges & also bypass controls to change software settings, allowing execution of malware planted in the same directory. This issue affects 2.6.2003.2401 version of Dragon Center. This affects the integrity of the system.

---
**Normal Attack Scenario to Bypass control** - An attacker can carry out a very simple attack, bypassing the controls to change certain settings of Dragon Center, which he doesn't has access to. 

    Steps to reproduce –
- Create two users in windows, one belonging to administrator group & other a normal user group. The software runs with administrator privileges; hence will be prompted with a password if user tries accessing it. As a user, you don’t have admin’s password, still we can manage to change few settings of Dragon Center by manipulating certain files located in “C:\ProgramData\MSI\Dragon Center”. The problem here being, the permissive ACL.

  `Scenario 1` - To change Battery Master settings via user account, change the value stored in BatteryMaster.txt. Value 0 points to the first option under Battery Master that is “Best for Mobility” & other as 1,2 mapping to the later options.

  `Scenario 2` - To Change Recommended Apps under “Tools & Help”, change the value inside Apps.json. Here what an attacker can achieve is, he can place a malware binary inside the same directory as App.json, as that directory is also writable by the attacker (Normal user). Now he will also replace the path of the existing Recommended App binary, that is the legitimate binary, with the one (malware) he planted in the same directory. To make it look more legitimate, the attacker will use the same Icon file as the legitimate one.
  

**Advanced Attack Scenario for EOP** - An attacker can carry out an advanced attack, allowing a normal user to delete arbitrary system level files, which normally can’t be done, as he doesn’t has write access.

    Steps to reproduce –
- Empty out “C:\ProgramData\MSI\Dragon Center”
- Create a symlink of the arbitrary file (C:\Windows\System32\protected.dll) to the RPC object (\\RPC Control\\battery.txt).
- Next, Mounting the RPC directory "\\RPC Control" to “C:\ProgramData\MSI\Dragon Center”
- Now next time the Dragon Center is ran by the administrator & if he attempts to change Battery settings, a Boolean value will be written to the battery.txt, which now points to the proteted.dll (symlink), thereby corrupting the dll.

---
