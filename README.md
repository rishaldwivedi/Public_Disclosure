# Public_Disclosure
Sharing POC's of latest discovery


# MSI Dragon Center EOP (CVE-2020-13149)


**Vulnerability** – Local Privilege escalation due to weak ACL

**Vulnerable Version** – Dragon Center 2 - 2.5.1905.3001  & Prior

**Fixed Version** – Dragon Center 2 - 2.6.x & Later 

**Vulnerable Binaries** – Dragon Center.exe (C:\Program Files (x86)\MSI\MSI Remind Manager)

**Vulnerability Description** – There are insecure file permissions on "C:\ProgramData\MSI\Dragon Center" folder in Dragon Center Software, shipped with MSI Gaming laptops, allowing local authenticated users to overwrite system files and gain escalated privileges & also bypass controls to change software settings, allowing execution of malware planted in the same directory. This issue affects 2.5.1905.3001 & Prior versions of Dragon Center. This affects the integrity of the system.

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
- Now next time the Dragon Center is ran by the administrator & if he attempts to change Battery settings, a Boolean value will be written to the battery.txt, which now points to the protected.dll (symlink), thereby corrupting the dll.

---

# MSI Dragon Center - Hardcoded Keys & Credentials (Vendor never acknowledged)


**Vulnerability** – Hardcoded API Keys & Credentials

**Vulnerable Version** – Dragon Center 2 - 2.5.1905.3001  & Prior

**Fixed Version** – Dragon Center 2 - 2.6.x & Later 

**Vulnerable Binaries** – Dragon Center.exe (C:\Program Files (x86)\MSI\MSI Remind Manager)

**Vulnerability Description** – The Binary after being decompiled, revels the complete source. Upon analysis, it was reveled that it contained a hardcoded Credentials & API Key for the domain https://register.msi.com/rest/. 

**Available exploit/Steps to Reproduce** – 
- Using a tool named dnSpy, load the .NET binary & attempt to decompile it.
- Upon successful decompilation, navigate to MainWindow class routine & search for keyword “/rest”
- You can find the API request with the API Keys to access & the credentials. 
- Now an attacker can simply navigate to https://register.msi.com/rest/ & login.

---

# qdPM RCE (CVE-2020-7246)


**Vulnerability** – Path Traversal & Improper Access Control leading to RCE

**Vulnerable Version** – qdPM - 9.1 & prior

**Fixed Version** – 

**Vulnerability Description** – An attacker (user with least privilege) can abuse the remove profile photo functionality to traverse through other directories & delete files on the server. In a attack scenario, it's possible to delete exsisting “.htaccess” file in the uploads & user directory, which would allow bypassing protection applied against running dangerous file types (php, html, exe). Leveraging this, it's possible to upload a php backdoor, gaining ability to execute commands on the server.

**Available exploit** - 
- Working exploit is available at - https://www.exploit-db.com/exploits/47954.
  `python qdPM-exploit.py -url http://IPADDRESS -u test1@localhost.com -p test1`
- Also this CVE has been fetured in AttackDefence Lab - https://www.attackdefense.com/challengedetailsnoauth?cid=1690

---

# Zoneminder (CVE-2019-6991)


**Vulnerability** – Classic Stack overflow vulnerability 

**Vulnerable Version** – 1.33.1 & Prior

**Fixed Version** – 

**Affected Binary** – zmu

**Vulnerability Description** – The vulnerability exists in function zmLoadUser(), in zm_user.cpp, while authenticating the user. The vulnerability exists in the login functionality. Once a username & password is supplied to the zmu binary, the username & password is passed through mysql_real_escape_string() function in order to produce an escaped SQL string. Due to absense of any protection and limitation placed to the length of username & password, there exists a stack based buffer overflow. 

Find more info at - 
- https://github.com/ZoneMinder/zoneminder/issues/2478
- https://github.com/ZoneMinder/zoneminder/pull/2482

---
**Available exploit** - 
- Working exploitation steps can be found at - https://www.sechustle.com/2020/01/discovering-exploiting-stack-overflow.html



