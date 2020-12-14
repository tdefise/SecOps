# Windows Security Hardening

This page is a summary of security configurations on Windows System that can increase the effort required by an attacker to get perform his actions on objective.

Within the "The Sliding Scale of Cyber Security", I would classify as "Architecture" as it is not system that are added to the environment to add security controls.
This means that they have **the best** return on investment compared to "Passive Defense" or "Active Defense" and are even required both those controls:

- **Passive Defense**: By applying the security controls below, we will leverage existing capabilities and already decrease our attack surface. If additional tools are required, which is often the case, we will be able to focus on specific attack surfaces and be more effective
- **Active Defense**: By applying the security controls below, this will increase the effort required by the attacker(s), which also means that he will most likely let more traces/noises of trying to perform his action on objective.

### Enable "LSA Protection"

The LSA, which includes the Local Security Authority Server Service (LSASS) process, validates users for local and remote sign-ins and enforces local security policies.

LSA Protection is a concept within Microsoft Active Directory allows you configure additional protection for the Local Security Authority (LSA) process to prevent Code injection that could Compromised Credentials.

Within the LSA Protection, you have the **Protected Process Light (PPL) technology**

The Protected Process Light (PPL) technology has been implemented in Windows 8.1, which ensures that the operating system only loads trusted services and processes. They should have an internal or external signature that meets the Windows requirements.

Here is a [guide](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) to configure it.

Mitigations against:

- [T1003 - OS Credential Dumping: LSASS Memory](https://attack.mitre.org/techniques/T1003/001/)
- [T1547.002 - Boot or Logon Autostart Execution: Authentication Package](https://attack.mitre.org/techniques/T1547/002/)
- [T1547.005 - Boot or Logon Autostart Execution: Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [T1547.008 - Boot or Logon Autostart Execution: LSASS Driver](https://attack.mitre.org/techniques/T1547/008/)
- [T1556.001 - Modify Authentication Process: Domain Controller Authentication](https://attack.mitre.org/techniques/T1556/001/)

Detections:

- Unsigned DLLs try to load into the LSA by setting the Registry key *HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe* with AuditLevel = 8.
Here below is how to monitor it with Sysmon

```xml
<RuleGroup name="" groupRelation="or">
    <RegistryEvent onmatch="include">
        <TargetObject condition="begin with">HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe*</TargetObject>
    </RegistryEvent>
</RuleGroup>
```

- Windows Event ID 3033 & 3063 for failed attempts to load LSA plug-ins and drivers.

### Restrict the use of "Mshta.exe"

Mshta.exe is a utility that executes Microsoft HTML Applications (HTA) files.

Adversaries may abuse mshta.exe to proxy execution of malicious .hta files and Javascript or VBScript through a trusted Windows utility.

Mitigations against:

- [T1218.005 - Signed Binary Proxy Execution: Mshta](https://attack.mitre.org/techniques/T1218/005/)

Detections:

- Monitor the use of mshta.exe, here below is how to do it through Sysmon

```xml
<RuleGroup name="" groupRelation="or">
    <NetworkConnect onmatch="include">
        <Image condition="image">mshta.exe</Image>
    </NetworkConnect>
</RuleGroup>
```

- Monitor the use of HTA files, here below is how to do it through Sysmon

```xml
<RuleGroup name="" groupRelation="or">
    <FileCreate onmatch="include">
        <TargetFilename condition="end with">.hta</TargetFilename> 
</FileCreate>
</RuleGroup>
