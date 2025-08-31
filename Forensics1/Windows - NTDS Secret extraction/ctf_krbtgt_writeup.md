# Extracting krbtgt AES256 Key from NTDS.dit (Windows AD)

## Challenge Description
You have a backup of the registry and NTDS of a Windows server hosting an Active Directory. Your task is to extract its secrets.

**Goal:** The flag is the `aes256-cts-hmac-sha1-96` key of the `krbtgt` account (used for Kerberos ticket encryption).

---

## Provided Files
After extracting the ZIP file, you will have two important files:

- `NTDS.dit` — Contains all AD user accounts and their password hashes.
- `SYSTEM` — Registry hive containing the AD boot key, needed to decrypt NTDS.dit secrets.

---

## Step 1: Prepare Workspace
1. Create a folder and place both `SYSTEM` and `NTDS.dit` inside.
   *This simplifies processing and management, as NTDS.dit needs SYSTEM to decrypt.*

---

## Step 2: Open PowerShell
Run **PowerShell as Administrator**.

---

## Step 3: Install DSInternals Module
```powershell
Install-Module -Name DSInternals -Scope CurrentUser
```
Check if the module is installed:
```powershell
Import-Module DSInternals
```

> If you encounter execution policy errors, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```
*This allows scripts to run without checking signatures or policies.*

---

## Step 4: Extract AD Boot Key
```powershell
$bootKey = Get-BootKey -SystemHiveFilePath "C:\Temp\SYSTEM"
$bootKey
```

---

## Step 5: Query krbtgt Account
Using the extracted boot key, query all accounts from `NTDS.dit`:
```powershell
Get-ADDBAccount -All -DBPath "C:\Temp\ntds.dit" -BootKey $bootKey |
    Where-Object { $_.SamAccountName -eq "krbtgt" }
```

---

## Step 6: Extract AES256 Kerberos Key
Scroll down the output, you will see the `krbtgt` object.
Under **Credentials**, find `KerberosNew`:

```
aes256-cts-hmac-sha1-96 : 85c422e6d4f4e340b445c6a3f16d8d7b25bfdf290d956134bc0d5b6ab272b475
```

---

## ✅ Flag
```
85c422e6d4f4e340b445c6a3f16d8d7b25bfdf290d956134bc0d5b6ab272b475
```

