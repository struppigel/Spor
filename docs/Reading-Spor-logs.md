# Reading Spor logs: a guide for helpers

This guide is for people who help others with malware problems and use Spor for malware removal. 

Spor only reads. It changes nothing on the PC, so it is safe to ask anyone to run it. 

---

## 1. Check the header first

The first lines tell you whether the log is complete.

```
Created:   2026-11-18 07:49:43 UTC (local time 08:49, UTC+01:00)
Computer:  DESKTOP-4K2M7QX, Windows 11 Home 26H2, build 26300.9974, 64-bit
Run by:    anna (administrator)
Machine SID: S-1-5-21-1111111111-2222222222-3333333333
Users:     anna
Options:   last 30 days, whitelist on, SHA256 hashes of files up to 500 MB
Times:     UTC
```

| Line | What to check |
|---|---|
| `Run by` | Must say `(administrator)`. Without admin rights most sources are missing. Ask for a new run as administrator. |
| `Times` | **All times in the log are UTC.** Use the local time in `Created` to convert them when you talk to the user, e.g. 08:49 local is 07:49 UTC. |
| `Options` | The time window, 30 days by default. If the infection is older, ask for a run with a longer time window. `whitelist on` means that known good files are hidden, see section 7. |
| `Error:` lines | Something went wrong before the scan. Sections can also end with `--- Errors ---`. An error means that part may be incomplete. |

The last line, `End of log. Scan took … (prefetch 9.4 s, …)`, lists every module that ran. If a module is missing, it was switched off.

---

## 2. How a line is built

Spor logs look as follows:

```
time [sources] item [status] => details <==== flags
```

Every part except the item is left out when it is empty.

```
2026-11-14 14:07:32 [PF DL] C:\Users\anna\Desktop\kprm_3.3.1.exe [gone] => Brave from download.toolslib.net/…, page toolslib.net/… <==== !double-extension
└─ time (UTC) ────┘ └─────┘ └─ the file ────────────────────────┘ └────┘    └─ details ───────────────────────────────────────┘ └─ flags ────────────┘
                    sources                                        status
```

- **time**: when it happened, in UTC
- **[sources]**: which Windows artifacts saw it, see section 4. Several tags mean several independent sources agree.
- **item**: a full path, a command or an event text
- **[status]**: only if something is not normal, see section 5. No status means the file is there and validly signed, or it is not a program.
- **=> details**: more facts as `name value; name value`
- **<==== flags**: Spor's warnings, see section 6. Lines with flags other than `!lolbin` are also in the SUMMARY.

Other lines:

| Line | Meaning |
|---|---|
| `==================== Title ====` | Section |
| `--- title ---` | Sub-section |
| `(text)` | Comment. `(line: …)` names the parts of the lines below it. `(none…)` means nothing was found. |
| `    key: value` | Indented, belongs to the line above (`loaded:`, `path:`, `action:`, `dll:`, …) |

Persistence lines start with the kind of entry and use `=>` for the program that runs:

```
2026-11-18 04:50:37 [run] HKU\anna\Software\Microsoft\Windows\CurrentVersion\Run\Discord => C:\Users\anna\AppData\Local\Discord\Update.exe [unsigned], arguments --processStart Discord.exe; value Discord
└─ key changed ───┘ └kind┘ └─ the Run entry ────────────────────────────────────────┘    └─ what it starts ───────────────────────────────┘ └ status ┘ └ details ─────────────────────────────────────┘
```

---

## 3. Reading order

1. **SUMMARY**: everything Spor flagged.
2. **TIMELINE**: This allows you to reconstruct what happened, starting with newest first. Find the first suspicious event, then read what happened before and after.
3. **The sections**: Contains more details about the entries in the timeline (loaded files, persistence entries, accounts, network use). Look at these to enrich your findings from the summary and timeline.
4. **FILES**: hash, signature and version of every file in the log, one line each. Use it to look up files, e.g. on VirusTotal.
5. **LEGEND**: what every source tag, status word and flag means.

---

## 4. Sources: what each tag proves

Not every source means that a file ran. A file that Windows only *recorded* is no proof of an infection.

| Tag | Source | Proves |
|---|---|---|
| `PF` | Prefetch | **ran**, with up to the last 8 run times |
| `PCA` | Program Compatibility Assistant | **ran**, sometimes with an exit code like `Abnormal process exit` or `Installer failed` |
| `UA` | UserAssist | **started by the user** from Explorer or the Start menu (`UA 5x` means 5 times) |
| `BAM` | Background Activity Moderator | **ran**, last time per user |
| `SRU` | SRUM | **was active and used the network** (first activity in the time window, data sent) |
| `MPL` | Defender log | Defender **looked the file up in the cloud**, usually because it ran or was written |
| `AM` | Amcache | Windows **recorded** the file. It was there, but did not necessarily run. |
| `SC` | ShimCache | file **modified**, often that means dropped. No proof of execution on Windows 10 and 11. |
| `NEW` | file system | file **created**, with the download URL from Zone.Identifier if there is one |
| `STP` | change journal, NTFS times | **timestamps were set**, maybe faked |
| `DL` | browser history | **downloaded**, with the URL and the page it came from |
| `OPN` | Recent folder, WebCache | **opened** in Explorer |
| `ISO` | VHDMP log | disk image (ISO, IMG, VHD) **mounted** |
| `ARC` | WinRAR and 7-Zip history | archive opened or extracted |
| `INS` | Uninstall keys, Windows Installer log | software **installed, updated or removed** |
| `AUT` `SVC` `TSK` `STA` `DRV` | Run keys, services, tasks, Startup folder, drivers | **persistence** created or changed |
| `DEF` `LOG` `USR` | Defender, event logs, accounts | detections, setting changes, cleared logs, account changes |
| `CAM` `MIC` | capability store | webcam or microphone used, and until when |
| `RUN` `ADR` `PSH` | Run dialog, address bar, PowerShell history | commands that were typed or pasted (ClickFix) |
| `RMM` | remote access tools | activity of AnyDesk, TeamViewer, ScreenConnect, … |

Several execution sources on one line, e.g. `[PF PCA UA BAM]`, are strong evidence. A file that only `[AM]` or `[SC]` saw may never have run.

If several sources see a file within 2 minutes, it is **one** line. A file that was seen many times shows the first and the last time, with `+N more times since …`.
If the same file was in folders that only differ in numbers (version folders, dated temp folders), the line says `in N folders that differ only in numbers, all listed below` and every real path follows as an indented `path:` line. **Use these `path:` lines for removal.**

---

## 5. Status words

| Status | Meaning | What to do |
|---|---|---|
| *(none)* | file is there, validly signed or not a program | – |
| `gone` | deleted since | Normal for installers, updates and temp files. Malware may have deleted itself, or Defender removed it (see DEFENDER). The SHA1 in AMCACHE FILES can still identify it. |
| `unsigned` | program without a signature | Common for games, open source tools, Git's `usr\bin` tools and Python launchers. Suspicious in AppData, Temp or ProgramData, or with a misleading name. |
| `invalid signature` | the signature does not verify | **Look closely.** FILES has the reason (`note …`): `file changed after signing` means a patched or infected file, `untrusted root` means self-signed. |
| `revoked signature` | the certificate was revoked or distrusted | **Strong warning sign.** Stolen certificates get revoked. |
| `expired signature` | the certificate expired and there is no timestamp | Old software, or malware signed with a leaked old certificate |
| `no access` | Spor could not read the file | Locked or protected. This is no verdict either way. |
| `volume not mounted` | the drive is not there now | USB stick, VeraCrypt volume, removed drive |
| `> N MB, not hashed` | bigger than the hash limit | – |

---

## 6. Flags

| Flag | Meaning | How worried to be |
|---|---|---|
| `!lolbin` | a Windows tool that malware likes to use (powershell, mshta, rundll32, regsvr32, cmd, certutil, …) | **Not on its own.** These are normal on many PCs. Look at what it ran: the arguments of a persistence entry, the PowerShell history, the files around it in the timeline. The SUMMARY lists all LOLBins in one line. |
| `!double-extension` | `invoice.pdf.exe` | High |
| `!RLO` | right-to-left override in the name, shown as `<RLO>` | High |
| `!in-folder-named-like-file` | `x.exe\evil.dll`, `app.exe.local\x.dll` | High, DLL hijacking |
| `!renamed-lolbin` | a Windows tool under another name (original name from Amcache) | High |
| `!suspicious` | a command that downloads or runs code (Run dialog, address bar, PowerShell history) | High, typical for **ClickFix** (fake CAPTCHA: "press Win+R, Ctrl+V, Enter") |
| `!kept-despite-warning` | the browser warned and the user kept the download | Medium to high |
| `!timestomped` | file timestamps were probably faked | Medium to high for programs and scripts. Read the signals. |
| `!defender-off` | real-time protection or another protection was turned off | High, unless the user did it |
| `!defender-exclusion` | Defender exclusion added or changed | **Ask the user.** Malware adds exclusions for its folder, but many power users add their own, e.g. for Downloads or project folders. |
| `!not-removed` | Defender could not remove a detection | High |
| `!log-cleared` | an event log was cleared | High, anti-forensics |
| `!hidden-account` | account hidden from the sign-in screen | High, backdoor account |
| `!com-hijack` | a per-user COM registration overrides the machine one (COM handler of a scheduled task) | High |
| `!unsigned`, `!outside-driver-folders` | driver without a valid signature, or loaded from an unusual folder | High for drivers (rootkits) |
| `!from-web` | a Store or MSIX app was installed from a web page (App Installer link) | High, this is a known way to deliver malware. Check the source URL and the signer. |
| `!log-syntax-in-name` | the path contains ` => ` or text like `[gone]` | High, the name was made to mislead someone who reads the log |

---

## 7. The whitelist

With `whitelist on`, Spor hides what is almost always harmless, so that the log stays readable. A folder alone is never enough: a hidden program must also be validly signed. LOLBins, interpreters like python or node, and flagged files are never hidden.

Hidden files are counted, e.g. in `(Hidden: …)` lines in the timeline and in `--- Hidden: known-noise locations ---` at the end of a section.

Ask for a run with the whitelist off (uncheck *Whitelist*, or `-nowhitelist`) if:

* the user has symptoms but the log shows nothing
* you suspect that a signed tool is abused
* a hidden count looks odd, e.g. a surprising number of files in a folder

---

## 8. Section by section

### SUMMARY
Flagged timeline lines (`[timeline …]`) and findings from the sections (`[Persistence]`, `[Defender]`, …). Every line is a starting point, not a verdict.

### TIMELINE
Look for **clusters**: a download (`DL`), the file starts (`PF PCA BAM`), new files (`NEW`) in AppData, ProgramData or Temp, a task or Run key (`TSK`, `AUT`), network use (`SRU`). Typical chains are:

- **Fake installer or cracked software**: `DL` of a zip or exe from a file hoster, `ARC` extraction, `PF` run from Downloads, Desktop or Temp, `NEW` files in `AppData\Roaming\<random>\`, then `TSK` or `AUT` persistence
- **ClickFix**: `RUN` (Run dialog) or `PSH` (PowerShell history) with `!suspicious`, `PF` of powershell or mshta, `NEW` files, then persistence
- **Infostealer**: one run of an unknown program, little persistence, but `SRU` shows data sent. The program is often `gone` afterwards.
- **RAT or remote access**: a remote access tool (`RMM`, REMOTE ACCESS section) that the user did not install, with incoming connections

### PREFETCH
`Files loaded by programs run in the last 30 days` shows which programs loaded executables or scripts from outside Windows and Program Files. Look for a normal program that loads a DLL from AppData or Temp (DLL sideloading), and for scripts loaded by `wscript`, `mshta` or `powershell`.

### AMCACHE
- `Drivers that are unsigned or outside the driver folders` is important for rootkits.
- `Entries without path`: Windows only stored the name and the SHA1. The name is often cut to 16 characters and shown with `…`. Useful for files that are deleted already.
- `Inventory scans`: files that Windows recorded in bulk. This is no proof of execution.

### EXECUTION EVIDENCE
Programs that ran (PCA, UserAssist, BAM, ShimCache) are in the timeline. The `Compatibility Assistant` list shows programs that ran **at some point**, without a time, and are gone now. Useful for older infections outside the time window.

### NEW FILES
Programs, scripts and archives created in the time window in Downloads, Desktop, Documents, Temp, AppData, ProgramData and Public, with the download URL if Windows saved one. A folder with many new files is one line with all names (installers). Downloaded files always get their own line.

This section also lists programs and scripts that look old but whose NTFS change time is recent. A single file like that is flagged (`STP … times set back <==== !timestomped`). A batch of 3 or more such files in one folder within a minute is one line without a flag, because installers and updaters copy files with their original times.

### TIMESTOMPING
Files whose timestamps were set, from the NTFS change journal. The journal is a ring buffer, on a busy PC it may only cover a few hours. The log says how far back it goes. Every file has a score and the signals. Round times on programs and scripts in user folders are the interesting ones.

### DOWNLOADS AND OPENED FILES
Browser downloads with the URL and the page, files opened in Explorer, mounted disk images and archives opened with WinRAR or 7-Zip. Malware often comes as ISO or IMG to avoid the "downloaded from the internet" warning.
Take a look at downloads from file hosters (gofile, mega, mediafire, discord cdn), from "free software" sites, and at password-protected archives.

### SOFTWARE
Programs installed, updated or removed in the time window, from the Uninstall entries and the Windows Installer log. The Installer log also has software that is gone now.
Look for software the user does not remember installing, remote access tools, "PDF/driver/system optimizer" tools, browser add-on bundles, and per-user installs into AppData, which need no admin rights.

Store and MSIX apps are listed with the operation (Add, Register, Remove or FAILED), where the package came from, whether it runs with full trust and its signature now. **An app installed from a web page is flagged `!from-web`.** Fake "App Installer" pages are a known way to deliver malware as an MSIX package.

A removal right before you got the log can mean that the user or the malware already uninstalled something.

### PERSISTENCE
Run keys (all entries), services and tasks outside trusted locations, recently installed services (event 7045), Task Scheduler events (also **deleted** tasks), Startup folders and WMI subscriptions.
Look for programs in AppData, ProgramData or Temp, random names, hidden tasks (`info: hidden`), and arguments that run scripts or encoded PowerShell. Services hosted by svchost.exe have an indented `dll:` line with the DLL that actually runs.

**Not covered yet:** Winlogon `Shell` and `Userinit`, Image File Execution Options, AppInit_DLLs, Active Setup, LSA packages, print monitors and browser extensions. Check those with other tools.

### DEFENDER
Detections (`1116`), actions (`1117`), failures (`!not-removed`), protection turned off, exclusions (current list and changes), cloud lookups from MPLog and cleared event logs.
`Defender detection history deleted N times`: Defender also does this by itself after 15 days. Many deletions right after a detection are suspicious.

### CLICKFIX
Run dialog history, Explorer address bar commands and PowerShell history (all suspicious lines and the last 15). PowerShell never saves lines with words like `password` or `token`, so an empty history does not prove that nothing was pasted.

### REMOTE ACCESS
Webcam and microphone use per program, and traces of AnyDesk, TeamViewer, ScreenConnect, RustDesk, NetSupport, Atera, MeshAgent and others: connection logs, server and account settings, file transfers.
**Ask the user whether they know the tool and the connections.** Scammers use legitimate remote access tools.

### NETWORK
- SRUM: data sent and received per program in the time window. A lot of `sent` data for an unknown program can mean stolen data.
- Connections now: programs outside trusted locations, LOLBins and unsigned programs.
- DNS cache: recent lookups of remote access, tunnel, paste and file sharing, bot API (Telegram, Discord webhooks) and IP lookup services. Many of them are normal, so combine them with the timeline.

### ACCOUNTS
Local accounts, last sign-in, members of Administrators and account changes. Look for new accounts, unknown administrators and hidden accounts.

### FILES and AMCACHE FILES
One line per file: hash, signature status, signer, certificate thumbprint, version information and the SHA1 that Amcache recorded. If the Amcache SHA1 differs from the file now, the file was replaced after Windows recorded it.
AMCACHE FILES lists the SHA1 of files that are not on disk anymore. Use them to look up deleted malware.

---

## 9. Normal on a clean PC

Expect these and don't report them as malware without more evidence:

- LOLBins in the timeline (powershell, cmd, msiexec, rundll32, schtasks, wsl, curl, …)
- Unsigned programs from Git (`Program Files\Git\usr\bin`), PostgreSQL, 7-Zip, HandBrake, MakeMKV, games (Steam, itch.io), Python `Scripts\*.exe` launchers and developer tools
- Old versions of updated programs shown as `gone`, e.g. Discord `app-1.0.xxxx`, VS Code extensions, Edge WebView
- Installers in Downloads and on the Desktop
- `Defender detection history deleted` now and then
- Disk images mounted by virtual machines (WSL, Docker, Hyper-V)
- Defender detections of files that the user analyses on purpose, e.g. if they are malware researchers or use security tools

---

## 10. Before you remove anything

- **Use the exact paths from the log.** For grouped lines use every indented `path:` line, not only the first one.
- **Check `[status]`**: `gone` files need no removal, but their persistence (Run key, task, service) might still be there.
- **Look up the hash** in the FILES section before you call a file malicious.
- **Ask the user** about anything that could be their own: Defender exclusions, remote access tools, unsigned tools in their project folders.
- **Persistence first**: remove the Run key, task or service together with the files, or the malware comes back.
- **A clean Spor log is not a clean PC.** Spor covers the last N days and the most common traces. Old infections, rootkits and the autostart locations listed in section 8 need other tools.

---

## 11. Quick checklist

1. Header: administrator? time window long enough? errors?
2. SUMMARY: do you understand every line?
3. TIMELINE: did you find the first suspicious event? What came before (download, archive, Run dialog) and after (files, persistence, network)?
4. PERSISTENCE: anything in AppData, ProgramData or Temp, random names, hidden tasks, scripts in arguments?
5. DEFENDER: detections not removed? exclusions the user did not set? protection off?
6. REMOTE ACCESS and NETWORK: unknown tools, connections, lots of data sent?
7. FILES: hashes looked up, signatures checked?
8. Unsure? Ask for a run with the whitelist off or a longer time window.
