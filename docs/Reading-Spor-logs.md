# Reading Spor logs: a guide for helpers

This guide is for people who help others with malware problems and use Spor for malware removal. 

Spor only reads. It changes nothing on the PC.

---

## 1. Check the header first

The first lines tell you whether the log is complete.

```
Created:   2026-11-18 07:49:43 UTC (local time 08:49, UTC+01:00)
Computer:  DESKTOP-4K2M7QX, Windows 11 Home 26H2, build 26300.9974, 64-bit
Run by:    anna (administrator)
Machine SID: S-1-5-21-1111111111-2222222222-3333333333
Users:     anna
Options:   last 30 days, whitelist on, SHA256 hashes of files up to 500 MB, profile default
Times:     UTC, except created and modified in FILES (local time of this PC, as FRST shows them)
Format:    one item per line: time [sources] item [status] => details <==== flags (parts left out when empty);
           ...
```

| Line | What to check |
|---|---|
| `Run by` | Must say `(administrator)`. Without admin rights most sources are missing. Ask for a new run as administrator. |
| `Times` | **The times in the log are UTC**: the time at the start of a line and the times in its details. The only exception are the `created` and `modified` times on the `file:` lines in FILES: they are the PC's local time, as FRST shows them, so you can compare them with an FRST log. Use the local time in `Created` to convert UTC |
| `Format` | A short reminder of how a line is built |
| `Options` | The time window, 30 days by default. If the infection is older, ask for a run with a longer time window. `whitelist on` means that known good files are hidden, see section 7. |
| `Error:` lines | Something went wrong before the scan. Sections can also end with `--- Errors ---`. An error means that part may be incomplete. |

The last line, `End of log. Scan took … (prefetch 9.4 s, …)`, lists every module that ran. If a module is missing, it was switched off.

---

## 2. Line buildup

Spor logs look as follows:

```
time [sources] item [status] => details <==== flags
```

Every part except the item is left out when it is empty.

Example:

```
2026-11-14 14:07:32 [PF DL] C:\Users\anna\Desktop\kprm_3.3.1.exe [gone] => Brave <==== !double-extension
    from: download.toolslib.net/…
    page: toolslib.net/…
```

- **time**: in UTC. Usually that's when something happened, but it depends on the source: `[SC]` lines have the file's modification time, `[AM]` lines tell when Windows wrote the Amcache entry, Run keys and services when the key was last changed, tasks and Startup items when the file was created (see section 4 and SUMMARY in section 8)
- **[sources]**: which Windows artifacts saw this entry, see section 4. Several tags means several sources say the same.
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
| `    key: value` | Indented, belongs to the line above (`loaded:`, `path:`, `action:`, `dll:`, `program:`, `file:`, `from:`, …). Long details and lists are on these lines, so the line above stays short. |

Persistence lines (Run keys, tasks) start with the kind of entry; the program that runs and its arguments are on the lines below:

```
2026-11-18 04:50:37 [run] HKU\anna\Software\Microsoft\Windows\CurrentVersion\Run\Discord
└─ key changed ───┘ └kind┘ └─ the Run entry ────────────────────────────────────────┘
    program: C:\Users\anna\AppData\Local\Discord\Update.exe [unsigned]
    arguments: --processStart Discord.exe
```

Other details on their own lines: a Defender detection's files (`file:`, `process:`), a download's addresses (`from:`, `page:`, `referrer:`), a program's install folder and Uninstall key (`folder:`, `key:`), the names of a folder's new files (`files:`).

---

## 3. Reading order

My recommendation: read the summary in full, then read the part of the timeline when the malware was seen to check what happened before and after that.

If you aren't sure whether a file is malicious, PUP or clean, check the files section for detailed information on it, such as hashes which you can lookup on Virustotal.

Wether you read the other sections depends on the type of threat, e.g., for a RAT I would check the remote tools section and the network. If something arrived via Clickfix, check the Clickfix section. Loaded files are mainly interesting for sideloading attacks, such as Hijackloader infection chains. The downloads section is useful to determine URLs of malicious software downloads, and maybe analyze them yourself.

1. **SUMMARY**: note everything Spor flagged.
2. **TIMELINE**: reconstruct what happened. Find the first suspicious event, then read what happened before and after.
3. **The sections**: Contains more details about the entries in the timeline (loaded files, persistence entries, accounts, network use). Look at these to enrich your findings from the summary and timeline.
4. **FILES**: hash, signature and version of every file the log names (with the whitelist on, not of the validly signed files it hides): the hash and signature on the line, `file:` (md5, size, created and modified in the PC's **local** time) and `version:` (version resource, certificate thumbprint) below it. Use it to look up files, e.g. on VirusTotal.
5. **LEGEND**: what every source tag, status word and flag means.

---

## 4. Sources

Not every source means that a file ran. A file that Windows only *recorded* is no proof of an infection.

| Tag | Source | Proves |
|---|---|---|
| `PF` | Prefetch | **ran**, with up to the last 8 run times |
| `PCA` | Program Compatibility Assistant | **ran**, sometimes with an exit code like `Abnormal process exit` or `Installer failed` |
| `UA` | UserAssist | **started by the user** from Explorer or the Start menu (`UA 5x` means 5 times) |
| `BAM` | Background Activity Moderator | **ran**, last time per user |
| `SRU` | SRUM | **was active** (first activity in the time window) and how much data it sent; `sent 0 bytes` means it ran without using the network |
| `MPL` | Defender log | Defender **looked the file up in the cloud**, usually because it ran or was written |
| `AM` | Amcache | Windows **recorded** the file. It was there, but did not necessarily run. The time is when Windows wrote the entry. |
| `SC` | ShimCache | the file **existed**. The time is the file's modification time, not when it ran or arrived: a copied file keeps its old time. No proof of execution on Windows 10 and 11. |
| `NEW` | file system | file **created**, with the download URL from Zone.Identifier if there is one |
| `STP` | change journal, NTFS times | **timestamps were set**, maybe faked |
| `DL` | browser history | **downloaded**, with the URL and the page it came from |
| `OPN` | Recent folder, WebCache | **opened** in Explorer |
| `ISO` | VHDMP log | disk image (ISO, IMG, VHD) **mounted** |
| `ARC` | WinRAR and 7-Zip history | archive opened or extracted |
| `DRP` | DROP FOLDERS sweep | a **loader project folder exists**, found by its files alone (no other evidence needed); the time is when the folder was created |
| `INS` | Uninstall keys, Windows Installer log | software **installed, updated or removed** |
| `AUT` `SVC` `TSK` `STA` `DRV` | Run keys, services, tasks, Startup folder, drivers | **persistence** created or changed |
| `DEF` `LOG` `USR` | Defender, event logs, accounts | detections, setting changes, cleared logs, account changes |
| `CAM` `MIC` | capability store | webcam or microphone used, and until when |
| `RUN` `ADR` `PSH` | Run dialog, address bar, PowerShell history | commands that were typed or pasted (ClickFix) |
| `RMM` | remote access tools | activity of AnyDesk, TeamViewer, ScreenConnect, … |
| `PROC` | process list | **running now**; the time is when it started |
| `4688` `SYSMON` | Security log, Sysmon | **process created**, with the parent and the command line. Only on PCs with process creation auditing or Sysmon. |

Several execution sources on one line, e.g. `[PF PCA UA BAM]`, are strong evidence. A file that only `[AM]` or `[SC]` saw may never have run.

If several sources see a file within 2 minutes, it is **one** line. A file that was seen many times shows the first and the last time, with `+N more times since …`. Processes of one program with different PIDs stay separate lines when one of them is flagged (Prefetch, BAM and file events go to the nearest of them, a SRUM hour to its run). A flagged line (a flag on an event, `!known-malware` included, or in the file name) has the time of its first flagged event, others the latest. A loader that runs again and again shows its first and its last run as flagged lines, the runs between as `+N more times`.
If the same file was in folders that only differ in numbers (version folders, dated temp folders), the line says `+N more times in between (all paths below)` and every path follows as an indented `path:` line with its own times. 

`[SC]` lines tell you when a file was modified (ShimCache keeps the file's modification time), `[AM]` lines tell when Windows wrote the entry. Neither proves that the program ran.
When a copied file was seen by another source too, there is no `[SC]` line at the old time: the other source's line has a `shimcache: file modified <time> (before it was created: a copy keeps the original's time)` line instead.

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
| `!invisible-char` | an invisible character in the name, shown as `<U+00A0>` etc. Outside USB DRIVES only characters never used in names (zero-width space, Hangul filler, Braille blank, ...); on USB drives any, also a no-break space | High for programs and for folders on USB drives: USB worms hide the user's files and their copy in a folder named like that. A no-break space or ideographic space outside USB drives is shown as `<U+00A0>` / `<U+3000>` but not flagged: Persian, Japanese and web-page-titled names use them. |
| `!in-folder-named-like-file` | `x.exe\evil.dll`, `app.exe.local\x.dll` | High, DLL hijacking |
| `!renamed-lolbin` | a Windows tool under another name (original name from Amcache) | High |
| `!lolbin-copy` | a copy of MSBuild, InstallUtil, RegAsm, RegSvcs, AddInProcess, aspnet_compiler, wscript, cscript or mshta outside its usual folders (found by its original name, so also renamed) | High, especially with a signature that does not hold (`file changed after signing`), the Hidden attribute or in a Windows cache folder: PavinLoader runs its `.wsf` with a copied MSBuild.exe. A validly signed copy in AppData can be a portable build tool; ask. |
| `!msi-script-action` | a cached Windows Installer package installs into `AppData\Local\<Vendor>\<Product>` and runs wscript, cscript, cmd, PowerShell or mshta (or a script of its own) as a custom action | High. RenLoader's fake vendor apps (`Realtek\Card Reader Helper`, `NVIDIA\PhysX Runtime`) start PavinLoader so. The line has the product code: remove the product, and the install folder. |
| `!suspicious` | a command that downloads or runs code (Run dialog, address bar, PowerShell history; since 0.8.1 also a Run value, service, task or running process whose Windows tool or interpreter gets such arguments, a WMI subscription, a program right in a Startup folder) | High, typical for **ClickFix** (fake CAPTCHA: "press Win+R, Ctrl+V, Enter") and for loaders that persist as `powershell ... irm ... \| iex` |
| `!kept-despite-warning` | the browser warned and the user kept the download | Medium to high |
| `!timestomped` | file timestamps were probably faked | Medium to high for programs and scripts. Read the signals. |
| `!defender-off` | real-time protection or another protection was turned off (also an attempt Tamper Protection blocked) | High, unless the user did it |
| `!defender-exclusion` | Defender exclusion added or changed | **Ask the user.** Malware adds exclusions for its folder, but many power users add their own, e.g. for Downloads or project folders. |
| `!not-removed` | Defender could not remove a detection | High |
| `!log-cleared` | an event log was cleared | High, anti-forensics |
| `!hidden-account` | account hidden from the sign-in screen | High, backdoor account |
| `!com-hijack` | a per-user COM registration overrides the machine one (COM handler of a scheduled task) | High |
| `!unsigned`, `!outside-driver-folders` | driver (or auto-start service program) without a valid signature, or a driver loaded from an unusual folder | High for drivers (rootkits). A well-known publisher's validly signed driver outside the driver folders (anti-cheat, VPN) has no SUMMARY line since 0.8.1. |
| `!from-web` | a Store or MSIX app was installed from a web page (App Installer link) | High, this is a known way to deliver malware. Check the source URL and the signer. |
| `!log-syntax-in-name` | the path contains ` => ` or text like `[gone]` | High, the name was made to mislead someone who reads the log |
| `!motw-removed` | a new program, script or shortcut has a Zone.Identifier with zone 0-2 and no URL | High. Browsers write zone 3 with a URL; a dropper wrote the low zone to turn off SmartScreen and the download warning. |
| `!sideload` | an unsigned DLL next to a signed program that imports it | High. The DLL line names the program; `proxy DLL, forwards to …` or `exports forwarded: N of M` means the DLL passes the real functions on to the original so the program keeps working. Remove the DLL, the program and the folder; the signed program is only the host. |
| `!proxy-exec` | a running program outside Windows and Program Files was started through `forfiles /c`, `cmd /c call`, `pcalua -a`, `conhost --headless`, … | High, used to hide the real parent |
| `!padded` | a new file is hundreds of MB of one repeated byte | High for programs and for data next to a new program: made too big for scanners and sandboxes. |
| `!runtime-loader` | a new program that ships a script runtime (Python/Ren'Py, AutoIt, Node.js, Electron unless signed by a well-known publisher, Java, Lua), with loader signs in its folder | High. The code is in the data files listed as `script:` lines, not in the program. |
| `!known-malware` | the item matches a pattern of a known malware family (Autodetect); the line names the family | High. The patterns are curated from confirmed cases; still read the line: a row can be wrong. `known malware <family>: loaded X` means the program loaded the family's files (Prefetch): a dropper, or the program the malware runs in. |
| `!injection-host` | calc, charmap or dllhost loaded unsigned code from a user folder, or runs with arguments it never takes | High: these Windows accessories load nothing from AppData. The program itself is Windows' own; the malware is what it loaded (the `loaded:` lines in PREFETCH). Kill the process, remove the loaded files. |
| `!renamed-program` | **hint**: a signed program under a random-looking or lure name that is not its original name | **Not on its own.** It goes to SUMMARY only with a strong flag on the same file or in the same folder, e.g. as the host of a `!sideload` DLL. |
| `!abused-tld` | **hint**: downloaded from a host under a cheap TLD (`.lol`, `.top`, `.xyz`, ...) | **Not on its own.** Next to a strong flag it says where the file came from. |
| `!root-program` | **hint**: a program, script or shortcut in the root of a drive | **Not on its own** (installers are often left in `C:\`). On a USB drive next to a hidden folder or a worm shortcut it is likely the worm's copy. |
| `!renamed-persisted` | a Run value, service or task starts a validly signed program under another name, from a random-looking folder | High: a loader's signed decoy (Adobe's `Setup.exe` as `S_Pipe.exe` in `kgw7Hp\kOsW3u0gxT\clip\`) that side-loads or starts the real payload. Look at the files next to it. |
| `!interpreter-outside` | Python, Node.js, AutoIt, Java, ... in a Windows folder or a drop location, started by persistence or running | High: a script interpreter has no business in `C:\Windows\System32\<name>\` or `C:\ProgramData\<name>\`; the script it runs is the malware. A portable Python in Downloads that the user runs by hand: ask. |
| `!defender-detected` | Defender detected this file or process | Every line of the file has it, so its ShimCache, Prefetch and network lines link to the detection. A PUA detection of a tool the user wants: ask. |
| `!in-defender-exclusion` | an unsigned file in a folder Defender excludes, or an excluded program | High when the exclusion is new or broad (`C:\`, `C:\Windows\System32`, `C:\Users\x`): malware excludes its own folder first. |
| `!vulnerable-driver` | a signed kernel driver known to be vulnerable (Intel NAL `iqvw64e.sys`, `RTCore64.sys`, ...) | High from Temp or an odd folder, or with a game cheat or Defender turned off: kernel access for a loader (kdmapper) or a Defender killer. From MSI Afterburner or a fan tool the user runs: ask. |
| `!random-name` | a driver with a random-looking file name | High: rootkits and cheat loaders install drivers under random names, often removed right after loading (`[gone]`). |
| context flags (`!remote-access`, `!account-change`, `!history-deleted`, `!disk-image`, `!upload`, `!new-service`, `!task-deleted`, `!startup-item`) | not malware by themselves; SUMMARY lists them so the case is complete | Read them with the evidence around them: a remote access tool right before a fake support call, an admin account created by a loader, Defender's history wiped after a detection, an ISO opened just before the infection, a large upload by an unsigned program. |
| `!invalid-signature` | a file changed after signing or with a revoked signature | Often a cracked game DLL (`steam_api64.dll`); in Windows or a security product's folder: infected. |
| `!usb-worm-lnk` | a shortcut on a USB drive that starts cmd/wscript/rundll32/..., points into a hidden folder, or is named like the drive or a hidden folder | High. The `worm signs:` line under it says why. |
| `!disguised-icon` | a shortcut to a program or script shows a folder, document or drive icon | High |
| `!autorun` | autorun.inf that starts something, or a MountPoints2 shell command | High |
| `!hidden-system` | a hidden and system item on a USB drive or USB disk | High for folders and programs. Explorer does not show these even with "show hidden files". |
| `!clsid-folder` | a folder that Explorer shows as something else (`x.{GUID}`, or a desktop.ini with a CLSID) | High on USB drives |
| `!ads` | an unusual alternate data stream on a file of a USB drive or a drive root | Medium. Read the stream name and size in the line. |
| `!explorer-hiding` | Explorer was changed so hidden files cannot be shown | High |

---

## 7. The whitelist

With `whitelist on`, Spor hides what is almost always harmless, so that the log stays readable. 

Hidden files are counted, e.g. in `(Hidden: …)` lines in the timeline and in `--- Hidden: known-noise locations ---` at the end of a section.

Ask for a run with the whitelist off (uncheck *Whitelist*, or `-nowhitelist`) if:

* the user has symptoms but the log shows nothing
* you suspect that a signed tool is abused
* a hidden count looks odd, e.g. a surprising number of files in a folder

---

## 8. Sections in detail

### SUMMARY
Flagged timeline lines (`[timeline …]`) and findings from the sections (`[Persistence]`, `[Defender]`, …), oldest first. Every line is built like any other line, e.g. `[Prefetch] C:\…\x.pdf.lnk => loaded by C:\…\host.exe <==== !double-extension` (up to Spor 0.7.1 the section findings had their flags in the text: `x.pdf.lnk  !double-extension  (loaded by …)`). `!known-malware` names a known malware family: on a timeline line (`known malware <family>: ...` in the details) or as an `[Autodetect]` line for hits that are not files on the timeline. Every line is a starting point, not a verdict.
The time is when something happened, except for these: ShimCache lines show the file's modification time, Amcache lines when Windows wrote the entry, Run keys and services when the key was last changed, tasks and Startup items when the file was created, and log or config files when they were last written. Such a time can be much older or newer than the infection: a dropped copy of MSBuild.exe keeps the modification time of the original.

### TIMELINE
A program that ships a script runtime has `script runtime <kind>` in its details and the script files below it as `script:` lines (hidden files first). Malware keeps its code there.

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
Programs, scripts and archives created in the time window in Downloads, Desktop, Documents, Temp, AppData, ProgramData and Public, with the download URL if Windows saved one. A folder with many new files is one line, its names on `files:` lines below (installers). Downloaded files always get their own line.

`zone 0` (or 1, 2) without a URL on a new program is `!motw-removed`. In folders in Temp, Downloads and the top of AppData, signed programs are checked for **DLL side-loading**: the unsigned DLL gets `!sideload`, the program `side-loads <dll>`. New files over 50 MB are checked for padding (`padded: N MB of byte 0x00`).

This section also lists programs and scripts that look old but whose NTFS change time is recent. A single file like that is flagged (`STP … set: B …, M … <==== !timestomped`). A batch of 3 or more such programs in one folder tree within a minute is one line without a flag, because installers and updaters copy files with their original times. Validly signed programs count for the batch but are not listed, so an install of signed programs with one unsigned `.jar` is a batch, not a flagged `.jar`.

### TIMESTOMPING
Files whose timestamps were set, from the NTFS change journal. The journal is a ring buffer, on a busy PC it may only cover a few hours. The log says how far back it goes (`back to <time>`). Files are listed most suspicious first, with their signals; `B` and `M` are the creation and modification time with all 7 fraction digits (`.0000000` = a whole second). Round times on programs and scripts in user folders are the interesting ones. A creation time newer than the modification time is not a signal: copying, downloading, extracting and moving to another drive keep the modification time and set a new creation time.

### DOWNLOADS AND OPENED FILES
Browser downloads with the URL and the page, files opened in Explorer, mounted disk images and archives opened with WinRAR or 7-Zip. Malware often comes as ISO or IMG to avoid the "downloaded from the internet" warning.
Take a look at downloads from file hosters (gofile, mega, mediafire, discord cdn), from "free software" sites, and at password-protected archives.

### SOFTWARE
Programs installed, updated or removed in the time window, from the Uninstall entries and the Windows Installer log. The Installer log also has software that is gone now.
Look for software the user does not remember installing, remote access tools, "PDF/driver/system optimizer" tools, browser add-on bundles, and per-user installs into AppData, which need no admin rights.

Store and MSIX apps are listed with the operation (Add, Register, Remove or FAILED), where the package came from, whether it runs with full trust and its signature now. **An app installed from a web page is flagged `!from-web`.** Fake "App Installer" pages are a known way to deliver malware as an MSIX package.

A removal right before you got the log can mean that the user or the malware already uninstalled something.

**Cached Windows Installer packages** lists only packages flagged `!msi-script-action`, with their custom actions (`custom action:`) and install folder (`folder:`). Removal tools delete the cached package, so ask for the first log of a case when this matters.

### RUNNING PROCESSES
Programs running now from outside Windows and Program Files, unsigned ones, LOLBins and interpreters with suspicious arguments, and processes with an unsigned module from outside Windows and Program Files (`module:` lines). `parent a.exe (pid) < b.exe (pid)` is the parent chain, nearest first; `pid N (exited)` means that parent is gone; `(exited, was X.exe)` names it from a process creation event (4688/Sysmon). A program started through a proxy-execution launcher is `!proxy-exec`; side-loaded DLLs are `module:` lines with `!sideload`.

### PERSISTENCE
Run keys (all entries), services and tasks outside trusted locations, recently installed services (event 7045), Task Scheduler events (also **deleted** tasks), Startup folders and WMI subscriptions.
Look for programs in AppData, ProgramData or Temp, random names, hidden tasks (`info: hidden`), and arguments that run scripts or encoded PowerShell. Services hosted by svchost.exe have an indented `dll:` line with the DLL that actually runs. A `module:` line is an unsigned DLL the program side-loads (`!sideload`).

**Reset and setup hooks** (Spor 0.9.0): what Windows runs by itself after "Reset this PC" (`C:\Recovery\OEM\ResetConfig.xml` and its scripts), at the end of Setup (`SetupComplete.cmd`) and from answer files (`unattend.xml`, `autounattend.xml`, also in the root of a USB stick). `!reset-hook` means it runs code or restores a task or registry values, or was written recently: malware uses it to survive a reset or a clean reinstall (WEEVILPROXY copies its task, a `.reg` export and a `.cmd` there, and drops a hidden `autounattend.xml` next to `\sources\boot.wim` on every drive). **A reset does not remove such malware: remove the hook files first.** `!reset-config` is context: a hook written recently that does nothing suspicious (a reset or reinstall writes them too); read the `command:` lines. A PC maker's older scripts, answer files and task copies (`AfterImageApply_*.cmd`, Lenovo's `scripts\FACTORY_POST`, the factory copy of `C:` in `C:\Recovery\OEM\C`) are listed without a flag, its other old files only as a count.

**Not covered yet:** Winlogon `Shell` and `Userinit`, Image File Execution Options, AppInit_DLLs, Active Setup, LSA packages and print monitors. Check those with other tools. Browser extensions: only Chromium extensions not from a store (DOWNLOADS).

### DEFENDER
Detections (`1116`), actions (`1117`), failures (`!not-removed`), protection turned off, exclusions (current list and changes), cloud lookups from MPLog and cleared event logs.
`Defender detection history deleted N times`: Defender also does this by itself after 15 days. Many deletions right after a detection are suspicious.

### CLICKFIX
Run dialog history, Explorer address bar commands and PowerShell history (all suspicious lines and the last 15). PowerShell never saves lines with words like `password` or `token`, so an empty history does not prove that nothing was pasted. A command typed several times is listed once, with `also: lines ...` below it. Lines that only check for a family's files (`Test-Path ...`, often a helper's own check) are no known-malware finding; a comment after the list names them.

### REMOTE ACCESS
Webcam and microphone use per program, and traces of AnyDesk, TeamViewer, ScreenConnect, RustDesk, NetSupport, Atera, MeshAgent and others: connection logs, server and account settings, file transfers.
**Ask the user whether they know the tool and the connections.** Scammers use legitimate remote access tools.

### NETWORK
- SRUM: data sent and received per program in the time window. A lot of `sent` data for an unknown program can mean stolen data. `sent 0 bytes; received 0 bytes` means the program ran without using the network.
- Connections now: programs outside trusted locations, LOLBins and unsigned programs.
- DNS cache: recent lookups of remote access, tunnel, paste and file sharing, bot API (Telegram, Discord webhooks) and IP lookup services. Many of them are normal, so combine them with the timeline.
- `victim ID in name`: a host name whose first part is a MAC address, a GUID or a long hash (`0800272a1b3c.example.click`). Beacons do this so every victim resolves its own name. Also in SUMMARY.
- `abused TLD`: names under .click, .top, .xyz and other cheap TLDs. Common for campaigns, but also for normal sites: only a hint.
- Proxy settings (Spor 0.9.0): `!local-proxy` means web traffic goes through a program on this PC (`127.0.0.1:57352`), the line names it. Together with `!root-cert` / `!custom-root` (DEFENDER) and `!settings-hidden` for `network-proxy`, that is a man-in-the-middle stealer (WEEVILPROXY). Removing the malware is not enough: turn the proxy off, delete the root certificate, and change the passwords and keys typed while it ran.

### ACCOUNTS
Local accounts, last sign-in, members of Administrators and account changes. Look for new accounts, unknown administrators and hidden accounts.

### USB DRIVES
Only with the **USB worm** or **All** profile. A typical USB worm infection looks like this on the stick:

- a hidden, often hidden+system, folder whose name you cannot see (`E:\<U+00A0>\`), holding the user's files and the worm's copy
- a shortcut in the root named like the stick or the folder, with a folder icon (`!disguised-icon`), that starts the worm (`cmd /c start ...`, `wscript`, `rundll32`) and then opens the hidden folder so the user sees their files (`!usb-worm-lnk`)
- sometimes `autorun.inf` (`!autorun`), a fake `RECYCLER` folder (`!hidden-system`), or a folder that Explorer shows as something else (`!clsid-folder`)

Read the **Shortcuts** sub-section for the command line, and FILES for the hashes of the worm's copy and of everything else on the stick. On the PC, look for the worm's copy in PERSISTENCE and RUNNING PROCESSES, and for runs from USB volumes in the timeline (`on USB drive <label>`). "MountPoints2" and "USB storage devices" tell you which sticks were plugged in and when, so you know which other sticks to clean.

### DROP FOLDERS
PavinLoader project folders that Spor found by sweeping Windows cache and system folders (WebCache, INetCache, Explorer, Caches, Notifications, Protect, Crypto, Themes, Libraries, the SYSTEM account's too) and `AppData\Local\<Vendor>\<Product>`, **without any other evidence**. A copy that never ran has no task, no ShimCache and no SRUM entry and would be missed otherwise. Typical folder: a copied `MSBuild.exe` (`!lolbin-copy`, invalid signature), a `.wsf`, a 20-30 MB `Resources.resx` and dummy files (`.sln`, `.csproj`, `.props`, `README.md`, `LICENSE`, `settings_853.cfg`, ...), sometimes hidden.

Folders created within seconds of each other are **one group**: every member has a `group:` line naming the first folder. Remove **every** folder of the group, together with the tasks that start the `.wsf` and the MSI app that dropped them (SOFTWARE, `!msi-script-action`). Folders listed with `created N s after ...` and no flag were only created at the same time: look before you remove them.

### FILES and AMCACHE FILES
Three lines per file: the hash, signature status and signer; `file:` with md5, size, the created and modified times in the PC's **local** time (like FRST, so you can compare the two logs) and the SHA1 that Amcache recorded; `version:` with the version information and the certificate thumbprint. If the Amcache SHA1 differs from the file now, the file was replaced after Windows recorded it.
With the whitelist on, FILES leaves out validly signed files that no line above shows and counts them in a `(Hidden: …)` comment; `-nowhitelist` lists them all.
AMCACHE FILES lists the SHA1 of files that are not on disk anymore. Use them to look up deleted malware.

---

## 9. Normal on a clean PC

Expect these and don't report them as malware without more evidence:

- LOLBins in the timeline (powershell, cmd, msiexec, rundll32, schtasks, wsl, curl, …)
- Unsigned programs from Git (`Program Files\Git\usr\bin`), PostgreSQL, 7-Zip, HandBrake, MakeMKV, games (Steam, itch.io), Python `Scripts\*.exe` launchers and developer tools
- Old versions of updated programs shown as `gone`, e.g. Discord `app-1.0.xxxx`, VS Code extensions, Edge WebView
- Installers in Downloads and on the Desktop
- `Spor.exe` itself with `PCA: Installer failed`: Windows' compatibility assistant treats programs that ask for admin rights like installers
- `Defender detection history deleted` now and then
- `!reset-config` for the hooks a recent "Reset this PC" or reinstall wrote (`C:\Windows\Panther\unattend.xml`)
- `!custom-root` for an antivirus web shield (Avast, AVG, Kaspersky, ESET), Fiddler or a developer's local certificate (mkcert)
- `!dev-mode` for developers; an unpacked extension they made themselves
- Disk images mounted by virtual machines (WSL, Docker, Hyper-V)
- Defender detections of files that the user analyses on purpose, e.g. if they are malware researchers or use security tools
- Games and tools that ship a script runtime (Ren'Py and Python games, Electron apps, Java tools) with `script runtime` in the timeline, without `!runtime-loader`. Electron apps validly signed by a well-known publisher (resources/publishers.txt) are never checked; other Electron apps are, like the other runtimes, because a lot of malware is Electron-based.
- RUNNING PROCESSES lines for developer tools and per-user programs of smaller publishers

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
