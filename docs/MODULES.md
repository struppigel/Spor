# What Spor scans

Every module writes its own section in the log. Everything with a time also goes into the timeline.
You can pick modules on the command line with `-modules`, e.g. `-modules prefetch,files,persistence`.

## Profiles

A profile is a set of modules. In the window, choose it in the "Profile" list (ticking boxes by hand makes it "Custom"); on the command line, use `-profile NAME`. `-modules` replaces the profile.

| Profile   | Modules                                                                 | For |
|-----------|-------------------------------------------------------------------------|-----|
| `default` | all modules except `usb`                                                | malware traces on the PC |
| `usb`     | `prefetch`, `exec`, `files`, `persistence`, `processes`, `usb`          | USB worms: the drives, the worm's copy on the PC, its autostart and process, programs run from USB volumes |
| `all`     | all modules                                                             | both |

## Overview

| Module        | Section in the log           | Sources                                                                 |
|---------------|------------------------------|-------------------------------------------------------------------------|
| `prefetch`    | PREFETCH                     | Prefetch files                                                          |
| `amcache`     | AMCACHE                      | `Amcache.hve`                                                           |
| `exec`        | EXECUTION EVIDENCE           | PCA, UserAssist, BAM, ShimCache, Compatibility Assistant, 4688, Sysmon  |
| `files`       | NEW FILES                    | file system, `Zone.Identifier`                                          |
| `timestomp`   | TIMESTOMPING                 | NTFS change journal                                                     |
| `downloads`   | DOWNLOADS AND OPENED FILES   | browser history, Recent folder, WebCache, VHDMP log, WinRAR and 7-Zip   |
| `software`    | SOFTWARE                     | Uninstall keys, Windows Installer log, AppX deployment log              |
| `persistence` | PERSISTENCE                  | Run keys, services, scheduled tasks, Startup folders, WMI               |
| `processes`   | RUNNING PROCESSES            | process list (WMI `Win32_Process`), loaded modules                      |
| `defender`    | DEFENDER                     | Defender event log, MPLog, Defender settings, cleared event logs        |
| `clickfix`    | CLICKFIX                     | Run dialog, Explorer address bar, PowerShell history                    |
| `remote`      | REMOTE ACCESS                | capability store, remote access tool logs and configs                   |
| `network`     | NETWORK                      | SRUM, connections, DNS cache                                            |
| `accounts`    | ACCOUNTS                     | local accounts, Security log                                            |
| `usb`         | USB DRIVES                   | drive contents, autorun.inf, shortcuts, Explorer settings, MountPoints2, USBSTOR, setupapi.dev.log, Partition/Diagnostic and Kernel-PnP events, Recent shortcuts |

## prefetch

Programs that ran, with the last 8 run times each. Also the files each program loaded, but only executables, scripts and archives outside Windows and Program Files.

## amcache

Files and drivers that Windows recorded in `Amcache.hve`, with their SHA1. Recorded does not mean executed.
When Windows recorded lots of files at once (an inventory scan), Spor collapses them to the top folders.
Unsigned drivers and drivers outside the driver folders are flagged.

## exec

PCA (Windows 11 22H2 and newer), UserAssist, BAM, ShimCache and the Compatibility Assistant store, for all users.
Process creation events, when the PC has them: Security event 4688 (process creation auditing) and Sysmon event 1. Launches by LOLBins or interpreters, or of programs outside Windows and Program Files, go to the timeline as `4688` / `SYSMON` with the parent and command line; proxy execution (`forfiles /c`, `cmd /c call`, ...) found through the creating processes gets `!proxy-exec`. A proxy-execution launcher whose arguments name a file or folder outside Windows and Program Files (`forfiles /p <folder in Temp>`, `pcalua -a <program>`, `conhost --headless <path>`, `cmd /c call <program>`) goes to the timeline too, flagged `!proxy-exec` when that runs as a process of its own (a program, or a script another program runs; not a batch file that cmd runs itself, and for `cmd /c call` only what call runs); so do the creators of every `!proxy-exec` event (up to 4 levels). Without either, the section says so: then program starts come only from Prefetch, BAM and Amcache. Spor does not turn auditing on.

## files

Executables, scripts, archives and disk images created in the time window. Spor searches Downloads, Desktop, Documents, AppData, Temp, ProgramData and Public.
Every file comes with its download URL and referrer if Windows saved them in `Zone.Identifier`.
A new program, script or shortcut in a drop location (Temp, Downloads, Desktop, the top of AppData and ProgramData, ...) whose `Zone.Identifier` says zone 0-2 without a URL gets the flag `!motw-removed`. Only a real URL counts as a download URL (not `about:internet`).
In a drop-location folder with new files, every validly signed program is checked for DLL side-loading: an unsigned DLL next to it that it imports (normal or delay-loaded imports, not API sets or KnownDLLs) gets `!sideload`, with proxy evidence when a signed copy of the original DLL sits in the folder under another name or most of its exports only forward or jump. Spor reads the PE headers as bytes; it never loads the files.
Every new file over 50 MB in a drop location (any type, up to three folders deep) is checked for padding: one repeated byte in 16 samples of 64 KB (`!padded`, see LOG-FORMAT.md). Padded files are not hashed.
A validly signed program under a random-looking or lure name that differs from its original name gets the hint `!renamed-program` (also in `persistence`).

## timestomp

Files whose timestamps were set in the time window, read from the NTFS change journal of every fixed NTFS drive.
Every file gets a score and Spor lists files with a score of 3 or more, together with the signals:

* +4 if the creation time is more than a day before the journal says the file was created. Not counted if NTFS tunneling explains it: when a program saves a file by writing a new one and renaming it over the old name within 15 seconds, NTFS keeps the old creation time. Browsers and Electron apps do that all the time.
* +3 if the creation time is in whole seconds, which is what SetFileTime tools write
* +1 if the creation time has only millisecond precision
* +1 if the modification time is in whole seconds (archives and installers do this too)
* +1 if both times are more than 7 days before the change, only together with another signal

The journal is a ring buffer. On a busy PC it may only go back a few hours. The log says how far back it goes.

## downloads

Browser download history of Chrome, Edge, Brave, Vivaldi, Opera, Yandex and Firefox, with the URL and the page the download came from.
Also files opened in Explorer (also from CD, ISO, USB and network drives), `file:///` entries in WebCache, mounted ISO, IMG and VHD files, and the WinRAR and 7-Zip history.

## software

Software installed, updated or removed in the time window:

* Uninstall keys of the machine and of every user: name, version, publisher, install date, folder, the program with its signature status, the registry key, and whether the entry is hidden
* Windows Installer events: installs, failed installs and removals with exact times, also for software that is gone now. With product name and MSI product code.
* Store and MSIX apps: added, registered, removed or failed, where the package came from, whether it runs with full trust, its signature now and its install folder

Apps installed from a web page (App Installer, `ms-appinstaller:` links) get the flag `!from-web`.

## persistence

Run keys, services, scheduled tasks, Startup folders and WMI subscriptions, each with the time it was created or changed.
Also service installs (System event 7045) and the Task Scheduler events, which still show deleted tasks.
Programs outside Windows and Program Files are checked for DLL side-loading like in `files`; the DLLs are listed as `module:` lines under the entry, flagged `!sideload`.

## processes

Programs running now that run from outside Windows and Program Files (or from a user-writable folder inside them), are not validly signed, are a LOLBin or interpreter with suspicious arguments, or have an unsigned module from outside Windows and Program Files loaded. Each with its parent chain (4 levels), its command line, and the unsigned modules as `module:` lines. The program is checked for DLL side-loading (`!sideload`) and renaming (`!renamed-program`). A program whose parent chain contains a proxy-execution launcher (`forfiles /c`, `pcalua -a`, `conhost --headless`, `cmd /c call`, ...) gets `!proxy-exec`. Programs installed per user and validly signed by a well-known publisher are counted, not listed (`-nowhitelist` lists them). Each listed process is also in the timeline (`PROC`) at its start time. Spor only reads the process list and the module lists; it does not open the processes' memory.

## defender

Defender detections, actions, setting changes like exclusions or real-time protection turned off, and tamper protection events.
Files that Defender looked up in the cloud (MPLog), the current exclusions, and cleared event logs.

## clickfix

The Run dialog history (RunMRU), the Explorer address bar (TypedPaths, also used by FileFix) and the PowerShell console history. Spor flags commands that download or run code and detects obfuscation.

## remote

Webcam and microphone use per program.
Traces of remote access tools: AnyDesk, TeamViewer, ScreenConnect, Splashtop, Radmin and Atera. NetSupport, MeshAgent and RustDesk configs are found by their content, so renamed copies are found too.

## network

* SRUM: data sent and received per program, usually 30 to 60 days back
* Connections and listening ports now, with the program and its signature
* DNS cache entries of remote access, tunnel, paste and file sharing, bot API and IP lookup services
* DNS cache entries with a victim ID in the name (`victim ID in name`: the first label of `<id>.<domain>.<tld>` is a MAC address, 32 hex digits, a GUID or a long base32/base64 ID; not under CDN and cloud domains; also in SUMMARY) and names under TLDs campaigns favour (`abused TLD`: .click, .top, .xyz, ...; listed only)

## accounts

Local accounts (admin or not, enabled, password set, last sign-in, hidden from the sign-in screen), the members of Administrators, and account changes from the Security log, e.g. an account was created or added to a group.

## usb

Not in the default profile; run it with the `usb` or `all` profile. For USB worms, which hide the user's files in a hidden folder (often named with a no-break space or another invisible character) and put a shortcut with a folder icon in their place.

* **Drives**: every drive with type, bus (USB hard disks report as fixed drives; the bus tells them apart), vendor and product, label, file system, volume serial and size
* **Contents**: removable and USB drives are listed in full (up to 2000 items and 8 folder levels per drive), other drives their root and the root folders that are hidden, system or oddly named (not Windows' own, such as `$Recycle.Bin` or `ProgramData`). Each item with its attributes in words, created and modified times and its alternate data streams. Invisible characters are shown as `<U+XXXX>`, also spaces at the start or end of a name and dots at its end. Every file goes to FILES (hash, signature, version). New flagged files go to the timeline (`NEW`), other flagged items to SUMMARY.
* **autorun.inf** on every drive root: each `[section] key=value` line, and the files that `open`, `shellexecute`, `shell\<verb>\command` and `icon` name (hashed). ANSI files keep their no-break spaces. A folder named autorun.inf is shown as an autorun "vaccine".
* **Shortcuts** (.lnk, .url) found in the listing: target with status, arguments, icon (path,index, with "folder icon" / "document icon" / "drive icon"), working folder, window state, description, the PC the shortcut was made on (tracker block), the target's volume, and where the target was read: link info, environment block, item list (shell items, as crafted worm shortcuts have it) or relative path. Files named in the arguments are hashed.
* **Explorer settings**: per user Hidden, HideFileExt, ShowSuperHidden; the Explorer policies NoDriveTypeAutoRun, NoAutorun, NoFolderOptions, HonorAutorunSetting; `SHOWALL\CheckedValue`
* **MountPoints2**: per user, the volumes Explorer saw (USB ones always, others in the time window) with the device from MountedDevices and any `Shell\<verb>\command`
* **USB storage devices**: USBSTOR with friendly name, serial, first installed (device properties or setupapi.dev.log), last connected and removed (device properties when readable, else the key time), labels from Windows Portable Devices and ReadyBoost (EMDMgmt), drive letter from MountedDevices
* **Connects** in the time window from Partition/Diagnostic event 1006 (vendor, model, serial, size; size 0 = removed), else Kernel-PnP 410. Timeline: `USB`.
* **Files opened from removable drives**: Recent and Office Recent shortcuts whose target was on a removable drive, with the volume serial and label

The volume serials and drive letters of USB drives (now mounted, from ReadyBoost, from Recent shortcuts) are used after all modules: timeline lines of files on them get `on USB drive <label> (serial <serial>)`, also Prefetch paths of volumes that are not mounted (`\VOLUME{...-SERIAL}`).

## Script-runtime launchers (all modules)

After the modules ran, Spor looks at every program on the timeline outside Windows and Program Files: does it ship a script runtime (Ren'Py/Python, AutoIt, Node.js, Electron, Java, Lua)? Malware ships a legitimate runtime and keeps its code in data files, so the launcher's signature says nothing. Such a launcher is never hidden by the signer whitelist (except Electron apps), its first timeline line says `script runtime <kind>` and lists the script containers and hidden files as `script:` lines. A new launcher folder with loader signs gets `!runtime-loader` (see LOG-FORMAT.md).

## Autodetect (all modules)

After the modules ran, Spor matches what they collected against `resources/autodetect.txt`, a curated database of **known malware families** (RenLoader, PavinLoader, CountLoader, Vidar, TamperedChef, ...) built from FenrisHub's malware rules and rewritten for what Spor sees. This is the only family-specific part of Spor: all other rules stay generic. A file on the timeline gets `!known-malware` on its timeline line, with `known malware <family>: <note>` first in the details; that line goes to SUMMARY. Every other hit goes to SUMMARY as `[Autodetect] <item> => <family>: <note> <==== !known-malware`.

What is matched (no extra file or registry reads): file paths (timeline, persistence targets, running programs and their unsigned modules, Startup items, install folders), task names, Run value names, service names, command lines (tasks, Run entries, services, running processes, Run dialog, PowerShell history), installed programs (`name | version | publisher`, all Uninstall entries, not only recent ones), signers and version-resource companies of the files Spor checked, and DNS cache names. Persistence entries hidden by the whitelist are matched too. One pass after all modules, before the timeline is built (signers of files that only the timeline checks: a second pass after it): an Aho-Corasick automaton over the literals finds the candidate rows, a regex runs only when its key is in the value (100 ms timeout). The time is in the end line (`autodetect N s`).

Rows: `kind <TAB> match <TAB> family <TAB> note <TAB> example <TAB> FenrisHub rule ids`. `match` is `=text` (the whole value), `*text` (part of it) or `/regex/ key=text`. Every row must match its example (tests). To try new rows without a new build, put `Spor.autodetect.txt` next to `Spor.exe`: it replaces the built-in database (the header's Options line says so).

## Flags by module

What each flag means: LOG-FORMAT.md. Flags from the file name are set wherever a file is shown.

| Flag | Set by |
|---|---|
| `!lolbin`, `!double-extension`, `!in-folder-named-like-file`, `!RLO`, `!invisible-char`, `!log-syntax-in-name` | every module, from the file name |
| `!usb-worm-lnk`, `!disguised-icon`, `!autorun`, `!hidden-system`, `!clsid-folder`, `!ads`, `!explorer-hiding` | `usb` |
| `!renamed-lolbin`, `!unsigned`, `!outside-driver-folders` | `amcache` |
| `!timestomped` | `files`, `timestomp` |
| `!motw-removed`, `!padded` | `files` |
| `!sideload` | `files`, `persistence`, `processes` |
| `!renamed-program` (hint) | `files`, `persistence`, `processes` |
| `!proxy-exec` | `processes`, `exec` (process creation events) |
| `!runtime-loader` | after all modules (script-runtime launchers) |
| `!known-malware` | after all modules (Autodetect) |
| `!kept-despite-warning` | `downloads` |
| `!from-web` | `software` |
| `!com-hijack` | `persistence` |
| `!defender-off`, `!defender-exclusion`, `!not-removed`, `!log-cleared` | `defender` |
| `!suspicious` | `clickfix` |
| `!hidden-account` | `accounts` |

## Signatures

Spor checks the signature of every program file it shows, also with `-nohash`:

1. WinVerifyTrust with a revocation check
2. The Windows catalogs. The catalog that contains the file's hash must have a valid signature itself.
3. For Store and MSIX apps the package signature. The certificate must be a code signing certificate that chains to a trusted root, the signature must cover the block map, and the file must match the block map.

The result is `valid`, `invalid` (with the reason, e.g. the file was changed after signing), `revoked`, `expired` or `unsigned`, plus the signer and the certificate thumbprint.
A file that Spor cannot read is `no access`, not `unsigned`.

The FILES section also lists the version information: file version, description, product, company and original file name.

## Locked files

SRUM, WebCache, Amcache and browser databases are often locked while Windows runs. Spor reads them through a shadow copy of the system drive. It creates the shadow copy only when needed and deletes it at the end. If that fails, it uses `esentutl /vss`.

SRUM and WebCache are ESE databases. Spor reads them with Windows' own `esent.dll` after replaying their logs into the copy with `esentutl /r`.
