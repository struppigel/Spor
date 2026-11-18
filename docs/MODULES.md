# What Spor scans

Every module writes its own section in the log. Everything with a time also goes into the timeline.
You can pick modules on the command line with `-modules`, e.g. `-modules prefetch,files,persistence`.

## Overview

| Module        | Section in the log           | Sources                                                                 |
|---------------|------------------------------|-------------------------------------------------------------------------|
| `prefetch`    | PREFETCH                     | Prefetch files                                                          |
| `amcache`     | AMCACHE                      | `Amcache.hve`                                                           |
| `exec`        | EXECUTION EVIDENCE           | PCA, UserAssist, BAM, ShimCache, Compatibility Assistant                |
| `files`       | NEW FILES                    | file system, `Zone.Identifier`                                          |
| `timestomp`   | TIMESTOMPING                 | NTFS change journal                                                     |
| `downloads`   | DOWNLOADS AND OPENED FILES   | browser history, Recent folder, WebCache, VHDMP log, WinRAR and 7-Zip   |
| `software`    | SOFTWARE                     | Uninstall keys, Windows Installer log, AppX deployment log              |
| `persistence` | PERSISTENCE                  | Run keys, services, scheduled tasks, Startup folders, WMI               |
| `defender`    | DEFENDER                     | Defender event log, MPLog, Defender settings, cleared event logs        |
| `clickfix`    | CLICKFIX                     | Run dialog, Explorer address bar, PowerShell history                    |
| `remote`      | REMOTE ACCESS                | capability store, remote access tool logs and configs                   |
| `network`     | NETWORK                      | SRUM, connections, DNS cache                                            |
| `accounts`    | ACCOUNTS                     | local accounts, Security log                                            |

## prefetch

Programs that ran, with the last 8 run times each. Also the files each program loaded, but only executables, scripts and archives outside Windows and Program Files.

## amcache

Files and drivers that Windows recorded in `Amcache.hve`, with their SHA1. Recorded does not mean executed.
When Windows recorded lots of files at once (an inventory scan), Spor collapses them to the top folders.
Unsigned drivers and drivers outside the driver folders are flagged.

## exec

PCA (Windows 11 22H2 and newer), UserAssist, BAM, ShimCache and the Compatibility Assistant store, for all users.

## files

Executables, scripts, archives and disk images created in the time window. Spor searches Downloads, Desktop, Documents, AppData, Temp, ProgramData and Public.
Every file comes with its download URL and referrer if Windows saved them in `Zone.Identifier`.

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

## accounts

Local accounts (admin or not, enabled, password set, last sign-in, hidden from the sign-in screen), the members of Administrators, and account changes from the Security log, e.g. an account was created or added to a group.

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
