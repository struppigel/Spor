# Spor log format

This describes how `Spor.txt` is built. It is meant for helpers who want to know where to find things, and for anyone who wants to parse the logs.

## Layout

1. **Header**: `key: value` lines with the creation time, the computer, who ran Spor, the users and the options
2. **SUMMARY**: only the flagged items
3. **TIMELINE**: everything with a time from all modules, newest first, with the sources in brackets
4. **One section per module** with everything that does not fit into a timeline, see [MODULES.md](MODULES.md)
5. **FILES**: one line per file with hash, signature, version information and the SHA1 that Amcache recorded
6. **AMCACHE FILES**: SHA1 from Amcache of files that are not listed in FILES
7. **LEGEND**: the timeline sources, status words and flags, one per line

The timeline sources are:

* runs: `PF` Prefetch, `PCA`, `UA` UserAssist, `BAM`, `MPL` Defender cloud lookup, `SRU` SRUM
* files: `AM` Amcache, `SC` ShimCache, `NEW` created, `STP` timestamps set, `DL` downloaded, `OPN` opened, `ISO` mounted, `ARC` archive tool
* software: `INS` installed, updated or removed
* persistence: `AUT` Run key, `SVC` service, `TSK` task, `STA` Startup folder, `DRV` driver
* security: `DEF` Defender, `LOG` log cleared, `USR` accounts
* remote access and ClickFix: `CAM` and `MIC` webcam and microphone, `RMM`, `RUN` Run dialog, `ADR` address bar, `PSH` PowerShell history

If several sources see the same file within 2 minutes, it is one line, e.g. `[PF PCA BAM]`. A file that was seen many times shows its first and last time, and every time it was flagged.
Paths that only differ in numbers in folder names (version folders, dated or GUID temp folders) count as the same file. Such a line is followed by one indented `path:` line per real path, so every path is still in the log.

Paths are written in their real case, although Prefetch stores them in upper case and Amcache in lower case. Nothing is shortened.

## Lines

There is one item per line and no column alignment, so word wrap in an editor does not break anything.
Every line is one of these:

| Line                               | Meaning |
|------------------------------------|---------|
| `==================== Title ====…` | Section. The title is followed by ` - description`. |
| `--- title ---`                    | Sub-section |
| empty line                         | Separates sections, and the explanations of a section from its items |
| `(text)`                           | Comment. `(line: …)` right before the items names their parts, e.g. `(line: time [sources] file or event [status] => details <==== flags)` |
| `(none…)`                          | The section has no items |
| item line                          | See below |
| `    key: value`                   | Indented line that belongs to the item above, e.g. `loaded:`, `path:`, `action:`, `dll:`. The value can be an item itself: `path [status] <==== flags` |
| `key: value`                       | Header line |

The section titles are `SUMMARY`, `TIMELINE`, `PREFETCH`, `AMCACHE`, `EXECUTION EVIDENCE`, `NEW FILES`, `TIMESTOMPING`, `DOWNLOADS AND OPENED FILES`, `SOFTWARE`, `PERSISTENCE`, `DEFENDER`, `CLICKFIX`, `REMOTE ACCESS`, `NETWORK`, `ACCOUNTS`, `FILES`, `AMCACHE FILES` and `LEGEND`.
The LEGEND has no item lines, skip it by its title.

## Item lines

An item line has these parts in this order. Every part is left out if it is empty.

```
time [tags] item => target [status], details <==== flags
```

1. time as `yyyy-MM-dd HH:mm:ss` in UTC
2. tags in brackets, e.g. `[PF PCA BAM]`, `[run]`, `[4720]`
3. the item: a path, command, account or event text
4. `=> target` if the line has one, e.g. the program of a persistence entry or the hash in FILES
5. ` [status]` after the target, or after the item if there is no target
6. details after ` => ` (or after `, ` if there is a target), separated by `; `. Labeled details are written as `name value`, e.g. `first seen 2026-11-01 10:00:00; sent 5 MB`
7. ` <==== !flag !flag` at the end

How to split a line:

* If the line starts with a digit, the first 19 characters are the time
* `<==== ` splits off the flags
* The first ` => ` splits the item from the rest
* ` [status]` is one of the status words below

Paths cannot contain `<`. They can contain ` => ` and text like `[gone]`, but then they get the flag `!log-syntax-in-name`. Such names are rare and are probably meant to mislead, so check the flags before you trust a split.

## Status words

No status means the file is there and validly signed, or it is not a program. Otherwise the status is one of these: `gone`, `no access`, `unsigned`, `invalid signature`, `revoked signature`, `expired signature`, `volume not mounted`, `> N MB, not hashed`.

In FILES, `not hashed` instead of a hash means hashing was off (`-nohash`) or the file type is not hashed.

## FILES

One line per file:

```
path => hash, signature valid; signer X; thumbprint Y; note Z; file version X; description Y; product Z; company W; original name V; amcache sha1 S; md5 M; size N; created T; modified T
```

* `md5` is left out with `-algo MD5` or if the file was not hashed
* `size` is in bytes
* `created` and `modified` are the file times in the **local time of the PC**. All other times in the log are UTC.

Files named in a Defender detection are hashed if they still exist, so they get a FILES line too. For `x.zip->inner.exe` this is the archive.

## Details

Some sections have details that identify an entry. Every detail is left out if its value is unknown.

| Where                                | Detail | Value |
|--------------------------------------|--------|-------|
| Header                               | `Machine SID: S-1-5-21-a-b-c` | Line after `Run by:`. The local account domain SID without RID. It is the same for every local account of a Windows install and changes after a reinstall, unlike the computer name. |
| ACCOUNTS, Local accounts             | `sid` | The full SID of the account (machine SID + RID) |
| PERSISTENCE, every item line         | `[kind]`, the first tag | `run`, `runonce`, `policy-run` (`Policies\Explorer\Run`), `service`, `driver`, `task` (also for Task Scheduler events), `startup`, `wmi`. Use the tag, not the sub-section title. |
| PERSISTENCE, Run keys                | `value` | The value name exactly as it is stored, with RLO shown as `<RLO>`. It can contain backslashes, so do not cut it from the entry. |
| PERSISTENCE, services                | `    dll: path [status] <==== flags` | For services hosted by svchost.exe: the ServiceDll and its status. The DLL is also in FILES. For 7045 lines it comes from the service key, if that still exists. On registry lines the target already is the DLL (`… (svchost DLL)`), the sub-line has the plain path. |
| SOFTWARE, Installed programs         | `key` | The Uninstall key: `HKLM\...\<subkey>`, `HKLM-x32\...\<subkey>` (WOW6432Node) or `HKU\<SID>\...\<subkey>` (per user). `<subkey>` is the key name as stored, e.g. an MSI product code `{GUID}` or a name like `TeamViewer`. The item is the raw DisplayName. |
| SOFTWARE, Installed programs         | `hidden` | `yes` if SystemComponent is 1 |
| SOFTWARE, grouped line (`N entries from <publisher>`) | `    key: <key>; name <name>; version <version>` | One indented line per entry after the `programs:` line, with the DisplayName and DisplayVersion of that entry |
| SOFTWARE, Windows Installer          | `name` | The product name alone. The item contains name and version. |
| SOFTWARE, Windows Installer          | `product code` | The MSI product code `{GUID}`. For an MSI install this is also the name of its Uninstall subkey. |
| SOFTWARE, Store and MSIX apps        | `folder` | The install folder of the package (`C:\Program Files\WindowsApps\<package full name>`). For a package that is gone, the folder it had. |

The `INS` lines in the timeline have the same details as the SOFTWARE line they come from (`key …`, `product code …` or `folder …`). A grouped install has one indented `key:` line per entry.

## Flags

| Flag | Meaning |
|---|---|
| `!lolbin` | regasm, msbuild, mshta, certutil, powershell, ... (also listed in System32) |
| `!renamed-lolbin` | a Windows tool under another name (original name from Amcache) |
| `!double-extension` | e.g. `invoice.pdf.exe`, also padded with spaces |
| `!in-folder-named-like-file` | e.g. `ab.exe\evil.dll`, `app.exe.local\x.dll` |
| `!RLO` | bidi override characters in the path, shown as `<RLO>` |
| `!unsigned`, `!outside-driver-folders` | drivers (Amcache) |
| `!suspicious` | ClickFix entries that download or run code |
| `!kept-despite-warning` | the browser warned about a download and the user kept it |
| `!defender-off`, `!defender-exclusion`, `!not-removed` | Defender protection turned off, exclusion added or changed, detection not removed |
| `!log-cleared` | an event log was cleared |
| `!hidden-account` | account hidden from the sign-in screen |
| `!timestomped` | file timestamps were probably faked (change journal, or an old whole-second creation time with a recent NTFS change time) |
| `!com-hijack` | a per-user COM registration overrides the machine one (COM handlers of scheduled tasks) |
| `!from-web` | a Store or MSIX app was installed from a web page (App Installer, `ms-appinstaller:` link). This is a known way to deliver malware. |
| `!log-syntax-in-name` | the path contains ` => ` or a status word in brackets, so it looks like log text |
