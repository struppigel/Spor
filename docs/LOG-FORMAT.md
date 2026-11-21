# Spor log format

This describes how `Spor.txt` is built. It is meant for helpers who want to know where to find things, and for anyone who wants to parse the logs.

## Layout

1. **Header**: `key: value` lines with the creation time, the computer, who ran Spor, the users and the options
2. **SUMMARY**: only the flagged items, oldest first. Items without a time (e.g. invalid signatures, Run dialog entries) come last. The comment under the title says which times are not when something happened (ShimCache: file modified; Amcache: entry written; Run keys and services: key changed; ...).
3. **TIMELINE**: everything with a time from all modules, oldest first, with the sources in brackets
4. **One section per module** with everything that does not fit into a timeline, see [MODULES.md](MODULES.md). Lists with times are oldest first too. Exceptions: the Run dialog and archive tool histories keep Windows' order (newest first, only the newest entry has a time), and some lists are sorted by size or score.
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
* USB drives: `USB` a USB storage device was first installed, connected or removed

Lines seen only by `SC` (ShimCache) or `AM` (Amcache) end their details with what their time is: `file modified` (ShimCache: the file's modification time; a copied file keeps its old time), `Amcache write` (when Windows wrote the entry), `file modified or Amcache write`. None of them proves that the program ran.

`STP` lines say which times were set, as MACB letters with all 7 fraction digits (a whole-second `.0000000` or millisecond-only time is the evidence): `set: B 2026-10-27 09:22:42.0000000, M 2026-10-27 09:22:42.0000000` (B = created, M = modified).

If several sources see the same file within 2 minutes, it is one line, e.g. `[PF PCA BAM]`. A file that was seen many times shows its first and last time, and every time it was flagged.
Processes of one program with different PIDs (`PROC`, `4688`, `SYSMON`) are separate lines when one of them is flagged; events without a PID (`PF`, `BAM`, file events) go to the line whose nearest event is closest in time, and an `SRU` hour bucket to the nearest line within an hour (the same run). A line's time is its latest event; on a flagged line (a strong flag on an event, `!known-malware` included, or in the file name), the time of the first flagged event, which for a flag in the file name is the line's first event.
Paths that only differ in numbers in folder names (version folders, dated or GUID temp folders) count as the same file. Such a line is followed by one indented `path:` line per real path, so every path is still in the log; its details say `+N more times (below)`, the `path:` lines have the times. A file seen in one folder only says `+N more times since <first time>`.

Paths are written in their real case, although Prefetch stores them in upper case and Amcache in lower case. Nothing is shortened.

Characters that cannot be seen are written so they can: bidi override characters as `<RLO>`, invisible or blank-looking characters (no-break space, zero-width characters, soft hyphen, Hangul fillers, the Braille blank, ...) as `<U+XXXX>` with their code point, e.g. `E:\<U+00A0>\x.exe` for a folder named with one no-break space. USB DRIVES also writes spaces at the start or end of a name and dots at its end this way (`<U+0020>`, `<U+002E>`). A parser that wants the real path replaces `<U+XXXX>` with the character.

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
| `    key: value`                   | Indented line that belongs to the item above, e.g. `loaded:`, `path:`, `action:`, `dll:`, `program:`, `file:`, `from:`. The value can be an item itself: `path [status] <==== flags`. Long details and lists are on such lines (see Sub-lines), not on the item line. |
| `key: value`                       | Header line |

The section titles are `SUMMARY`, `TIMELINE`, `PREFETCH`, `AMCACHE`, `EXECUTION EVIDENCE`, `NEW FILES`, `TIMESTOMPING`, `DOWNLOADS AND OPENED FILES`, `SOFTWARE`, `PERSISTENCE`, `DEFENDER`, `CLICKFIX`, `REMOTE ACCESS`, `NETWORK`, `ACCOUNTS`, `FILES`, `AMCACHE FILES` and `LEGEND`.
The LEGEND has no item lines, skip it by its title.

## Item lines

An item line has these parts in this order. Every part is left out if it is empty.

```
time [tags] item => target [status], details <==== flags
```

1. time as `yyyy-MM-dd HH:mm:ss` in UTC, always with `-`, `:` and the Gregorian calendar, whatever the PC's language
2. tags in brackets, e.g. `[PF PCA BAM]`, `[run]`, `[4720]`. A line can have several, each in its own brackets: `[task] [106]` (a Task Scheduler event), `[strup] [7-Zip]`, `[anna] [Brave]` (the user, on a PC with several users)
3. the item: a path, command, account or event text. Event texts can contain ` => ` themselves, e.g. `Defender action taken: NAME => action A` (also `Defender detected:` and `Defender action FAILED:`, the last with `!not-removed`; the detected files are on `file:` sub-lines) or `C:\folder\ => 14 new files` (the names on `files:` sub-lines)
4. `=> target` if the line has one, e.g. the program of a persistence entry or the hash in FILES
5. ` [status]` after the target, or after the item if there is no target
6. details after ` => ` (or after `, ` if there is a target), separated by `; `. Labeled details are written as `name value`, e.g. `first seen 2026-11-01 10:00:00; sent 5242880 bytes`
7. ` <==== !flag !flag` at the end

How to split a line:

* If the line starts with a digit, the first 19 characters are the time. Exception: the PowerShell history lines in CLICKFIX start with the line number in the history file (`222 [suspicious] command`)
* `<==== ` splits off the flags
* The first ` => ` splits the item from the rest
* ` [status]` is one of the status words below, or several of them joined with `, ` (`[> 500 MB, not hashed, unsigned]`)

Paths cannot contain `<`. They can contain ` => ` and text like `[gone]`, but then they get the flag `!log-syntax-in-name`. Such names are rare and are probably meant to mislead, so check the flags before you trust a split.

Sizes are exact numbers of bytes, never rounded (`sent 50855936 bytes`), so two logs can be compared.

## Status words

No status means the file is there and validly signed, or it is not a program. Otherwise the status is one of these: `gone`, `no access`, `unsigned`, `invalid signature`, `revoked signature`, `expired signature`, `volume not mounted`, `> N MB, not hashed`.

In FILES, `not hashed` instead of a hash means hashing was off (`-nohash`) or the file type is not hashed.

## FILES

Three lines per file: the hash line and two sub-lines (each left out when it has no value):

```
path => hash, signature valid; signer X; note Z
    file: md5 M; size N; created T; modified T; amcache sha1 S
    version: file version X; description Y; product Z; company W; original name V; thumbprint T
```

Up to Spor 0.6 all of this was on one line, in the order `signature; signer; thumbprint; note; file version; ...; amcache sha1; md5; size; created; modified`. A parser that appends the sub-lines' details to the line (`; `) reads both.

* `md5` is left out with `-algo MD5` or if the file was not hashed
* `size` is in bytes
* `created` and `modified` are the file times in the **local time of the PC**, as FRST shows them: UTC plus the PC's UTC offset when Spor ran (the one in the `Created:` header line), also for files from the other daylight saving period. So they equal FRST's times for the same file. All other times in the log are UTC.

Files named in a Defender detection are hashed if they still exist, so they get a FILES line too. For `x.zip->inner.exe` this is the archive.

## Details

Some sections have details that identify an entry. Every detail is left out if its value is unknown.

| Where                                | Detail | Value |
|--------------------------------------|--------|-------|
| Header                               | `Machine SID: S-1-5-21-a-b-c` | Line after `Run by:`. The local account domain SID without RID. It is the same for every local account of a Windows install and changes after a reinstall, unlike the computer name. |
| ACCOUNTS, Local accounts             | `sid` | The full SID of the account (machine SID + RID) |
| PERSISTENCE, every item line         | `[kind]`, the first tag | `run`, `runonce`, `policy-run` (`Policies\Explorer\Run`), `service`, `driver`, `task` (also for Task Scheduler events), `startup`, `wmi`. Use the tag, not the sub-section title. |
| PERSISTENCE, Run keys                | `    value: name` | The value name exactly as it is stored, with RLO shown as `<RLO>`, only when it contains a backslash (then it cannot be cut from the entry). Without a `value:` line the value name is the entry's last part after `\`. |
| PERSISTENCE, Run keys and tasks      | `    program: path [status]`, `    arguments: ...` | What the entry or the task's first action starts, with its status, and its arguments (left out when there are none). The item line has the entry (Run key and value, or task path) and the flags. |
| PERSISTENCE, services                | `    dll: path [status] <==== flags` | For services hosted by svchost.exe: the ServiceDll and its status. The DLL is also in FILES. For 7045 lines it comes from the service key, if that still exists. On registry lines the target already is the DLL (`… (svchost DLL)`), the sub-line has the plain path. |
| PERSISTENCE, every item line         | `    module: path [status] => details <==== !sideload` | An unsigned DLL the persisted program side-loads (see `!sideload`). The DLL also gets its own timeline line when it is new. |
| RUNNING PROCESSES, every item line   | `started [pid] program [status] => parent a.exe (pid) < b.exe (pid) < pid N (exited); arguments ...` | The parent chain, nearest first, up to 4 levels: name and PID of each parent that still runs, `pid N (exited)` for one that is gone (or whose PID now belongs to a newer process), `pid N (exited, was X.exe)` when a Security 4688 or Sysmon 1 event recorded that PID starting before the child (never guessed). `parent unknown` without WMI, `parent none` without a parent. The rest of the line always starts with `parent`, never with a path. `arguments` when the command line starts with the program's own path (nothing when it has no arguments), else `command line ...` (another spelling of the path, a different program). |
| RUNNING PROCESSES                    | `    module: path [status] => details <==== flags` | An unsigned module from outside Windows and Program Files loaded in the process; a side-loaded one has `!sideload` and the details of that flag. `    modules: no access` when the module list could not be read (protected processes). |
| TIMELINE, a script-runtime launcher  | `    script: path => created; N bytes[; hidden]` | The script containers (`.rpa`, `.rpyc`, `.pyc`, `.pyz`, `.a3x`, `.au3`, `.asar`, `.jar`, `.js`, outside the runtime's own library folders) and hidden or dot files up to two folders below the launcher: hidden ones first, then the biggest, at most 10. `created` is the file's creation time (UTC). On the launcher's first timeline line. |
| USB DRIVES, Drives                   | `E: => type ...` | The drive letter without a backslash: a drive row is no path. |
| USB DRIVES, Contents                 | `path\ => attributes ...` | A folder ends in `\`. `attributes` lists the file attributes in words (`hidden, system, read-only, archive, ...`, or `normal`); `streams` the alternate data streams with their sizes. |
| USB DRIVES, autorun.inf              | `    inf: [section] key=value` | Each line of the file, in order (keys like `shell\open\command` cannot be sub-line keys, so the whole entry is the value). |
| USB DRIVES, autorun.inf              | `    target: path [status] <==== flags` / `    icon file: path ...` | The files the autorun.inf starts (`open`, `shellexecute`, `shell\<verb>\command`) and its icon, relative paths resolved against the drive root. Also in FILES. |
| USB DRIVES, Shortcuts                | `    argument file: path [status] <==== flags` | An existing file the shortcut's arguments name: a full path, or one relative to the working folder, the shortcut's folder or the drive root (a worm's hidden copy). Also in FILES. |
| USB DRIVES, Shortcuts                | `    worm signs:`, `    item list target:`, `    target with variables:`, `    relative path:` | Why the shortcut is `!usb-worm-lnk`; the target from the shell items, from the environment block and the relative path, when they differ from the target. |
| SOFTWARE, Installed programs         | `    folder: path\`, `    key: <key>` | The install folder, and the Uninstall key: `HKLM\...\<subkey>`, `HKLM-x32\...\<subkey>` (WOW6432Node) or `HKU\<SID>\...\<subkey>` (per user). `<subkey>` is the key name as stored, e.g. an MSI product code `{GUID}` or a name like `TeamViewer`. The item is the raw DisplayName. TIMELINE `[INS]` lines have the same `key:` (and, for Store apps, `folder:`) sub-line. |
| SOFTWARE, Store and MSIX apps        | `    signer: ...`, `    folder: path` | The package signature now and the package's install folder. A Windows Update source (`x-windowsupdate://...`) is written as `Windows Update`. |
| SOFTWARE, Installed programs         | `hidden` | `yes` if SystemComponent is 1 |
| SOFTWARE, grouped line (`N entries from <publisher>`) | `    key: <key>; name <name>; version <version>` | One indented line per entry, with the DisplayName and DisplayVersion of that entry (also under the TIMELINE's grouped `[INS]` line). Several `key:` lines = a group; a single entry has one. |
| DEFENDER, TIMELINE `[DEF]`, SUMMARY | `    file: path`, `    process: path, pid:N:M`, `    resource: ...` | One line per item a detection names: a file (also `x.zip->inner.exe`), a process (with its pid), anything else (a registry key, ...). The item line has the threat and `=> action X` (and `process X`, the process that touched the file, when it is not a detected item). |
| TIMELINE and SUMMARY, downloads      | `    from: address`, `    page: address`, `    referrer: URL` | The download URL (browser: `host/path`; Zone.Identifier: the full URL), the page it was started from and the referrer, each once (a page or referrer that is the download URL itself is left out). The item line has the browser. |
| TIMELINE, NEW, AM and STP folder lines | `    files: a, b, c` | The names of a folder's files, about 150 characters per line, cut between names. AMCACHE inventory scans: `    files: folder\ => a, b, c`, every line with its folder. |
| TIMELINE, Run key changes (`AUT`)    | `    now: a, b, c` | The values the key has now. |
| TIMESTOMPING                         | `B`, `M` | Creation and modification time of the file now, with 7 fraction digits; most suspicious first. |
| SOFTWARE, Windows Installer          | `name` | The product name alone. The item contains name, version and manufacturer (`installed: Hamachi 2.4.0.79 (LogMeIn, Inc.)`), read from the event's data, so it reads the same on every Windows language. A status other than 0 follows as `, status 1602 (failed)`. |
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
| `!invisible-char` | an invisible character in the path, shown as `<U+XXXX>`. Every module flags only characters that are never part of normal names: zero-width space, word joiner and invisible operators, Hangul fillers (U+3164, U+115F, U+1160, U+FFA0), the Braille blank U+2800, BOM, Khmer / Mongolian invisible vowels and separators. USB DRIVES flags every invisible character, also the no-break space, ideographic space and zero-width (non-)joiner (normal in Persian, Japanese and web-page-titled names elsewhere), and a name that starts or ends with a space or ends with a dot. USB worms hide their copy in a folder named like that. Every module shows all of them as `<U+XXXX>`. |
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
| `!motw-removed` | a new program, script or shortcut in a drop location has a `Zone.Identifier` with ZoneId 0-2 (this computer, intranet, trusted) and no URL. Browsers write zone 3 with a URL; a dropper or tool wrote the low zone, which turns off SmartScreen and the download warnings. A missing stream is not flagged. |
| `!sideload` | an unsigned DLL lies next to a validly signed program (outside Windows and Program Files) that imports it: DLL side-loading. The DLL's line says `loaded by <program> (signed by <signer>)` and the proxy evidence, if any: `proxy DLL, forwards to <file> (original name <name>)` (a signed DLL in the folder whose version resource names the side-loaded DLL) or `exports forwarded: N of M` (exports that are forwarders or jump stubs). The program's line says `side-loads <dll>`. |
| `!known-malware` | the item matches a pattern of a known malware family from the curated database `resources/autodetect.txt` (Autodetect). A file on the timeline: its timeline line gets the flag and `known malware <family>: <note>` first in its details (and so reaches SUMMARY as a `[timeline ...]` line). Every other hit (task, Run entry, service, program, DNS name, command line, signer, a file without an event in the time window) is a SUMMARY line `[Autodetect] <item> => <family>: <note> <==== !known-malware`, at the earliest time the item was seen (an SRUM hour only when there is no other time); more than 10 of one family: one more line `<family>: N more items match`. |
| `!renamed-program` | **hint**: a validly signed program outside Windows and Program Files has a random-looking or lure name (invoice, setup, crack, ...) that is not the name it was built under (version resource OriginalFilename, else InternalName, else the PDB file name). The NEW line says `original name X`. A hint is not a finding on its own: it goes to SUMMARY only together with a strong flag on the same file or in the same folder. |
| `!proxy-exec` | a running program outside Windows and Program Files was started through a Windows program that launches programs for others: `forfiles /c`, `pcalua -a`, `conhost --headless`, `explorer.exe <path>`, `cmd /c call`, `rundll32 url.dll,FileProtocolHandler`, `scriptrunner -appvscript`, `wmic process call create`, `mshta`. Set in RUNNING PROCESSES from the parent chain (only parents that still run can be seen), and on `4688` / `SYSMON` timeline lines from the creating processes found in the process creation events. Also on the `4688` / `SYSMON` line of a launcher itself (not `explorer.exe`) pointed at a program outside Windows and Program Files that runs as a process of its own (a program, or a script another program runs), e.g. `cmd /c call <program in Temp>` or `pcalua -a <program in Downloads>`. For `cmd /c call` that is what call runs, not its arguments; a batch file (`cmd /c call build.bat`) runs inside cmd and is a timeline line without the flag. A launcher pointed at a folder there (`forfiles /p <folder in Temp> /m x.exe /c "cmd /c call @path"`) is a timeline line without the flag. The creators of every `!proxy-exec` event (up to 4 levels) are timeline lines too. |
| `!padded` | a new file in a drop location is inflated with one repeated byte (16 samples of 64 KB all the same byte) against the size limits of scanners and sandbox uploads. Programs over 50 MB: their overlay (data after the last section, before the signature) is more than 90 % of the file and padded. Other files over 100 MB: the whole file. The NEW line says `padded: N MB of byte 0xXX`. The flag goes on programs and on data files in the folder of a new program or the folder below it; other padded files only get the detail. Partial downloads, VM disks, sparse files, pagefile and hiberfil are not checked. |
| `!runtime-loader` | a new program that ships a script runtime (Ren'Py/Python, AutoIt, Node.js, Electron, Java, Lua: markers next to it or up to two folders below) whose folder also shows loader signs: a padded file, a random-named data file with an unknown extension and encrypted-looking content (> 512 KB, entropy > 7.9), a hidden or dot file next to its scripts, a program it started itself outside its folder and outside Windows and Program Files (or a proxy-execution launcher such as `forfiles /c`), or a `!motw-removed` file written within 2 minutes of one of its runs. The program's first line says `script runtime <kind>` and lists the signs in its folder; the signs of a run (`started <program>`, `!motw-removed file <path> written within 2 minutes of this run`) are on the line of that run (the latest run at or before them, else the nearest). The first and the last of these run lines get the flag; the runs between are counted (`+N more times`). The first line gets the flag only with signs of its own. A runtime alone is not flagged: games and tools look the same. Electron apps validly signed by a well-known publisher (`resources/publishers.txt`) and programs directly in a shared folder (Downloads, Desktop, Temp, the root of AppData, ...) are not checked; other Electron apps are, because a lot of malware is Electron-based. |
| `!usb-worm-lnk` | USB DRIVES: a shortcut on a removable drive (or the root of any drive) that looks like a USB worm's: it starts cmd, wscript, cscript, powershell, mshta, rundll32, regsvr32, explorer, ... or points into a hidden folder of the drive (target or arguments), its target is only in the item list or a relative path (no link info) and runnable, or it is named like the drive's label or a hidden folder. The indented `worm signs:` line says which. |
| `!disguised-icon` | a shortcut to a program or script shows a folder, document or drive icon (shell32.dll / imageres.dll index, or the icon of a .pdf, .docx, .jpg, ... file). USB worms make the shortcut look like the folder they hid. |
| `!autorun` | an autorun.inf on a drive root starts something (`open`, `shellexecute`, `shell\<verb>\command`), or a user's MountPoints2 key has a `Shell\<verb>\command` |
| `!hidden-system` | an item on a removable drive has the hidden and system attributes (not `System Volume Information`, `$RECYCLE.BIN`, `desktop.ini`, ...). Explorer hides these even when hidden files are shown. A fake `RECYCLER` folder (the recycle bin name of Windows XP) also says so. |
| `!clsid-folder` | a folder named `x.{GUID}`, or with a `desktop.ini` that sets `CLSID`, `CLSID2` or `UICLSID`: Explorer shows it as another shell object (e.g. the Recycle Bin) and hides its contents |
| `!ads` | a file on a removable drive or a drive root has an alternate data stream other than the ones Windows, browsers and sync tools write (`Zone.Identifier`, `SmartScreen`, Dropbox, ...) |
| `!explorer-hiding` | `HKLM\...\Explorer\Advanced\Folder\Hidden\SHOWALL\CheckedValue` is not 1 ("show hidden files" does not stick), or the `NoFolderOptions` policy blocks Folder Options |
