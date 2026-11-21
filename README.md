# Spor

Forensic triage tool for malware removal helpers. It collects execution, download, persistence and remote-access evidence, puts it on one timeline and writes everything to one log file, `Spor.txt`.

Spor started as a set of my PowerShell snippets for malware removal help.

## Download

[Releases page](https://github.com/struppigel/Spor/releases)

## How to use

1. Download `Spor.exe`
2. Run it and allow it to run as administrator
3. Choose a profile if the helper asked for one (**Default**, **USB worm** or **All**), click **Scan** and wait. This takes a few minutes.
4. The log `Spor.txt` opens in Notepad when the scan is done. It is saved next to `Spor.exe`

## Features

* Program runs from Prefetch, Amcache, PCA, UserAssist, BAM, ShimCache and the Compatibility Assistant
* Files loaded by programs, read from Prefetch
* New executables, scripts and archives, with the download URL and referrer from `Zone.Identifier`; Mark-of-the-Web removal, padded files
* DLL side-loading (unsigned DLL imported by a signed program next to it, with proxy-DLL evidence) and renamed signed programs
* Running processes with parent chains and unsigned modules, proxy execution (forfiles, cmd /c call, pcalua, ...), process creation events (4688, Sysmon)
* Script-runtime launchers (Ren'Py/Python, AutoIt, Node.js, Java, Lua) with their script files, and loader signs around them
* Browser downloads, files opened in Explorer, mounted ISO/IMG/VHD files, WinRAR and 7-Zip history
* Timestomping detection from the NTFS change journal
* Software installed, updated or removed: Uninstall keys, Windows Installer events, Store/MSIX apps
* Persistence with times: Run keys, services, scheduled tasks (also deleted ones), Startup folders, WMI subscriptions
* Defender detections, exclusions, setting changes and cloud lookups, cleared event logs
* ClickFix traces: Run dialog, Explorer address bar, PowerShell history
* Webcam and microphone use, remote access tools (AnyDesk, TeamViewer, ScreenConnect, ...)
* Data sent per program (SRUM), current connections, DNS cache (also victim-ID host names and abused TLDs)
* Local accounts, administrators, hidden accounts, account changes
* One timeline of all events, oldest first, and a summary of flagged items
* USB worm profile: the contents of USB drives with hidden and invisible-named items (shown as `<U+00A0>`, ...) and their attributes, autorun.inf, shortcuts with target, arguments and icon (folder icons on programs are flagged), Explorer settings that hide files, MountPoints2, USB device history and connects, files opened from USB drives
* Autodetect: known malware families (RenLoader, PavinLoader, CountLoader, ...) from a curated pattern database, named in the summary
* Signature check of every program file (WinVerifyTrust, Windows catalogs, MSIX package signatures), SHA256 and MD5 hashes, version information
* Whitelist that hides validly signed files in trusted locations, so the log stays readable. You can turn it off.
* Log format with one line per item, easy to read and to parse

Details per module are in [docs/MODULES.md](docs/MODULES.md).

**Notes:** Spor changes nothing on the system. It reads locked files (SRUM, WebCache, Amcache, browser databases) through a shadow copy of the system drive and deletes the shadow copy at the end. Some antivirus programs may alert on that. 

## Why Spor may use the network

Spor itself never sends anything. It has no update check and no telemetry, and the log stays on the PC until you send it to someone.

But your firewall may still see network traffic while Spor scans. When Spor checks a signature, Windows checks whether the certificate was revoked, e.g., because it was stolen. For that Windows downloads revocation lists (CRL) or asks the certificate authority (OCSP), and it may download missing intermediate certificates. These requests go to the servers of the certificate authorities, e.g., Microsoft, DigiCert or Sectigo. Windows' signature check runs inside Spor's process, so a firewall may show them as coming from Spor.exe.

If one signature check takes longer than 4 seconds, e.g., because the PC is offline, Spor uses only the revocation data Windows has cached for the rest of the scan. A signature whose revocation status could not be checked says `revocation not checked (offline)` in the FILES section.

The NETWORK section reads the connections and the DNS cache that already exist on the PC. It does not make connections of its own.

## Reading the logs

* [Reading Spor logs](docs/Reading-Spor-logs.md) is a tutorial for helpers: how to read a log and what is normal on a clean PC
* [docs/LOG-FORMAT.md](docs/LOG-FORMAT.md) describes the log format, for helpers and for parsers

## Command line

Without options, Spor opens its window. With options, it scans without a window, e.g. `Spor.exe -scan -noopen -out C:\logs\Spor.txt`:

```
Spor.exe [-scan] [-profile default|usb|all] [-days 30] [-nowhitelist] [-noise REGEX] [-modules files,downloads,...]
         [-algo SHA256|SHA1|MD5] [-maxmb 500] [-nohash] [-out FILE] [-noopen]
```

Profiles: `default` runs every module except `usb`, `usb` runs the USB worm scan (drives, shortcuts, autorun.inf, USB history, plus prefetch, exec, files, persistence, processes), `all` runs everything. `-modules` replaces the profile. Details: [docs/MODULES.md](docs/MODULES.md).

Spor asks for admin rights (UAC). It writes `Spor.txt` next to the exe, or to the Desktop if that folder isn't writable.

## Supported OS

Windows 10 and 11. Spor needs .NET Framework 4.8, which is part of both, so there is nothing to install. I test it on Windows 11.

## Building

You need the .NET SDK.

* **Windows:** `dotnet build -c Release`, or open `Spor.csproj` in Visual Studio 2022
* **Linux:** install `dotnet-sdk-8.0` and `mono-devel`, then run `dotnet build -c Release`. The project uses Mono's 4.8 reference assemblies, so the build needs no NuGet downloads.

The exe is written to `bin\Release\net48\Spor.exe`.

Code layout:

```
src/Program.cs           entry point: window, or command line options
src/MainForm.cs          the window
src/Scanner.cs           module runner, log header, timeline, summary, FILES
src/Context.cs           options, user profiles and hives, hashing, trust rule
src/Rules.cs             shared whitelist and flag rules
src/Whitelist.cs         known-noise locations and names (resources/whitelist.txt)
src/Correlate.cs         checks across modules after the scan (script-runtime launchers)
src/Autodetect.cs        known-malware patterns (resources/autodetect.txt) over everything the modules collected
src/Pe.cs                read-only PE parser (imports, exports, PDB path, overlay)
src/Sideload.cs          DLL side-loading rule
src/Names.cs             random-looking and lure names, renamed programs
src/Padded.cs            padded (inflated) files
src/HostNames.cs         DNS names with victim IDs, abused TLDs
src/Native.cs            Windows API calls (registry, volumes, decompression, LSA, processes and modules)
src/Signature.cs         WinVerifyTrust and catalog lookup
src/Package.cs           MSIX package signatures
src/Sqlite.cs            read-only SQLite reader for browser history
src/Ese.cs               ESE databases through esent.dll (SRUM, WebCache)
src/Helpers.cs           Zone.Identifier, .lnk parser, event log queries, command lines
src/Util.cs              text files, folder walk, formatting
src/Modules/*.cs         one class per module (Usb.cs: the USB worm scan)
```

## Author

Karsten Hahn

Twitter/X: [@Struppigel](https://x.com/struppigel)

Mastodon: [struppigel@infosec.exchange](https://infosec.exchange/@struppigel)

Bluesky: [struppigel.bsky.social](https://bsky.app/profile/struppigel.bsky.social)

Youtube: [MalwareAnalysisForHedgehogs](https://www.youtube.com/c/MalwareAnalysisForHedgehogs)

## License

[MIT License](LICENSE)
