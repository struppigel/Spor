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

* One timeline of all events, oldest first, and a summary of flagged items
* Program runs from Prefetch, Amcache, PCA, UserAssist, BAM and ShimCache
* New and downloaded files with their download URL, browser downloads, mounted ISO/IMG/VHD files
* DLL side-loading, renamed signed programs, timestomping
* Running processes with parent chains and unsigned modules
* Persistence with times: Run keys, services, scheduled tasks (also deleted ones), Startup folders, WMI subscriptions
* Defender detections and exclusions, proxy settings, root certificates, browser extensions
* ClickFix traces, remote access tools, network connections and DNS cache
* USB worm profile: hidden items on USB drives, autorun.inf, shortcuts, USB device history
* Autodetect of known malware families (RenLoader, PavinLoader, CountLoader, ...)
* Signature check and hashes of every program file, and a whitelist that hides validly signed files in trusted locations

Details per module are in [docs/MODULES.md](docs/MODULES.md).

**Notes:** Spor changes nothing on the system. It reads locked files (SRUM, WebCache, Amcache, browser databases) through a shadow copy of the system drive and deletes the shadow copy at the end. Some antivirus programs may alert on that. 

## Why Spor may use the network

Spor itself never sends anything: no update check, no telemetry. Your firewall may still show traffic from Spor.exe, because Windows' signature check runs inside Spor's process and asks the certificate authorities (Microsoft, DigiCert, Sectigo, ...) whether a certificate was revoked. If the PC is offline, Spor uses only cached revocation data and marks those signatures `revocation not checked (offline)`.

## Reading the logs

* [Reading Spor logs](docs/Reading-Spor-logs.md) is a tutorial for helpers: how to read a log and what is normal on a clean PC
* [docs/LOG-FORMAT.md](docs/LOG-FORMAT.md) describes the log format, for helpers and for parsers

## Command line

Without options, Spor opens its window. With options, it scans without a window, e.g. `Spor.exe -scan -noopen -out C:\logs\Spor.txt`:

```
Spor.exe [-scan] [-profile default|usb|all] [-days 30] [-nowhitelist] [-noise REGEX] [-modules files,downloads,...]
         [-algo SHA256|SHA1|MD5] [-maxmb 500] [-nohash] [-out FILE] [-noopen]
```

Profiles: `default` runs every module except `usb`, `usb` runs the USB worm scan, `all` runs everything. `-modules` replaces the profile. Details: [docs/MODULES.md](docs/MODULES.md).

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
src/Scanner.cs           module runner, log header, timeline, summary, FILES
src/Context.cs           options, user profiles and hives, hashing, trust rule
src/Rules.cs             shared whitelist and flag rules
src/Autodetect.cs        known-malware patterns (resources/autodetect.txt)
src/Modules/*.cs         one class per module
src/*.cs                 parsers and helpers (PE, .lnk, SQLite, ESE, signatures, Windows API)
```

## Author

Karsten Hahn

Twitter/X: [@Struppigel](https://x.com/struppigel)

Mastodon: [struppigel@infosec.exchange](https://infosec.exchange/@struppigel)

Bluesky: [struppigel.bsky.social](https://bsky.app/profile/struppigel.bsky.social)

Youtube: [MalwareAnalysisForHedgehogs](https://www.youtube.com/c/MalwareAnalysisForHedgehogs)

## License

[MIT License](LICENSE)
