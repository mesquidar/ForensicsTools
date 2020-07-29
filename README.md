# ForensicsTools
A list of free and open forensics analysis tools and other resources

- [Awesome Forensics](#awesome-forensics)
- [Collections](#collections)
- [Tools](#tools)
  - [Distributions](#distributions)
  - [Frameworks](#frameworks)
  - [Live forensics](#live-forensics)
  - [Acquisition](#acquisition)
  - [Imageing](#imageing)
  - [Carving](#carving)
  - [Memory Forensics](#memory-forensics)
  - [Network Forensics](#network-forensics)
  - [Windows Artifacts](#windows-artifacts)
    - [NTFS/MFT Processing](#ntfsmft-processing)
  - [OS X Forensics](#os-x-forensics)
  - [Mobile Forensics](#mobile-forensics)
  - [Docker Forensics](#docker-forensics)
  - [Internet Artifacts](#internet-artifacts)
  - [Timeline Analysis](#timeline-analysis)
  - [Disk image handling](#disk-image-handling)
  - [Decryption](#decryption)
  - [Management](#management)
  - [Picture Analysis](#picture-analysis)
  - [Metadata Forensics](#metadata-forensics)
  - [Website Forensics](#website-forensics)
- [Learn Forensics](#learn-forensics)
  - [CTFs](#ctfs)
- [Resources](#resources)
  - [Books](#books)
  - [File System Corpora](#file-system-corpora)
  - [Twitter](#twitter)
  - [Blogs](#blogs)
  - [Other](#other)
- [Related Awesome Lists](#related-awesome-lists)

## Collections

- [DFIR – The definitive compendium project](https://aboutdfir.com) - Collection of forensic resources for learning and research. Offers lists of certifications, books, blogs, challenges and more
- [dfir.training](https://www.dfir.training/) - Database of forensic resources focused on events, tools and more
- :star: [ForensicArtifacts.com Artifact Repository](https://github.com/ForensicArtifacts/artifacts) - Machine-readable knowledge base of forensic artifacts

## Tools

- [Forensics tools on Wikipedia](https://en.wikipedia.org/wiki/List_of_digital_forensics_tools)
- [Eric Zimmerman's Tools](https://ericzimmerman.github.io/#!index.md)

### Distributions

- [bitscout](https://github.com/vitaly-kamluk/bitscout) - LiveCD/LiveUSB for remote forensic acquisition and analysis
- [CAINE](https://www.caine-live.net/)
- [GRML-Forensic](https://grml-forensic.org/)
- :star:[SANS Investigative Forensics Toolkit (sift)](https://github.com/teamdfir/sift) - Linux distribution for forensic analysis
- [Santoku Linux](https://santoku-linux.com/) - Santoku is dedicated to mobile forensics, analysis, and security, and packaged in an easy to use, Open Source platform.
- [Sumuri Paladin](https://sumuri.com/software/paladin/) - Linux distribution that simplifies various forensics tasks in a forensically sound manner via the PALADIN Toolbox
- [Tsurugi Linux](https://tsurugi-linux.org/) - Linux distribution for forensic analysis
- [WinFE](https://www.winfe.net/home) - Windows Forensics enviroment

### Frameworks

- :star:[Autopsy](http://www.sleuthkit.org/autopsy/) - SleuthKit GUI
- [dff](https://github.com/arxsys/dff) - Forensic framework
- [dexter](https://github.com/coinbase/dexter) - Dexter is a forensics acquisition framework designed to be extensible and secure
- [IntelMQ](https://github.com/certtools/intelmq) - IntelMQ collects and processes security feeds
- [Kuiper](https://github.com/DFIRKuiper/Kuiper) - Digital Investigation Platform
- [Laika BOSS](https://github.com/lmco/laikaboss) - Laika is an object scanner and intrusion detection system
- [RegRippy](https://github.com/airbus-cert/regrippy) - is a framework for reading and extracting useful forensics data from Windows registry hives.
- [PowerForensics](https://github.com/Invoke-IR/PowerForensics) - PowerForensics is a framework for live disk forensic analysis
- :star: [The Sleuth Kit](https://github.com/sleuthkit/sleuthkit) - Tools for low level forensic analysis
- [turbinia](https://github.com/google/turbinia) - Turbinia is an open-source framework for deploying, managing, and running forensic workloads on cloud platforms
- [IPED - Indexador e Processador de Evidências Digitais](https://github.com/sepinf-inc/IPED) - Brazilian Federal Police Tool for Forensic Investigations

### Live forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response: remote live forensics for incident response
- [Linux Expl0rer](https://github.com/intezer/linux-explorer) - Easy-to-use live forensics toolbox for Linux endpoints written in Python & Flask
- [mig](https://github.com/mozilla/mig) - Distributed & real time digital forensics at the speed of the cloud
- [osquery](https://github.com/osquery/osquery) - SQL powered operating system analytics

### Acquisition

- [artifactcollector](https://github.com/forensicanalysis/artifactcollector) - A customizable agent to collect forensic artifacts on any Windows, macOS or Linux system
- [ArtifactExtractor](https://github.com/Silv3rHorn/ArtifactExtractor) - Extract common Windows artifacts from source images and VSCs
- [AVML](https://github.com/microsoft/avml) - A portable volatile memory acquisition tool for Linux
- [DFIR ORC](https://dfir-orc.github.io/) - Forensics artefact collection tool for systems running Microsoft Windows
- [DumpIt](https://www.comae.com/dumpit/) - 
- [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector) - Collect artifacts on windows
- [FireEye Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) 
- [LiME](https://github.com/504ensicsLabs/LiME) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD
- [Magnet RAM Capture](https://www.magnetforensics.com/resources/magnet-ram-capture/) - is a free imaging tool designed to capture the physical memory 
- [RAM Capturer](https://belkasoft.com/ram-capturer) - by Belkasoft is a free tool to dump the data from a computer’s volatile memory. It’s compatible with Windows OS.
- [Velociraptor](https://github.com/Velocidex/velociraptor) - Velociraptor is a tool for collecting host based state information using Velocidex Query Language (VQL) queries

### Imageing

- [dc3dd](https://sourceforge.net/projects/dc3dd/) - Improved version of dd
- [dcfldd](http://dcfldd.sourceforge.net) - Different improved version of dd (this version has some bugs!, another version is on github [adulau/dcfldd](https://github.com/adulau/dcfldd))
- [FTK Imager](https://accessdata.com/product-download/ftk-imager-version-3-4-3/) - Free imageing tool for windows
- [Guymager](https://guymager.sourceforge.io/) - Open source version for disk imageing on linux systems

### Carving

- [bstrings](https://github.com/EricZimmerman/bstrings) - Improved strings utility
- [bulk_extractor](https://github.com/simsong/bulk_extractor) - Extracts informations like email adresses, creditscard numbers and histrograms of disk images
- [floss](https://github.com/fireeye/flare-floss) - Static analysis tool to automatically deobfuscate strings from malware binaries
- :star: [photorec](https://www.cgsecurity.org/wiki/PhotoRec) - File carving tool
- [swap_digger](https://github.com/sevagas/swap_digger) - A bash script used to automate Linux swap analysis, automating swap extraction and searches for Linux user credentials, Web form credentials, Web form emails, etc.

### Memory Forensics

- [FireEye RedLine](https://www.fireeye.com/services/freeware/redline.html) - provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis and the development of a threat assessment profile.
- [inVtero.net](https://github.com/ShaneK2/inVtero.net) - High speed memory analysis framework
  developed in .NET supports all Windows x64, includes code integrity and write support
- [KeeFarce](https://github.com/denandz/KeeFarce) - Extract KeePass passwords from memory
- [MemProcFS](https://github.com/ufrisk/MemProcFS) - An easy and convenient way of accessing physical memory as files a virtual file system.
- [Rekall](https://github.com/google/rekall) - Memory Forensic Framework
- :star:[volatility](https://github.com/volatilityfoundation/volatility) - The memory forensic framework
- [VolUtility](https://github.com/kevthehermit/VolUtility) - Web App for Volatility framework

### Network Forensics

- [NetworkMiner](https://www.netresec.com/?page=Networkminer)
- [Xplico](https://www.xplico.org/)
- [WireShark](https://www.wireshark.org/)

### Windows Artifacts

- [Beagle](https://github.com/yampelo/beagle) -  Transform data sources and logs into graphs
- [CrowdResponse](https://www.crowdstrike.com/resources/community-tools/crowdresponse/) - by CrowdStrike is a static host data collection tool
- [FRED](https://www.pinguin.lu/fred) - Cross-platform microsoft registry hive editor
- [LastActivityView](nirsoft.net/utils/computer_activity_view.html) - LastActivityView by Nirsoftis a tool for Windows operating system that collects information from various sources on a running system, and displays a log of actions made by the user and events occurred on this computer. 
- [LogonTracer](https://github.com/JPCERTCC/LogonTracer) - Investigate malicious Windows logon by visualizing and analyzing Windows event log 
- [python-evt](https://github.com/williballenthin/python-evt) - Pure Python parser for classic Windows Event Log files (.evt)
- [RegRipper3.0](https://github.com/keydet89/RegRipper3.0) - RegRipper is an open source Perl tool for parsing the Registry and presenting it for analysis.

#### NTFS/MFT Processing

- [MFT-Parsers](http://az4n6.blogspot.com/2015/09/whos-your-master-mft-parsers-reviewed.html) - Comparison of MFT-Parsers
- [MFTExtractor](https://github.com/aarsakian/MFTExtractor) - MFT-Parser
- [NTFS journal parser](http://strozfriedberg.github.io/ntfs-linker/)
- [NTFS USN Journal parser](https://github.com/PoorBillionaire/USN-Journal-Parser)
- [RecuperaBit](https://github.com/Lazza/RecuperaBit) - Reconstruct and recover NTFS data
- [python-ntfs](https://github.com/williballenthin/python-ntfs) - NTFS analysis

### OS X Forensics

- [APFS Fuse](https://github.com/sgan81/apfs-fuse) - is a read-only FUSE driver for the new Apple File System
- [APOLLO](https://github.com/mac4n6/APOLLO)
- [Disk-Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - is a Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [MAC OSX Artifacts](https://docs.google.com/spreadsheets/d/1X2Hu0NE2ptdRj023OVWIGp5dqZOw-CfxHLOW_GNGpX8/edit#gid=1317205466) - locations artifacts by mac4n6 group
- [mac_apt (macOS Artifact Parsing Tool)](https://github.com/ydkhatri/mac_apt) - Extracts forensic artifacts from disk images or live machines
- [MacLocationsScraper](https://github.com/mac4n6/Mac-Locations-Scraper) - Dump the contents of the location database files on iOS and macOS.
- [macMRUParser](https://github.com/mac4n6/macMRU-Parser) - Python script to parse the Most Recently Used (MRU) plist files on macOS into a more human friendly format.
- [OSXAuditor](https://github.com/jipegit/OSXAuditor)
- [OSX Collect](https://github.com/Yelp/osxcollector)


### Mobile Forensics

- [Andriller](https://github.com/den4uk/andriller) - is software utility with a collection of forensic tools for smartphones. It performs read-only, forensically sound, non-destructive acquisition from Android devices
- [ALEAPP](https://github.com/abrignoni/ALEAPP) - An Android Logs Events and Protobuf Parser
- [iOS Frequent Locations Dumper](https://github.com/mac4n6/iOS-Frequent-Locations-Dumper) - Dump the contents of the StateModel#.archive files located in /private/var/mobile/Library/Caches/com.apple.routined/
- [MEAT](https://github.com/jfarley248/MEAT) - Perform different kinds of acquisitions on iOS devices
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) - is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis.
- [OpenBackupExtractor](https://github.com/vgmoose/OpenBackupExtractor) - is an app for extracting data from iPhone and iPad backups.


### Docker Forensics

- [dof (Docker Forensics Toolkit)](https://github.com/docker-forensics-toolkit/toolkit) - Extracts and interprets forensic artifacts from disk images of Docker Host systems
- [Docker Explorer](https://github.com/google/docker-explorer) Extracts and interprets forensic artifacts from disk images of Docker Host systems

### Internet Artifacts

- [ChromeCacheView](https://www.nirsoft.net/utils/chrome_cache_view.html) - by Nirsoft is a small utility that reads the cache folder of Google Chrome Web browser, and displays the list of all files currently stored in the cache
- [chrome-url-dumper](https://github.com/eLoopWoo/chrome-url-dumper) - Dump all local stored infromation collected by Chrome
- [Dumpzilla](http://www.dumpzilla.org/) - extract all forensic interesting information of Firefox, Iceweasel and Seamonkey browsers
- [hindsight](https://github.com/obsidianforensics/hindsight) - Internet history forensics for Google Chrome/Chromium
- [unfurl](https://github.com/obsidianforensics/unfurl) - Extract and visualize data from URLs

### Timeline Analysis

- [DFTimewolf](https://github.com/log2timeline/dftimewolf) - Framework for orchestrating forensic collection, processing and data export using GRR and Rekall
- :star: [plaso](https://github.com/log2timeline/plaso) - Extract timestamps from various files and aggregate them
- [timeliner](https://github.com/airbus-cert/timeliner) - A rewrite of mactime, a bodyfile reader
- [timesketch](https://github.com/google/timesketch) - Collaborative forensic timeline analysis

### Disk image handling

- [Disk Arbitrator](https://github.com/aburgh/Disk-Arbitrator) - A Mac OS X forensic utility designed to help the user ensure correct forensic procedures are followed during imaging of a disk device
- [imagemounter](https://github.com/ralphje/imagemounter) - Command line utility and Python package to ease the (un)mounting of forensic disk images
- [libewf](https://github.com/libyal/libewf) - Libewf is a library and some tools to access the Expert Witness Compression Format (EWF, E01)
- [OSFMount](https://www.osforensics.com/tools/mount-disk-images.html) - allows you to mount local disk image files (bit-for-bit copies of an entire disk or disk partition) in Windows as a physical disk or a logical drive
- [PancakeViewer](https://github.com/forensicmatt/PancakeViewer) - Disk image viewer based in dfvfs, similar to the FTK Imager viewer.
- [xmount](https://www.pinguin.lu/xmount) - Convert between different disk image formats

### Decryption

- [hashcat](https://hashcat.net/hashcat/) - Fast password cracker with GPU support
- [John the Ripper](https://www.openwall.com/john/) - Password cracker

### Management

- [dfirtrack](https://github.com/stuhli/dfirtrack) - Digital Forensics and Incident Response Tracking application, track systems
- [Incidents](https://github.com/veeral-patel/incidents) - Web application for organizing non-trivial security investigations. Built on the idea that incidents are trees of tickets, where some tickets are leads

### Picture Analysis

- [Ghiro](http://www.getghiro.org/) - is a fully automated tool designed to run forensics analysis over a massive amount of images
- [sherloq](https://github.com/GuidoBartoli/sherloq) - An open-source digital photographic image forensic toolset

### Metadata Forensics

- [ExifTool](https://exiftool.org/) by Phil Harvey
- [FOCA](https://github.com/ElevenPaths/FOCA) - FOCA is a tool used mainly to find metadata and hidden information in the documents

### Website Forensics

## Learn forensics

- [Forensic challenges](https://www.amanhardikar.com/mindmaps/ForensicChallenges.html) - Mindmap of forensic challenges
- [Training material](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational) - Online training material by European Union Agency for Network and Information Security for different topics (e.g. [Digital forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#digital_forensics), [Network forensics](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material/technical-operational/#network_forensics))

### CTFs

- [Forensics CTFs](https://github.com/apsdehal/awesome-ctf/blob/master/README.md#forensics)
- [Precision Widgets of North Dakota Intrusion](https://betweentwodfirns.blogspot.com/2017/11/dfir-ctf-precision-widgets-of-north.html)

### Challenges

- [SANS Forensics Challenges](https://digital-forensics.sans.org/community/challenges)

## Resources

### Webs

- [InsecInstitute Resources](https://resources.infosecinstitute.com/)
- [SANS Digital Forensics](https://digital-forensics.sans.org/)

### Books

*more at [Recommended Readings](http://dfir.org/?q=node/8) by Andrew Case*

- [Network Forensics: Tracking Hackers through Cyberspace](https://www.pearson.com/us/higher-education/program/Davidoff-Network-Forensics-Tracking-Hackers-through-Cyberspace/PGM322390.html) - Learn to recognize hackers’ tracks and uncover network-based evidence
- [The Art of Memory Forensics](https://www.memoryanalysis.net/amf) - Detecting Malware and Threats in Windows, Linux, and Mac Memory
- [The Practice of Network Security Monitoring](https://nostarch.com/nsm) - Understanding Incident Detection and Response

### File System Corpora

- [Digital Forensic Challenge Images](https://www.ashemery.com/dfir.html) - Two DFIR challenges with images
- [Digital Forensics Tool Testing Images](http://dftt.sourceforge.net)
- [FAU Open Research Challenge Digital Forensics](https://openresearchchallenge.org/digitalForensics/appliedforensiccomputinggroup)
- [The CFReDS Project](https://www.cfreds.nist.gov)
  - [Hacking Case (4.5 GB NTFS Image)](https://www.cfreds.nist.gov/Hacking_Case.html)

### Twitter

- [@4n6ist](https://twitter.com/4n6ist)
- [@aheadless](https://twitter.com/aheadless)
- [@AppleExaminer](https://twitter.com/AppleExaminer) - Apple OS X & iOS Digital Forensics
- [@blackbagtech](https://twitter.com/blackbagtech)
- [@carrier4n6](https://twitter.com/carrier4n6) - Brian Carrier, author of Autopsy and the Sleuth Kit
- [@CindyMurph](https://twitter.com/CindyMurph) - Detective & Digital Forensic Examiner
- [@EricRZimmerman](https://twitter.com/EricRZimmerman) - Certified SANS Instructor
- [@forensikblog](https://twitter.com/forensikblog) - Computer forensic geek
- [@HECFBlog](https://twitter.com/HECFBlog) - SANS Certified Instructor
- [@Hexacorn](https://twitter.com/Hexacorn) - DFIR+Malware
- [@hiddenillusion](https://twitter.com/hiddenillusion)
- [@iamevltwin](https://twitter.com/iamevltwin) - Mac Nerd, Forensic Analyst, Author & Instructor of SANS FOR518
- [@jaredcatkinson](https://twitter.com/jaredcatkinson) - PowerShell Forensics
- [@maridegrazia](https://twitter.com/maridegrazia) - Computer Forensics Examiner
- [@sleuthkit](https://twitter.com/sleuthkit)
- [@williballenthin](https://twitter.com/williballenthin)
- [@XWaysGuide](https://twitter.com/XWaysGuide)

### Blogs

- [SANS Forensics Blog](https://www.sans.org/blog/?focus-area=digital-forensics)
- [thisweekin4n6.wordpress.com](thisweekin4n6.wordpress.com) - Weekly updates for forensics

### Other

- [/r/computerforensics/](https://www.reddit.com/r/computerforensics/) - Subreddit for computer forensics
- [ForensicPosters](https://github.com/Invoke-IR/ForensicPosters) - Posters of file system structures
- [HFS+ Resources](https://github.com/mac4n6/HFSPlus_Resources)
- [mac4n6 Presentations](https://github.com/mac4n6/Presentations) - Presentation Archives for OS X and iOS Related Research
- [SANS Forensics CheatSheets](https://digital-forensics.sans.org/community/cheat-sheets) - Different CheatSheets from SANS
- [SANS Digital Forensics Posters](https://digital-forensics.sans.org/community/posters) - Digital Forensics Posters from SANS
- [SANS WhitePapers](https://digital-forensics.sans.org/community/whitepapers) - White Papers written by forensic practitioners seeking GCFA, GCFE, and GREM Gold

## Related Awesome Lists

- [Android Security](https://github.com/ashishb/android-security-awesome)
- [AppSec](https://github.com/paragonie/awesome-appsec)
- [Awesome Forensics](https://github.com/cugu/awesome-forensics)
- [CTFs](https://github.com/apsdehal/awesome-ctf)
- [Hacking](https://github.com/carpedm20/awesome-hacking)
- [Honeypots](https://github.com/paralax/awesome-honeypots)
- [Incident-Response](https://github.com/meirwah/awesome-incident-response)
- [Infosec](https://github.com/onlurking/awesome-infosec)
- [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
- [Pentesting](https://github.com/enaqx/awesome-pentest)
- [Security](https://github.com/sbilly/awesome-security)
- [Social Engineering](https://github.com/v2-dev/awesome-social-engineering)
- [YARA](https://github.com/InQuest/awesome-yara)
