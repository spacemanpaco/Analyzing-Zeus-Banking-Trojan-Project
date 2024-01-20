Basic Static Analysis 

We used PEStudio to analyze the file further, which disassembles the binary to its code to try and identify API calls, functions or possible URLs embedded within the file. It is also able to show the raw and virtual size of the file, which further helps in identifying packed binaries.  

PEStudio showed a URL [corect.com] embedded in the file. Searching this URL in VirusTotal yielded no significant results or connections to Malware 

 

Raw vs Virtual Size was also shoowing that they are close in file size, meaning executable is most likely not packed. Bad actors use compression on their code to be able to contain as many capabilities into their payload as possible. 

  

Suspected API Calls were identified that the executable had embedded in it. These functionalities show the bad actor would be able to have a wide range of access to many functions on the victim’s computer. 

    AllowSetForegroundWindow 

    GetEnvironmentVariable 

    GetEnvironmentVariable 

    VkKeyScan 

    GetAsyncKeyState 

    PathRenameExtension 

    WriteFile 

    FindNextFile 

    GetCurrentThread 

    Execution through API,WinExec 

    GlobalAddAtom 

    GetClipboardOwner 

    GetClipboardData 

    EnumClipboardFormats 

    DdeQueryNextServer 

    GetConsoleAliasExesLength 

    SetCurrentDirectory 

    CallWindowProc 

    UpdateWindow 

    GetCapture 

    IsWindowEnabled 

    GetWindowTextLength 

    DeleteCriticalSection 

    SizeofResource 

    GetLogicalDrives 

    GetTickCount 

    GetDriveType 

    LocalUnlock 

    HeapFree 

    VirtualQueryEx 

    LocalAlloc 

    LocalFree 

    CopyAcceleratorTable 

    SwapMouseButton 

    PathQuoteSpaces 

    PathCombine 

    GetCompressedFileSize 

    CreateFileMapping 

    GetPrivateProfileInt 

    FreeLibrary 

    GetModuleHandle 

  

Suspected Function Calls were extracted from the strings identified. They were referencing three (3) different DLLs which could be leveraged further through functions being called. There was alot of obfuscated code before references to the DLLs which could mean the actual function was in the obfuscation.  

    AsksmaceaglyBubuPulsKaifTeasMistPeelGhisPrimChaoLyreroeno 

    KERNEL32.MulDiv 

    BagsSpicDollBikeAzonPoopHamsPyasmap 

    KERNEL32.SetCurrentDirectory 

    BardHolyawe 

    SHLWAPI.SHFreeShared 

    BathEftsDawnvilepughThroCymakohloverMitefuzerat 

    SHLWAPI.PathMakeSystemFolder 

    BemaCadsPodsWavyCedeRadsbrioOustPerefenom 

    USER32.SetDlgItemText 

    BullbonyaweeWaitsnugTierDriblibye 

    KERNEL32.VirtualQuery 

    CameValeWauler 

    USER32.IsIconic 

    CedeSalsshulLimyThroliraValeDonabox 

    USER32.CreateCaret 

    CellrotoCrudUntohighCols 

    KERNEL32.CreateFile 

    DenyLubeDunssawsOresvarut 

    SHLWAPI.PathRemoveFileSpec 

    DragRoutflusCrowPeatmownNewsyaksSerfmare 

    USER32.DestroyIcon 

    Dumpcotsavo 

    USER32.SetDlgItemInt 

    DungBadebankBangGelthoboCocaBozotsksWheyVaryShoghoseNipsCadisi 

    USER32.EndPaint 

    ExitRollWoodGumsgamaSloerevsWussletssinkYearZitiryesHypout 

    USER32.GetClassInfo 

    FociTalcileador 

    KERNEL32.ConvertDefaultLocale 

    GeneAilshe 

    KERNEL32.FindFirstFile 

    GhisGoodHowlCoonCigscateged 

    KERNEL32.GetWindowsDirectory 

    GimpWadsdashHoraYardSeatDeanScanscowRantKeasfib 

    KERNEL32.LCMapString 

    Haesourfe 

    USER32.GetKeyNameText 

    HoggSoonLasstwaeNapeCeilBawlscopdub 

    KERNEL32.SystemTimeToFileTime 

    Icontellnoway 

    SHLWAPI.PathRemoveBlanks 

    ImidslatJokyCombdrubChefBilkSale 

    USER32.GetShellWindow 

    IzararfsFlamWostAirsconsMouefemelallPoretweeSacsOxidMinx 

    SHLWAPI.PathAddExtension 

    JabsNaveFateLariManyLeeksecshiesBawlwoo 

    KERNEL32.CreateIoCompletionPort 

    KatsDoreOmerBetsKoraKeef 

    KERNEL32.GetShortPathName 

    KineChamLows 

    KERNEL32.SetCurrentDirectory 

    LeerMiff 

    KERNEL32.LeaveCriticalSection 

    MaarSectFiscNextMattbamsErasnimstoeaBadshon 

    USER32.GetClassInfo 

    MarkMokeOsesShwaSkegpornlimemim 

    KERNEL32.GetStartupInfo 

    MeanOrrabirogirtWorkGawpSassPirnVinoLotaPledEidefe 

    SHLWAPI.SHLockShared 

    NextLoveOralwanySurfhm 

    KERNEL32.VerSetConditionMask 

    NisiBoyolineJiaoveryObiaowedblamHaetMaulweensky 

    SHLWAPI.PathCanonicalize 

    OastcabskamiKartDumbInksSomsMass 

    KERNEL32.SetCurrentDirectory 

    PeckQuinFillrillsaw 

    KERNEL32.GetThreadPriority 

    RamilimaputtHastJobs 

    KERNEL32.FindNextFile 

    RemsSlaySoreAnoaaxalbuffusesemeuMapsyogaHangLoud 

    SHLWAPI.PathMakePretty 

    RidsFineZingMickMomsdue 

    USER32.GetMonitorInfo 

    SeminerdsoloseenYaginobox 

    SHLWAPI.PathIsLFNFileSpec 

    SiretomsbritGrewIckyNapaLumsBoaren 

    KERNEL32.OpenFileMapping 

    SlabKitsSlayseptPfftjiffSabsdeskOafsNowtMemsKirnKepiMiffDunt 

    KERNEL32.OpenSemaphore 

    SoldKartAgueiliaRushWauldhal 

    SHLWAPI.PathIsUNC 

    SuitplieGunsMaidBaitFeusJiaotodycolyAlbsLuneToyspe 

    USER32.GetProp 

    SungActaKopsMaarposyparefuzedeck 

    SHLWAPI.PathIsDirectory 

    ToeaTailecusGeesSoliCadeSpueEndsPlaykaphall 

    SHLWAPI.PathRemoveArgs 

    Vavsrubepodsjadebrooli 

    USER32.GetUpdateRgn 

    VeerCrawFlateel 

    SHLWAPI.PathParseIconLocation 

    WainMeekPinyWonkpooflaudsir 

    KERNEL32.GetWindowsDirectory 

    WhopTestrangrapsdebsTzarNipaYins 

    KERNEL32.DeleteFile 

    YeukMags 

    KERNEL32.GlobalHandle 

    ZetaBeduPirnhipsjailTingSrisTeleAposhuskNameHoerflagemuwo 

    USER32.LoadIcon 

  

There were references to Libraries in the executable. The obfuscated code could be refencing URL calls that could be embedded in to the SHLWAPI.dll. CPU instructions could be coded into the KERNEL32.dll, allowing the bad actor to have full control of the victim’s processor. Leveraging the USER32.dll would allow the bad actor to be able to call for functions related to user interface. 

SHLWAPI.dll- Shell Light-weight Utility Library 

KERNEL32.dll- Windows NT BASE API Client 

USER32.dll- Multi-User Windows USER API Client Library 

  

Capa is a command line tool that analyzes the malware file to see the different TTPs associated to the malware file. This tool references the MITRE attack framework to be able to categorize the type of threat the malware presents. This malware showed it had anti-analysis, anti-vm, vm-detection, sandbox evasion and loading code capabilities.  

 