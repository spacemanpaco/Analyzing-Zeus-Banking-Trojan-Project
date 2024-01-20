Basic Dynamic Analysis 

After ensuring safety, the malware was detonated in the sandbox. It created an administrator prompt for permission to download Adobe Flash Player. The executable seemed to disappear after the download was complete. Referencing process monitor shows the User's temp directory being used to drop a DLL [msimg32.dll] and the executable [InstallFlashPlayer.exe]. The DLL and EXE were not identified in any of the previous static analysis that was completed.  


The executable is interacting with the registry as well. It is setting values in the SOFTWARE registry such as ProxyBypass and running Google Update. Creating Registry values allows persistence for the malware, evading detection and even disabling security features.  

 
The DLL and EXE found in the User’s Temp directory were uploaded to VirusTotal and the DLL was found to be malicious and associated with Trojan malware. The DLL [msimg32.dll] is used as Graphical Device Interface, a tool Windows uses for drawing lines, boxes, texts and other basic elements for user interface. The malware attempts to hijack this seemingly harmless DLL to host its malware in. The EXE [InstallFlashPlayer.exe] seems to be a legitimate download, with no real security concerns. The EXE [invoice_2318362983713_823931342io.pdf.exe] is run, and the malicious DLL is sideloaded for hijacking the victim machine. 
 

Network traffic was analyzed with WireShark and showed HTTP GET request being made to a site name fpdownload[.]macromedia[.]com with the request /get/flashplayer/update/current/install/install_all_win_cab_64_ax_sgn.z.  

The site shows a legitimate Adobe help page. VirusTotal also shows the URL being flagged as malicious by only one vendor. It seems that the bad actor is using a legitimate website page to host their malware, as a means of evading detection of their malware hosting server.  

 