# VPNIPToolAnalyzer
A tool for automatically analyzing IPs


Folder paths:
build - used for exe
combinedfiles - acts as input destination for combining files
inputfiles - acts as input destination for input files including blacklist files
lib - used for exe
reports - acts as output destination for all reports
savedata - acts as input/output for loading and saving respectively.

Instructions how to create exe via cx_Freeze:
1. open cmd
2. cd to path of folder ~/VPNIPTool/
3. type "py setup.py build"(assuming py is environment variable for python 36)
4. Done executing! To run, copy the files from /build/exe.win32-3.6/ to the VPNIPTool folder and run the main.exe application.

inputfile requires strict input:

ise-2017-08-01.gz:Aug  5 00:01:00 muise-psn01 CISE_RADIUS_Accounting 00000000 3 0 2015-08-01 00:03:55.200 -44:00 0000000 3002 NOTICE Radius: RADIUS Accounting watchdog update, ConfigVersionId=000, Device IP Address=000000, RequestLatency=0, NetworkDeviceName=0000, User-Name=mortalspirit, NAS-IP-Address=00000, NAS-Port=0000, Service-Type=0000, Framed-Protocol=0000, Framed-IP-Address=00.00.000, Class=CACS:###, Called-Station-ID=000.00.00.000, Calling-Station-ID=00.000.000.00, Acct-Status-Type=Interim-Update, Acct-Delay-Time=0, Acct-Input-Octets=0, Acct-Output-Octets=0, Acct-Session-Id=0, Acct-Authentic=0, Acct-Input-Packets=0, Acct-Output-Packets=0, NAS-Port-Type=0, Tunnel-Client-Endpoint=(tag=0) 00.000.000.00, cisco-av-pair=mdm-tlv=device-type=phone\,2, cisco-av-pair=mdm-tlv=device-platform=mac-intel, cisco-av-pair=mdm-tlv=device-mac=00-00-00-00,
