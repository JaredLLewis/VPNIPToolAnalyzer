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
