@echo off
title RedScan Pro - Build
echo.
echo  ================================================
echo   RedScan Pro - Advanced Security Scanner
echo   Building EXE...
echo  ================================================
echo.

echo [1/3] Installing dependencies...
pip install -q customtkinter requests urllib3 Pillow pyinstaller paramiko cryptography
echo      Done.
echo.

echo [2/3] Building EXE...
pyinstaller ^
    --onefile ^
    --windowed ^
    --name "RedScan-Pro" ^
    --icon "sb.ico" ^
    --add-data "sb.ico;." ^
    --collect-all customtkinter ^
    --hidden-import customtkinter ^
    --hidden-import PIL ^
    --hidden-import requests ^
    --hidden-import urllib3 ^
    --hidden-import smtplib ^
    --hidden-import email ^
    --hidden-import email.mime.text ^
    --hidden-import email.mime.multipart ^
    --hidden-import socket ^
    --hidden-import ftplib ^
    --hidden-import json ^
    --hidden-import re ^
    --hidden-import base64 ^
    --hidden-import paramiko ^
    --hidden-import paramiko.transport ^
    --hidden-import paramiko.auth_handler ^
    --collect-all paramiko ^
    --hidden-import bgp_pool ^
    --hidden-import telegram_notifier ^
    --hidden-import ipaddress ^
    sb_scanner.py

echo.
echo [3/3] Done!
echo.
echo  EXE  :  dist\RedScan-Pro.exe
echo  Note :  Results save in a "results" folder next to the EXE.
echo.
pause
