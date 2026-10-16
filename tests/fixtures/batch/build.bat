@echo off
REM Build the harbour tools
:: second comment style
set OUT=dist
call scripts\clean.bat
:build
echo Building to %OUT%
goto :eof
