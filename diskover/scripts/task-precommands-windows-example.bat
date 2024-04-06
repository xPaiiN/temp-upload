@echo off
::
:: diskover-web task panel index task pre-crawl script example for Windows
::
:: Usage:
:: Post-Crawl Command input: cmd.exe
:: Post-Crawl Command Args input: /c ".\scripts\task-precommands-windows-example.bat"
::

@echo Starting task pre commands...

:: mount unc paths to drive letter
@echo Mapping unc paths to drive letters...

net use Z: "\\WinServer\ShareFiles" password /user:domainname\username /persistent:yes
:: exit if error
if %errorlevel% neq 0 goto error

@echo Finished mapping unc paths.

@echo Finished running task pre commands.
goto :eof

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
