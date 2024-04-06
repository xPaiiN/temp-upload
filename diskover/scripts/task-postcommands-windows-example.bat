@echo off
::
:: diskover-web task panel index task post-crawl script example for Windows
::
:: Usage:
:: Post-Crawl Command input: cmd.exe
:: Post-Crawl Command Args input: /c ".\scripts\task-postcommands-windows-example.bat" {indexname}
::

:: exit if there are no args
if [%1]==[] goto usage

@echo Starting task post commands...

:: get index name from arg 1
:: arg 1 is {indexname} in diskover-web index task post-crawl command args
set INDEXNAME=%1

:: run diskover tag copier
python ".\plugins_postindex\diskover-tagcopier.py" -a -v %INDEXNAME%
:: exit if error
if %errorlevel% neq 0 goto error

:: run diskover es field copier
::python ".\plugins_postindex\diskover-esfieldcopier.py" -a -v %INDEXNAME%
:: exit if error
::if %errorlevel% neq 0 goto error

:: run diskover dupes finder
::python ".\plugins_postindex\diskover-dupesfinder.py" -u %INDEXNAME%
:: exit if error
::if %errorlevel% neq 0 goto error

:: run diskover illegalfilename
::python ".\plugins_postindex\diskover-illegalfilename.py" %INDEXNAME%
:: exit if error
::if %errorlevel% neq 0 goto error

@echo Finished running task post commands.
goto :eof

:usage
@echo No index argument supplied
exit /b 1

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
