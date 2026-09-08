@echo off
setlocal DisableDelayedExpansion
cd /d "%~dp0"
if errorlevel 1 goto :folder_error
if not exist "start.py" goto :missing_start

rem Enumerate installed versions instead of trusting the default py -3.
rem Both the legacy launcher and Python install manager support py -0p.
set "MASTERMONK_PY_COMMAND="
for /f "tokens=1" %%V in ('py -0p 2^>nul') do (
  call :try_registered_python "%%V"
  if errorlevel 0 if not errorlevel 1 goto :python_ready
)

rem Also support Python installations on PATH without a registered launcher.
for /f "delims=" %%P in ('where python.exe 2^>nul') do (
  call :try_python_exe "%%P"
  if errorlevel 0 if not errorlevel 1 goto :python_ready
)
goto :python_missing

:python_ready
echo Using:
%MASTERMONK_PY_COMMAND% -E -c "import sys; print(sys.executable); print('Python ' + sys.version.split()[0])"
if not "%errorlevel%"=="0" goto :python_missing
if /i "%~1"=="--check-python" exit /b 0

echo.
echo Starting MasterMonk. Default address: http://127.0.0.1:8787
echo Open the address printed by the server in your browser.
echo Keep this window open for real-source updates. Press Ctrl+C to stop.
echo.
%MASTERMONK_PY_COMMAND% -E start.py %*
set "MASTERMONK_EXIT_CODE=%errorlevel%"
if "%MASTERMONK_EXIT_CODE%"=="0" exit /b 0
echo.
echo MasterMonk stopped with an error. Read the message above.
echo If the port is already in use, close the other MasterMonk process first.
if "%~1"=="" pause
exit /b %MASTERMONK_EXIT_CODE%

:folder_error
echo ERROR: The MasterMonk folder could not be opened.
goto :failed

:missing_start
echo ERROR: start.py was not found beside this launcher.
echo Extract the project first, then place START_WINDOWS.bat beside start.py.
goto :failed

:python_missing
echo ERROR: No working Python 3.11 or newer was found.
echo Registered installations and python.exe commands on PATH were checked.
echo Install or repair Python: https://www.python.org/downloads/windows/
echo To list registered installations, run py -0p in Command Prompt.
echo This launcher does not change your system Python settings.

:failed
if "%~1"=="" pause
exit /b 1

:try_registered_python
set "MASTERMONK_SELECTOR=%~1"
rem Ignore informational headings, which do not start with a selector dash.
if not "%MASTERMONK_SELECTOR:~0,1%"=="-" exit /b 1
py "%MASTERMONK_SELECTOR%" -E -c "import sys, encodings, sqlite3, ssl; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not "%errorlevel%"=="0" exit /b 1
set "MASTERMONK_PY_COMMAND=py "%MASTERMONK_SELECTOR%""
exit /b 0

:try_python_exe
"%~1" -E -c "import sys, encodings, sqlite3, ssl; sys.exit(sys.version_info < (3, 11))" >nul 2>&1
if not "%errorlevel%"=="0" exit /b 1
set "MASTERMONK_PY_COMMAND="%~1""
exit /b 0
