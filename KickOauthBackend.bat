@echo off
:: This ensures the command runs in the folder where the .bat file is saved
cd /d "%~dp0"

echo Launching application with npm start...
echo.

call npm start

:: If the app stops or crashes, this keeps the window open so you can see why
echo.
echo Application has stopped.
pause