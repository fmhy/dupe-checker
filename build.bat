:: Build script for compiled exe using nuitka

@prompt Executing:  
python -m nuitka --standalone --onefile --remove-output --assume-yes-for-downloads --disable-console --clean-cache=all --enable-plugin=pyqt5 --include-data-files=MainWindow.ui=MainWindow.ui --include-data-dir=assets=assets "--windows-icon-from-ico=%~dp0assets\icon.ico" FmhyChecker.pyw

@echo off
if %errorlevel%==0 (
    echo.Complete&color 0a
) else (
    echo.Failed with error code %errorlevel%&color 04
)

echo.====================
pause >nul