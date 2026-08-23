@echo off
chcp 65001 >nul
rem AegisIR 启动器：无参数时打开桌面窗口，带参数时透传给命令行
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] 请以管理员身份运行（右键 -^> 以管理员身份运行）
    echo     探测与隔离功能需要管理员权限
    pause
    exit /b 1
)
if "%~1"=="" (
    python "%~dp0run.py" app
) else (
    python "%~dp0run.py" %*
)
if errorlevel 1 pause
