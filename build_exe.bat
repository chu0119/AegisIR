@echo off
chcp 65001 >nul
rem 一键构建全部产物：dist\AegisIR.exe（Windows 桌面软件）+ dist\aegis-node.pyz（跨平台节点包）
pip show pyinstaller >nul 2>&1 || pip install pyinstaller pywebview

echo === 构建跨平台节点包 aegis-node.pyz ===
python build_node.py || goto :err

echo === 构建单文件 AegisIR.exe（UAC 自动提权） ===
pyinstaller -y -F --uac-admin --name AegisIR ^
  --version-file version_file.txt ^
  --collect-all scapy ^
  --collect-all webview ^
  --collect-all clr_loader ^
  --add-data "aegis_ir\web;aegis_ir\web" ^
  run.py || goto :err

echo.
echo 构建完成:
echo   dist\AegisIR.exe      Windows 桌面软件（目标机需 Npcap）
echo   dist\aegis-node.pyz   跨平台节点包（Linux/macOS/Windows，仅需 python3）
pause
exit /b 0
:err
echo 构建失败，请检查上方报错
pause
exit /b 1
