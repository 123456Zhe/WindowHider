@echo off
chcp 65001 >nul
title 正在编译 窗口隐身器...

set CSC=
if exist "%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" set CSC="%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not defined CSC if exist "%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe" set CSC="%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"

if not defined CSC (
    echo [错误] 没找到 Windows 自带的 C# 编译器
    echo 请确认是 Windows 7 / 10 / 11 系统
    pause
    exit /b 1
)

echo 找到编译器: %CSC%
echo.
% CSC% /nologo /t:winexe /optimize+ /r:System.Windows.Forms.dll /r:System.Drawing.dll /out:WindowHider.exe WindowHider.cs

if errorlevel 1 (
    echo.
    echo [错误] 编译失败
    pause
    exit /b 1
)

echo.
echo ============================================
echo  编译成功！生成了 WindowHider.exe
echo  双击运行即可，无需安装
echo ============================================
pause
