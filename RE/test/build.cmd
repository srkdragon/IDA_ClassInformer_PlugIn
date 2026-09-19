@echo off
REM Build the RTTI corpus for x86 and x64 with VS2026 (MSVC 14.51)
setlocal
cd /d "%~dp0"
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x86 >nul
cl /nologo /O2 /EHsc /Zi /GR /W4 /Fertti_corpus_x86.exe rtti_corpus.cpp /link /MAP:rtti_corpus_x86.map
@endlocal

setlocal
cd /d "%~dp0"
set "PATH=C:\Program Files (x86)\Microsoft Visual Studio\Installer;%PATH%"
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul
cl /nologo /O2 /EHsc /Zi /GR /W4 /Fertti_corpus_x64.exe rtti_corpus.cpp /link /MAP:rtti_corpus_x64.map
@endlocal
