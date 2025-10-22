@echo off
echo Compilando Cliente RDT 4.0 para Windows...
echo.

REM Verificar se o g++ está disponível
g++ --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERRO: g++ nao encontrado. Instale o MinGW-w64 ou MSYS2.
    echo.
    echo Instrucoes de instalacao:
    echo 1. Baixe o MSYS2 de https://www.msys2.org/
    echo 2. Instale o pacote mingw-w64-x86_64-gcc
    echo 3. Adicione o diretorio bin do MSYS2 ao PATH
    pause
    exit /b 1
)

REM Verificar se a biblioteca OpenSSL está disponível
echo Verificando dependencias...
g++ -lws2_32 -lcrypto -v 2>&1 | findstr "crypto" >nul
if %errorlevel% neq 0 (
    echo AVISO: Biblioteca OpenSSL pode nao estar disponivel.
    echo Certifique-se de que o OpenSSL esta instalado.
    echo.
)

REM Compilar o cliente
echo Compilando...
g++ -std=c++11 -Wall -Wextra -o client.exe client_cross_platform.cpp -lws2_32 -lcrypto

if %errorlevel% equ 0 (
    echo.
    echo Compilacao bem-sucedida!
    echo Executavel criado: client.exe
    echo.
    echo Para executar: client.exe
) else (
    echo.
    echo ERRO na compilacao!
    echo Verifique se todas as dependencias estao instaladas.
)

echo.
pause

