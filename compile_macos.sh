#!/bin/bash

echo "Compilando Cliente RDT 4.0 para macOS..."
echo

# Verificar se o g++ está disponível
if ! command -v g++ &> /dev/null; then
    echo "ERRO: g++ não encontrado."
    echo "Instale o Xcode Command Line Tools:"
    echo "  xcode-select --install"
    echo
    echo "Ou instale via Homebrew:"
    echo "  brew install gcc"
    exit 1
fi

# Verificar se a biblioteca OpenSSL está disponível
echo "Verificando dependências..."
if ! pkg-config --exists openssl; then
    echo "AVISO: OpenSSL pode não estar instalado."
    echo "Instale com Homebrew:"
    echo "  brew install openssl"
    echo "  brew link openssl --force"
    echo
fi

# Compilar o cliente
echo "Compilando..."
g++ -std=c++11 -Wall -Wextra -o client_macos client_cross_platform.cpp -lcrypto

if [ $? -eq 0 ]; then
    echo
    echo "Compilação bem-sucedida!"
    echo "Executável criado: client_macos"
    echo
    echo "Para executar: ./client_macos"
    echo "Para dar permissão de execução: chmod +x client_macos"
else
    echo
    echo "ERRO na compilação!"
    echo "Verifique se todas as dependências estão instaladas."
    exit 1
fi

echo

