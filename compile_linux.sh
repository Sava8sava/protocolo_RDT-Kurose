#!/bin/bash

echo "Compilando Cliente RDT 4.0 para Linux..."
echo

# Verificar se o g++ está disponível
if ! command -v g++ &> /dev/null; then
    echo "ERRO: g++ não encontrado. Instale o g++:"
    echo "  Ubuntu/Debian: sudo apt-get install g++"
    echo "  CentOS/RHEL:   sudo yum install gcc-c++"
    echo "  Fedora:        sudo dnf install gcc-c++"
    exit 1
fi

# Verificar se a biblioteca OpenSSL está disponível
echo "Verificando dependências..."
if ! pkg-config --exists openssl; then
    echo "AVISO: OpenSSL pode não estar instalado."
    echo "Instale com:"
    echo "  Ubuntu/Debian: sudo apt-get install libssl-dev"
    echo "  CentOS/RHEL:   sudo yum install openssl-devel"
    echo "  Fedora:        sudo dnf install openssl-devel"
    echo
fi

# Compilar o cliente
echo "Compilando..."
g++ -std=c++11 -Wall -Wextra -o client_linux client_cross_platform.cpp -lcrypto

if [ $? -eq 0 ]; then
    echo
    echo "Compilação bem-sucedida!"
    echo "Executável criado: client_linux"
    echo
    echo "Para executar: ./client_linux"
    echo "Para dar permissão de execução: chmod +x client_linux"
else
    echo
    echo "ERRO na compilação!"
    echo "Verifique se todas as dependências estão instaladas."
    exit 1
fi

echo

