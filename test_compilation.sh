#!/bin/bash

echo "=== Teste de Compilação Cross-Platform ==="
echo

# Função para testar compilação
test_compilation() {
    local platform=$1
    local source_file=$2
    local output_file=$3
    local libs=$4
    
    echo "Testando compilação para $platform..."
    
    if g++ -std=c++11 -Wall -Wextra -o "$output_file" "$source_file" $libs 2>/dev/null; then
        echo "✅ $platform: Compilação bem-sucedida"
        if [ -f "$output_file" ]; then
            echo "   Executável criado: $output_file"
            rm -f "$output_file"  # Limpar após teste
        fi
        return 0
    else
        echo "❌ $platform: Falha na compilação"
        return 1
    fi
}

# Verificar se o arquivo fonte existe
if [ ! -f "client_cross_platform.cpp" ]; then
    echo "ERRO: Arquivo client_cross_platform.cpp não encontrado!"
    exit 1
fi

# Verificar se g++ está disponível
if ! command -v g++ &> /dev/null; then
    echo "ERRO: g++ não encontrado. Instale o compilador C++."
    exit 1
fi

echo "Arquivo fonte encontrado: client_cross_platform.cpp"
echo "Compilador encontrado: $(g++ --version | head -n1)"
echo

# Testar diferentes configurações
success_count=0
total_tests=0

# Teste 1: Compilação básica (sem bibliotecas específicas)
total_tests=$((total_tests + 1))
if test_compilation "Básico" "client_cross_platform.cpp" "test_basic" ""; then
    success_count=$((success_count + 1))
fi

# Teste 2: Compilação com OpenSSL (Linux/macOS)
total_tests=$((total_tests + 1))
if test_compilation "Linux/macOS" "client_cross_platform.cpp" "test_unix" "-lcrypto"; then
    success_count=$((success_count + 1))
fi

# Teste 3: Compilação com Winsock (Windows - se disponível)
total_tests=$((total_tests + 1))
if test_compilation "Windows" "client_cross_platform.cpp" "test_windows.exe" "-lws2_32 -lcrypto"; then
    success_count=$((success_count + 1))
fi

echo
echo "=== Resultados ==="
echo "Testes bem-sucedidos: $success_count/$total_tests"

if [ $success_count -eq $total_tests ]; then
    echo "🎉 Todos os testes passaram! O código é cross-platform."
elif [ $success_count -gt 0 ]; then
    echo "⚠️  Alguns testes falharam. Verifique as dependências."
else
    echo "❌ Todos os testes falharam. Verifique o código e dependências."
fi

echo
echo "Para compilar para seu sistema específico:"
echo "  Linux:   g++ -std=c++11 -o client client_cross_platform.cpp -lcrypto"
echo "  macOS:   g++ -std=c++11 -o client client_cross_platform.cpp -lcrypto"
echo "  Windows: g++ -std=c++11 -o client.exe client_cross_platform.cpp -lws2_32 -lcrypto"

