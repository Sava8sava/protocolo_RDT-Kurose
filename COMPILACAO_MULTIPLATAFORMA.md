# 🌍 Cliente RDT 4.0 - Compilação Multiplataforma

Este documento contém as instruções para compilar e executar o cliente RDT 4.0 em diferentes sistemas operacionais.

## 📋 Pré-requisitos

### Todos os Sistemas
- Compilador C++ com suporte a C++11 ou superior
- Biblioteca OpenSSL instalada

### Windows
- MinGW-w64 ou Visual Studio Build Tools
- OpenSSL para Windows (pode usar vcpkg ou chocolatey)

### Linux/Ubuntu/Debian
```bash
sudo apt update
sudo apt install build-essential libssl-dev
```

### macOS
```bash
# Instalar Homebrew se não tiver
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar dependências
brew install openssl
```

### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install gcc-c++ openssl-devel

# Fedora
sudo dnf install gcc-c++ openssl-devel
```

## 🔨 Compilação

### Windows (MinGW)
```cmd
g++ client_final.cpp -o client.exe -lws2_32 -lcrypto
```

### Windows (Visual Studio)
```cmd
cl client_final.cpp /link ws2_32.lib libcrypto.lib
```

### Linux/Unix
```bash
g++ client_final.cpp -o client -lcrypto
```

### macOS
```bash
# Se OpenSSL foi instalado via Homebrew
g++ client_final.cpp -o client -lcrypto -I/opt/homebrew/include -L/opt/homebrew/lib
```

## ▶️ Execução

### Windows
```cmd
client.exe
```

### Linux/Unix/macOS
```bash
./client
```

## 🛠️ Principais Modificações Realizadas

### 1. Detecção Automática de Sistema
- Uso de `#ifdef _WIN32` para detectar Windows
- Includes condicionais para diferentes plataformas

### 2. Abstração de Tipos
- `socket_t`: Unifica `SOCKET` (Windows) e `int` (Unix)
- `sockaddr_t`: Padroniza tipos de endereço de socket
- `socklen_t_compat`: Compatibilidade para tamanhos de socket

### 3. Funções Abstraídas
- `init_sockets()`: Inicializa Winsock no Windows, nada no Unix
- `cleanup_sockets()`: Limpa Winsock no Windows
- `CLOSE_SOCKET()`: Macro para `closesocket()` vs `close()`
- `GET_SOCKET_ERROR()`: Macro para `WSAGetLastError()` vs `errno`
- `set_socket_timeout()`: Configura timeout multiplataforma

### 4. Tratamento de Erro Unificado
- Constantes de erro padronizadas
- Mensagens de erro consistentes entre plataformas



## 🐛 Resolução de Problemas

### Erro de OpenSSL
```bash
# Ubuntu/Debian
sudo apt install libssl-dev

# CentOS/RHEL
sudo yum install openssl-devel
```

### Erro de Link no Windows
- Certifique-se que o compilador encontra `ws2_32.lib` e `libcrypto.lib`
- Use vcpkg para gerenciar dependências: `vcpkg install openssl`

### Permissões no Unix
```bash
# Se precisar de privilégios administrativos
sudo ./client
```

---


