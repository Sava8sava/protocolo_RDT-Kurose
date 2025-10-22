# Cliente RDT 4.0 - Versão Cross-Platform

Este é uma versão portada do cliente RDT 4.0 que funciona em múltiplos sistemas operacionais: Windows, Linux e macOS.

## Arquivos

- `client_cross_platform.cpp` - Código fonte cross-platform
- `client.cpp` - Código original (apenas Windows)
- `Makefile` - Compilação automática para diferentes sistemas
- `compile_windows.bat` - Script de compilação para Windows
- `compile_linux.sh` - Script de compilação para Linux
- `compile_macos.sh` - Script de compilação para macOS

## Dependências

### Windows
- **MinGW-w64** ou **MSYS2** com g++
- **OpenSSL** (libcrypto)

### Linux
- **g++** (GNU Compiler Collection)
- **OpenSSL** (libssl-dev)

### macOS
- **Xcode Command Line Tools** ou **Homebrew** com g++
- **OpenSSL**

## Instalação de Dependências

### Windows

#### Opção 1: MSYS2 (Recomendado)
1. Baixe o MSYS2 de https://www.msys2.org/
2. Instale e abra o terminal MSYS2
3. Execute:
   ```bash
   pacman -S mingw-w64-x86_64-gcc
   pacman -S mingw-w64-x86_64-openssl
   ```
4. Adicione `C:\msys64\mingw64\bin` ao PATH do Windows

#### Opção 2: MinGW-w64
1. Baixe o MinGW-w64 de https://www.mingw-w64.org/
2. Instale o OpenSSL para Windows
3. Adicione os diretórios bin ao PATH

### Linux

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install g++ libssl-dev
```

#### CentOS/RHEL
```bash
sudo yum install gcc-c++ openssl-devel
```

#### Fedora
```bash
sudo dnf install gcc-c++ openssl-devel
```

### macOS

#### Via Xcode Command Line Tools
```bash
xcode-select --install
```

#### Via Homebrew
```bash
# Instalar Homebrew se não tiver
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Instalar dependências
brew install gcc openssl
brew link openssl --force
```

## Compilação

### Método 1: Makefile (Recomendado)
```bash
# Compilação automática para o sistema atual
make

# Compilação específica por sistema
make windows
make linux
make macos

# Limpeza
make clean

# Ajuda
make help
```

### Método 2: Scripts de Compilação

#### Windows
```cmd
compile_windows.bat
```

#### Linux
```bash
chmod +x compile_linux.sh
./compile_linux.sh
```

#### macOS
```bash
chmod +x compile_macos.sh
./compile_macos.sh
```

### Método 3: Compilação Manual

#### Windows
```cmd
g++ -std=c++11 -Wall -Wextra -o client.exe client_cross_platform.cpp -lws2_32 -lcrypto
```

#### Linux
```bash
g++ -std=c++11 -Wall -Wextra -o client_linux client_cross_platform.cpp -lcrypto
```

#### macOS
```bash
g++ -std=c++11 -Wall -Wextra -o client_macos client_cross_platform.cpp -lcrypto
```

## Execução

### Windows
```cmd
client.exe
```

### Linux
```bash
./client_linux
```

### macOS
```bash
./client_macos
```

## Principais Mudanças para Cross-Platform

### 1. Detecção de Plataforma
```cpp
#ifdef _WIN32
    // Código específico do Windows
#else
    // Código para Unix-like (Linux/macOS)
#endif
```

### 2. Sockets
- **Windows**: Winsock2 (`winsock2.h`, `Ws2tcpip.h`)
- **Unix-like**: Berkeley Sockets (`sys/socket.h`, `netinet/in.h`)

### 3. Tipos de Socket
- **Windows**: `SOCKET`
- **Unix-like**: `int`

### 4. Funções de Erro
- **Windows**: `WSAGetLastError()`
- **Unix-like**: `errno`

### 5. Fechamento de Socket
- **Windows**: `closesocket()`
- **Unix-like**: `close()`

### 6. Inicialização de Rede
- **Windows**: `WSAStartup()` / `WSACleanup()`
- **Unix-like**: Não necessário

## Solução de Problemas

### Erro: "g++ não encontrado"
- **Windows**: Instale MinGW-w64 ou MSYS2
- **Linux**: `sudo apt-get install g++` (Ubuntu/Debian)
- **macOS**: `xcode-select --install`

### Erro: "libcrypto não encontrada"
- **Windows**: Instale OpenSSL para Windows
- **Linux**: `sudo apt-get install libssl-dev`
- **macOS**: `brew install openssl`

### Erro de Compilação no macOS
Se encontrar problemas com OpenSSL no macOS:
```bash
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
g++ -std=c++11 -Wall -Wextra -o client_macos client_cross_platform.cpp -lcrypto
```

### Problemas de Permissão (Linux/macOS)
```bash
chmod +x client_linux
chmod +x client_macos
```

## Testando a Compatibilidade

Para verificar se a compilação foi bem-sucedida:

1. **Compile** o código usando um dos métodos acima
2. **Execute** o programa
3. **Verifique** se ele solicita a porta do cliente
4. **Teste** a conexão com um servidor

## Diferenças do Código Original

- ✅ Suporte a Windows, Linux e macOS
- ✅ Detecção automática de plataforma
- ✅ Compilação com Makefile
- ✅ Scripts de compilação para cada sistema
- ✅ Documentação completa
- ✅ Tratamento de erros cross-platform
- ✅ Mantém toda a funcionalidade original

## Licença

Este código mantém a mesma licença do projeto original.

