# Makefile para compilação cross-platform do cliente RDT 4.0
# Suporta Windows (MinGW), Linux e macOS

# Detectar o sistema operacional
UNAME_S := $(shell uname -s)

# Configurações específicas por plataforma
ifeq ($(UNAME_S),Linux)
    CC = g++
    CFLAGS = -std=c++11 -Wall -Wextra
    LIBS = -lcrypto
    TARGET = client_linux
    PLATFORM = Linux
endif

ifeq ($(UNAME_S),Darwin)
    CC = g++
    CFLAGS = -std=c++11 -Wall -Wextra
    LIBS = -lcrypto
    TARGET = client_macos
    PLATFORM = macOS
endif

# Windows (MinGW)
ifeq ($(OS),Windows_NT)
    CC = g++
    CFLAGS = -std=c++11 -Wall -Wextra
    LIBS = -lws2_32 -lcrypto
    TARGET = client.exe
    PLATFORM = Windows
endif

# Fallback para outros sistemas Unix-like
ifndef PLATFORM
    CC = g++
    CFLAGS = -std=c++11 -Wall -Wextra
    LIBS = -lcrypto
    TARGET = client_unix
    PLATFORM = Unix
endif

# Arquivo fonte
SOURCE = client_cross_platform.cpp

# Regra principal
all: $(TARGET)

$(TARGET): $(SOURCE)
	@echo "Compilando para $(PLATFORM)..."
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LIBS)
	@echo "Compilação concluída: $(TARGET)"

# Regra para Windows específica
windows: client_cross_platform.cpp
	@echo "Compilando para Windows..."
	g++ -std=c++11 -Wall -Wextra -o client.exe client_cross_platform.cpp -lws2_32 -lcrypto
	@echo "Compilação concluída: client.exe"

# Regra para Linux
linux: client_cross_platform.cpp
	@echo "Compilando para Linux..."
	g++ -std=c++11 -Wall -Wextra -o client_linux client_cross_platform.cpp -lcrypto
	@echo "Compilação concluída: client_linux"

# Regra para macOS
macos: client_cross_platform.cpp
	@echo "Compilando para macOS..."
	g++ -std=c++11 -Wall -Wextra -o client_macos client_cross_platform.cpp -lcrypto
	@echo "Compilação concluída: client_macos"

# Limpeza
clean:
	@echo "Removendo arquivos compilados..."
	rm -f client.exe client_linux client_macos client_unix
	@echo "Limpeza concluída."

# Instruções de uso
help:
	@echo "Makefile para Cliente RDT 4.0 Cross-Platform"
	@echo ""
	@echo "Comandos disponíveis:"
	@echo "  make          - Compila automaticamente para o sistema atual"
	@echo "  make windows  - Compila especificamente para Windows"
	@echo "  make linux    - Compila especificamente para Linux"
	@echo "  make macos    - Compila especificamente para macOS"
	@echo "  make clean    - Remove arquivos compilados"
	@echo "  make help     - Mostra esta ajuda"
	@echo ""
	@echo "Sistema detectado: $(PLATFORM)"
	@echo "Target: $(TARGET)"

# Regra padrão
.PHONY: all windows linux macos clean help

