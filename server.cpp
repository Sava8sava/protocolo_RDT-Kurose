#include <stdio.h>

#ifdef _WIN32
#include <winsock2.h>
#include <Ws2tcpip.h>
#define SOCKET_TYPE SOCKET
#define CLOSE_SOCKET(s) closesocket(s)
#define GET_LAST_ERROR() WSAGetLastError()
#define SOCKET_ERR SOCKET_ERROR
#define SOCKADDR struct sockaddr
#define SOCKADDR_IN struct sockaddr_in
#pragma comment(lib, "Ws2_32.lib")

#else // outro sistema OP
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>

#define SOCKET_TYPE int 
#define CLOSE_SOCKET(s) close(s)
#define GET_LAST_ERROR() errno 
#define SOCKET_ERR -1 
#define SOCKADDR struct sockaddr
#define SOCKADDR_IN struct sockaddr_in

// Definir um valor para NO_ERROR e NO_ERROR para simular a Winsock
#define NO_ERROR 0
// Não precisa do WSAGetLastError() ou WSACleanup() no Linux
#endif


int main()
{
    int res = 0;
#ifdef _WIN32
    WSADATA wsaData;
    res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        wprintf(L"Erro ao iniciar WinSock\n");
        return 1;
    }
#endif

    SOCKET_TYPE Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Sapi == (SOCKET_TYPE)SOCKET_ERR) { // Verifica a criação do socket
        printf("Erro ao criar socket: %d\n", GET_LAST_ERROR());
        return 1;
    }

    SOCKADDR_IN addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(12345);
    #ifdef _WIN32
    addr.sin_addr.s_addr = INADDR_ANY;
    #else
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    #endif

    res = bind(Sapi,(SOCKADDR *) &addr, sizeof(addr));
    if (res == SOCKET_ERR)
    {
        printf(": Ligacao do socket falhou com erro%u\n", GET_LAST_ERROR());
        //wprintf(L": Ligacao do socket falhou com erro%u\n", WSAGetLastError());
        CLOSE_SOCKET(Sapi);
        #ifdef _WIN32 
        WSACleanup();
        #endif
        return 1;
    }
    else
    {  
      printf("Ligacao finalizada com sucesso\n");
      //wprintf("Ligacao finalizada com sucesso\n");
    }

    SOCKADDR_IN sendback;
    #ifdef _WIN32 
    int sendbackSize = sizeof(sendback);
    #else
    socklen_t sendbackSize = sizeof(sendback);
    #endif
    
    int bufferlen = 1024;
    char buffer[bufferlen];

    printf("Recebendo datagramas...\n");
    res = recvfrom(Sapi, buffer, bufferlen, 0, (SOCKADDR *) &sendback, &sendbackSize);

    if (res == SOCKET_ERR)
    {
        printf("Recvfrom falhou com erro %d\n", GET_LAST_ERROR());
        //wprintf(L"Recvfrom falhou com erro %d\n", WSAGetLastError());
    }
    else if (res > 0)
    {
        
        printf("Mensagem recebida de %s:%d: ",
               inet_ntoa(sendback.sin_addr), // função para converter IP p/ string
               ntohs(sendback.sin_port));    // função para converter porta p/ host
        for (int i = 0; i < res; i++)
        {
            printf("%c", buffer[i]);
        }
        printf("\n");
    }
 
    printf("Fim do recebimento. Fechando socket\n");
    res = CLOSE_SOCKET(Sapi);

    if (res == SOCKET_ERR) {
        printf("Fechamento falhou com erro %d\n", GET_LAST_ERROR());
        return 1;
    }

    #ifdef _WIN32
    printf("Saindo.\n");
    WSACleanup(); // Limpeza final (Só no Windows)
    #endif

    return 0;
    }
