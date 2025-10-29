/*
 * Cliente RDT 4.0 - Versão Multiplataforma
 * 
 * Compilação:
 * Windows: g++ client_final.cpp -o client.exe -lws2_32 -lcrypto
 * Linux/Unix: g++ client_final.cpp -o client -lcrypto
 */

#ifdef _WIN32
    #ifndef UNICODE
    #define UNICODE
    #endif
    #define WIN32_LEAN_AND_MEAN
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #pragma comment(lib, "Ws2_32.lib")
    #pragma comment(lib, "libcrypto.lib")
    typedef SOCKET socket_t;
    typedef SOCKADDR sockaddr_t;
    typedef int socklen_t_compat;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_SOCKET_ERROR() WSAGetLastError()
    #define SOCKET_WOULD_BLOCK WSAEWOULDBLOCK
    #define SOCKET_TIMEOUT_ERROR WSAETIMEDOUT
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    typedef int socket_t;
    typedef struct sockaddr sockaddr_t;
    typedef socklen_t socklen_t_compat;
    #define INVALID_SOCKET -1
    #define SOCKET_ERROR -1
    #define CLOSE_SOCKET(s) close(s)
    #define GET_SOCKET_ERROR() errno
    #define SOCKET_WOULD_BLOCK EWOULDBLOCK
    #define SOCKET_TIMEOUT_ERROR EAGAIN
#endif

#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <openssl/md5.h>
#include <openssl/evp.h>
#include <sstream>
#include <iomanip>
#include <thread>
#include <cstring>

const int N = 16;
const int TIMEOUT_MS = 40000; 
const int ATTEMPTS = 5;
const int HASH_LEN = 16;
const int RDT_HEADER_LEN = 14; // 1(seq) + 1(tipo) + 4(IP dest) + 2(porta dest) + 4(IP orig) + 2(porta orig)


void md5_raw(const char *data, size_t len, unsigned char out[MD5_DIGEST_LENGTH]) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned int md_len;
    md = EVP_get_digestbyname("MD5");
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, data, len);
    EVP_DigestFinal_ex(mdctx, out, &md_len);
    EVP_MD_CTX_free(mdctx);
}

bool isCorrupted(char datagram[], int size)
{
    if (size < HASH_LEN) return true;
    std::string message(datagram, size - HASH_LEN);
    unsigned char receivedHash[HASH_LEN];
    memcpy(receivedHash, datagram + size - HASH_LEN, HASH_LEN);
    unsigned char calculatedHash[HASH_LEN];
    md5_raw(message.c_str(), message.length(), calculatedHash);
    return memcmp(receivedHash, calculatedHash, HASH_LEN) != 0;
}

bool formDatagram(uint8_t *buf, size_t buf_len,
                             uint8_t seq, char type,
                             const char *dest_ip_str, uint16_t dest_port,
                             const char *src_ip_str, uint16_t src_port,
                             const uint8_t *payload, size_t payload_len,
                             size_t &total_len_out)
{
    const size_t data_len = RDT_HEADER_LEN + payload_len;
    const size_t total_len = data_len + HASH_LEN;
    if (buf_len < total_len) return false;
    size_t offset = 0;
    buf[offset++] = seq;
    buf[offset++] = static_cast<uint8_t>(type);
    in_addr dest_addr{};
    if (inet_pton(AF_INET, dest_ip_str, &dest_addr) != 1) return false;
    memcpy(buf + offset, &dest_addr.s_addr, 4);
    offset += 4;
    uint16_t dest_port_net = htons(dest_port);
    memcpy(buf + offset, &dest_port_net, 2);
    offset += 2;
    in_addr src_addr{};
    if (inet_pton(AF_INET, src_ip_str, &src_addr) != 1) return false;
    memcpy(buf + offset, &src_addr.s_addr, 4);
    offset += 4;
    uint16_t src_port_net = htons(src_port);
    memcpy(buf + offset, &src_port_net, 2);
    offset += 2;
    if (payload_len > 0 && payload != nullptr) {
        memcpy(buf + offset, payload, payload_len);
        offset += payload_len;
    }
    unsigned char digest[HASH_LEN];
    md5_raw((char*)buf, offset, digest);
    memcpy(buf + offset, digest, HASH_LEN);
    total_len_out = total_len;
    return true;
}

class TransmissionWindow{
    public:
    int expected;
    std::vector<std::string> appData;
    bool connected;
    bool finished; 

    TransmissionWindow() : expected(0), connected(false), finished(false) {}

    int receive(int seq, char tipo, std::string payload)
    {
        if (tipo == 'C')
        {
            if (!connected)
            {
                connected = true;
                expected = (seq + 1) % N;
                std::cout << "Pacote tipo 'C' recebido. Esperado agora: " << expected << std::endl;
                return expected;
            }
            else
            {
                std::cout << "'C' duplicado recebido. Reenviando ACK " << (seq + 1) % N << "..." << std::endl;
                return (seq + 1) % N; 
            }
        }
        else if (tipo == 'D' && connected && !finished)
        {
            if (seq == expected)
            {
                std::cout << "Seq=" << seq << " | Mensagem='" << payload << "'" << std::endl;
                appData.push_back(payload);
                expected = (expected + 1) % N;
                return expected;
            }
            else
            {
                std::cout << "Esperado=" << expected << ", Recebido=" << seq << ". Ignorado." << std::endl;
                return expected;
            }
        }

        else if (tipo == 'F' && connected)
        {
            std::cout << " Pacote tipo 'F' recebido. Enviando ACK." << std::endl;
            finished = true; 
            return (seq + 1) % N; 
        }

        return -1;
    }
};

// Função para inicializar sockets por plataforma
int init_sockets() {
#ifdef _WIN32
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        printf("Erro ao iniciar WinSock\n");
        return -1;
    }
#endif
    return 0;
}

// Função para limpar sockets por plataforma
void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

// Função para configurar timeout de socket multiplataforma
int set_socket_timeout(socket_t sockfd, int timeout_ms) {
#ifdef _WIN32
    DWORD timeout = timeout_ms;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
}

int main()
{
    if (init_sockets() != 0) {
        return 1;
    }

    int clientPort;
    std::cout << "=== CLIENTE RDT 4.0 ===" << std::endl;
    std::cout << "Porta do cliente: ";
    std::cin >> clientPort;

    socket_t Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Sapi == INVALID_SOCKET) {
        printf("Erro ao criar socket\n");
        cleanup_sockets();
        return 1;
    }

    char clientIP[INET_ADDRSTRLEN];
    sockaddr_in fake{};
    fake.sin_family = AF_INET;
    fake.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &fake.sin_addr);
    connect(Sapi, (sockaddr_t*)&fake, sizeof(fake));
    sockaddr_in local{};
    socklen_t_compat len = sizeof(local);
    getsockname(Sapi, (sockaddr_t*)&local, &len);
    inet_ntop(AF_INET, &local.sin_addr, clientIP, sizeof(clientIP));
    CLOSE_SOCKET(Sapi); 
    
    Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (Sapi == INVALID_SOCKET) {
        printf("Erro ao criar socket\n");
        cleanup_sockets();
        return 1;
    }
    
    sockaddr_in clientaddr;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(clientPort);
    inet_pton(AF_INET, clientIP, &clientaddr.sin_addr);

    int res = bind(Sapi, (sockaddr_t*)&clientaddr, sizeof(clientaddr));
    if (res == SOCKET_ERROR)
    {
        printf("Bind falhou com erro %d\n", GET_SOCKET_ERROR());
        CLOSE_SOCKET(Sapi);
        cleanup_sockets();
        return 1;
    }
    std::cout << "Socket vinculado em " << clientIP << ":" << clientPort << "\n" << std::endl;

    set_socket_timeout(Sapi, TIMEOUT_MS);

    std::string routerIP, destIP;
    int routerPort, destPort;
    
    std::cout << "IP da rede intermediaria (roteador): ";
    std::cin >> routerIP;
    std::cout << "Porta da rede intermediaria (roteador): ";
    std::cin >> routerPort;
    std::cout << "IP do servidor destino: ";
    std::cin >> destIP;
    std::cout << "Porta do servidor destino: ";
    std::cin >> destPort;

    sockaddr_in routerAddr{};
    routerAddr.sin_family = AF_INET;
    routerAddr.sin_port = htons(routerPort);
    inet_pton(AF_INET, routerIP.c_str(), &routerAddr.sin_addr);

    int seqIni;
    do
    {
        std::cout << "Numero de sequencia inicial (0–15): ";
        std::cin >> seqIni;
    } while(seqIni < 0 || seqIni > 15);


    int bufferlen = 2048;
    uint8_t buffer[bufferlen];
    sockaddr_in sendback;
    int sendbackSize = sizeof(sendback);
    
    TransmissionWindow window;
    
    std::cout << "\nEnviando pacote de conexão tipo 'C'..." << std::endl;
    uint8_t conn_packet[1024]; 
    size_t conn_packet_len;
    if (!formDatagram(conn_packet, 1024, seqIni, 'C', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, conn_packet_len))
    {
        perror("Nao foi possivel formar o segmento de conexao");
        return 0;
    }

    for (int attempt = 0; attempt < ATTEMPTS; attempt++)
    {
        sendto(Sapi, (const char*)conn_packet, conn_packet_len, 0, (sockaddr_t*)&routerAddr, sizeof(routerAddr));
        std::cout << "Tentativa " << attempt + 1 << ": aguardando resposta do servidor..." << std::endl;

        int bytes = recvfrom(Sapi, (char *)buffer, bufferlen - 1, 0, (sockaddr_t*)&sendback, (socklen_t_compat*)&sendbackSize);

        if (bytes < 0) {
            if (GET_SOCKET_ERROR() == SOCKET_TIMEOUT_ERROR) {
                std::cout << "Timeout." << std::endl;
                if (attempt < ATTEMPTS - 1) { 
                     std::cout << "Aguardando 10 segundos antes de tentar novamente..." << std::endl;
                     std::this_thread::sleep_for(std::chrono::seconds(10));
                     std::cout << "Reenviando pacote de conexao.\n" << std::endl;
                }
                continue;
            } else {
                perror("recvfrom error no handshake");
                break;
            }
        }

        if (isCorrupted((char*)buffer, bytes)) {
            std::cout << "Pacote corrompido ou invalido. Ignorado.\n" << std::endl;
            continue;
        }

        uint8_t seq = buffer[0];
        char type = (char)buffer[1];
        int next_ack = window.receive(seq, type, "");
            
        if (next_ack != -1) {
            size_t ack_len;
            formDatagram(buffer, bufferlen, next_ack, 'A', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, ack_len);
            sendto(Sapi, (const char*)buffer, ack_len, 0, (sockaddr_t*)&routerAddr, sizeof(routerAddr));
            if (window.connected) {
                std::cout << " Enviado ACK " << next_ack << ". Conexao estabelecida!\n" << std::endl;
                break; 
            }
        }
    }

    if (!window.connected)
    {
        std::cout << "Nao foi possivel estabelecer conexao apos multiplas tentativas." << std::endl;
        CLOSE_SOCKET(Sapi);
        cleanup_sockets();
        return 0;
    }
    std::cout << "Aguardando pacotes de dados...\n" << std::endl;

    while (!window.finished)
    {
        res = recvfrom(Sapi, (char *)buffer, bufferlen, 0, (sockaddr_t*)&sendback, (socklen_t_compat*)&sendbackSize);

        if (res == SOCKET_ERROR)
        {
            if (GET_SOCKET_ERROR() == SOCKET_TIMEOUT_ERROR) {
                std::cout << "Esperando pacote" << std::endl;
                continue;
            } else {
                printf("Recvfrom falhou com erro %d\n", GET_SOCKET_ERROR());
                break;
            }
        }

        if (isCorrupted((char*)buffer, res))
        {
            printf("Pacote corrompido. Descartando\n");
            continue;
        }

        uint8_t seq = buffer[0];
        char type = (char)buffer[1];
        int payload_len = res - RDT_HEADER_LEN - HASH_LEN;
        std::string payload = "";
        if (payload_len > 0) {
            payload = std::string((char*)buffer + RDT_HEADER_LEN, payload_len);
        }

        int action = window.receive(seq, type, payload);

        if (action != -1) 
        {
            size_t ack_len;
            formDatagram(buffer, bufferlen, action, 'A', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, ack_len);
            int sent = sendto(Sapi, (const char *)buffer, ack_len, 0, (sockaddr_t*)&routerAddr, sizeof(routerAddr));

            if (sent < 0)
            {
                perror("Erro ao enviar ACK");
                break;
            } 
            std::cout << "[ACK] " << action << " enviado.\n" << std::endl;
        }
    }
    std::cout << "\nConexao encerrada pelo servidor. Entrando em espera por "
              << (TIMEOUT_MS * 2) / 1000.0 << " seg." << std::endl;
    set_socket_timeout(Sapi, TIMEOUT_MS * 2);
    res = recvfrom(Sapi, (char *)buffer, bufferlen, 0, (sockaddr_t*)&sendback, (socklen_t_compat*)&sendbackSize);

    if (res == SOCKET_ERROR)
    {
        if (GET_SOCKET_ERROR() == SOCKET_TIMEOUT_ERROR) {
            std::cout << "Tempo esgotado. Fechando" << std::endl;
        } else {
            printf("recvfrom falhou com erro %d\n", GET_SOCKET_ERROR());
        }
    }
    else if (res > 0)
    {
        if (!isCorrupted((char*)buffer, res))
        {
            uint8_t seq = buffer[0];
            char type = (char)buffer[1];

            if (type == 'F') {
                std::cout << "Pacote tipo F duplicado recebido. Reenviando ACK final..." << std::endl;
                
                int action = (seq + 1) % N;
                size_t ack_len;
                formDatagram(buffer, bufferlen, action, 'A', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, ack_len);
                sendto(Sapi, (const char *)buffer, ack_len, 0, (sockaddr_t*)&routerAddr, sizeof(routerAddr));
                std::cout << "[ACK] " << action << " reenviado." << std::endl;
            }
        }
    }

    CLOSE_SOCKET(Sapi);
    std::cout << "\nConexao finalizada. " << std::endl;
    std::cout << "Mensagens recebidas:" << std::endl;
    for (const auto& msg : window.appData) {
        std::cout << "- " << msg << std::endl;
    }

    cleanup_sockets();
    return 0;
}
