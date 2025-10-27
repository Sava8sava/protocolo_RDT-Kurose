#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
// Comando para compilar (com seu path do vcpkg):
// g++ client_final.cpp -o client.exe -IC:\Users\kauan\vcpkg\installed\x64-windows\include -LC:\Users\kauan\vcpkg\installed\x64-windows\lib -lws2_32 -lcrypto

#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <string>
#include <chrono>
#include <openssl/md5.h>
#include <openssl/evp.h> // Para a API moderna do MD5
#include <sstream>
#include <iomanip>
#include <thread> // Para o sleep

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "libcrypto.lib") // Para OpenSSL

// ===========================
// CONSTANTES (Como em Python)
// ===========================
const int N = 16;
const int TIMEOUT_MS = 40000; // 1.0 segundo
const int ATTEMPTS = 5;
const int HASH_LEN = 16;
const int RDT_HEADER_LEN = 14; // 1(seq) + 1(tipo) + 4(IP dest) + 2(porta dest) + 4(IP orig) + 2(porta orig)

// ===========================
// FUNÇÕES AUXILIARES
// ===========================

// Gera o hash MD5 binário (16 bytes)
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

// Verifica a corrupção comparando o hash
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

// Monta o datagrama
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

// ===========================
// CLASSE DE CONTROLE DE RECEPÇÃO
// ===========================
class TransmissionWindow{
    public:
    int expected;
    std::vector<std::string> appData;
    bool connected;
    bool finished; // Flag para "FIN do servidor recebido"

    TransmissionWindow() : expected(0), connected(false), finished(false) {}

    int receive(int seq, char tipo, std::string payload)
    {
        if (tipo == 'C')
        {
            if (!connected)
            {
                connected = true;
                expected = (seq + 1) % N;
                std::cout << "[HANDSHAKE] Pacote tipo 'C' recebido. Esperado agora: " << expected << std::endl;
                return expected;
            }
            else
            {
                std::cout << "[HANDSHAKE] 'C' duplicado recebido. Reenviando ACK " << (seq + 1) % N << "..." << std::endl;
                return (seq + 1) % N; // Reenvia o ACK
            }
        }

        // Não aceita mais pacotes 'D' se o 'F' já chegou
        else if (tipo == 'D' && connected && !finished)
        {
            if (seq == expected)
            {
                std::cout << "[DADOS] Seq=" << seq << " | Mensagem='" << payload << "'" << std::endl;
                appData.push_back(payload);
                expected = (expected + 1) % N;
                return expected;
            }
            else
            {
                std::cout << "[FORA DE ORDEM] Esperado=" << expected << ", Recebido=" << seq << ". Ignorado." << std::endl;
                // Reenvia o ACK anterior
                return expected;
            }
        }

        else if (tipo == 'F' && connected)
        {
            // Se eu receber um FIN (mesmo que duplicado), eu mando um ACK
            std::cout << "[FIM] Pacote tipo 'F' recebido. Enviando ACK." << std::endl;
            finished = true; // Marco que o servidor quer fechar
            return (seq + 1) % N; // Envia o ACK
        }

        return -1;
    }
};

// ===========================
// PROGRAMA PRINCIPAL
// ===========================
int main()
{
    WSADATA wsaData;
    int res = 0;
    res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != NO_ERROR) {
        wprintf(L"Erro ao iniciar WinSock\n");
        return 1;
    }

    int clientPort;
    std::cout << "=== CLIENTE RDT 4.0 ===" << std::endl;
    std::cout << "Porta do cliente: ";
    std::cin >> clientPort;

    SOCKET Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    char clientIP[INET_ADDRSTRLEN];
    sockaddr_in fake{};
    fake.sin_family = AF_INET;
    fake.sin_port = htons(80);
    inet_pton(AF_INET, "8.8.8.8", &fake.sin_addr);
    connect(Sapi, (sockaddr*)&fake, sizeof(fake));
    sockaddr_in local{};
    int len = sizeof(local);
    getsockname(Sapi, (sockaddr*)&local, &len);
    inet_ntop(AF_INET, &local.sin_addr, clientIP, sizeof(clientIP));
    closesocket(Sapi); 
    
    Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in clientaddr;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(clientPort);
    inet_pton(AF_INET, clientIP, &clientaddr.sin_addr);

    res = bind(Sapi,(SOCKADDR *) &clientaddr, sizeof(clientaddr));
    if (res == SOCKET_ERROR)
    {
        wprintf(L"Bind falhou com erro %u\n", WSAGetLastError());
        closesocket(Sapi);
        WSACleanup();
        return 1;
    }
    std::cout << "[INFO] Socket vinculado em " << clientIP << ":" << clientPort << "\n" << std::endl;

    DWORD timeout = TIMEOUT_MS;
    setsockopt(Sapi, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));

    std::string routerIP, destIP;
    int routerPort, destPort;
    
    std::cout << "IP da rede intermediária (roteador): ";
    std::cin >> routerIP;
    std::cout << "Porta da rede intermediária (roteador): ";
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
        std::cout << "Número de sequência inicial (0–15): ";
        std::cin >> seqIni;
    } while(seqIni < 0 || seqIni > 15);


    int bufferlen = 2048;
    uint8_t buffer[bufferlen];
    sockaddr_in sendback;
    int sendbackSize = sizeof(sendback);
    
    TransmissionWindow window;
    
    // === HANDSHAKE ===
    std::cout << "\n[ETAPA 1] Enviando pacote de conexão tipo 'C'..." << std::endl;
    uint8_t conn_packet[1024]; 
    size_t conn_packet_len;
    if (!formDatagram(conn_packet, 1024, seqIni, 'C', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, conn_packet_len))
    {
        perror("Nao foi possivel formar o segmento de conexao");
        return 0;
    }

    for (int attempt = 0; attempt < ATTEMPTS; attempt++)
    {
        sendto(Sapi, (const char*)conn_packet, conn_packet_len, 0, (SOCKADDR *) &routerAddr, sizeof(routerAddr));
        std::cout << "Tentativa " << attempt + 1 << ": aguardando resposta do servidor..." << std::endl;

        ssize_t bytes = recvfrom(Sapi, (char *)buffer, bufferlen - 1, 0, (SOCKADDR *) &sendback, &sendbackSize);

        if (bytes < 0) {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                std::cout << "Timeout." << std::endl;
                if (attempt < ATTEMPTS - 1) { 
                     std::cout << "Aguardando 10 segundos antes de tentar novamente..." << std::endl;
                     std::this_thread::sleep_for(std::chrono::seconds(10));
                     std::cout << "Reenviando pacote de conexão.\n" << std::endl;
                }
                continue;
            } else {
                perror("recvfrom error no handshake");
                break;
            }
        }

        if (isCorrupted((char*)buffer, bytes)) {
            std::cout << "Pacote corrompido ou inválido. Ignorado.\n" << std::endl;
            continue;
        }

        uint8_t seq = buffer[0];
        char type = (char)buffer[1];
        int next_ack = window.receive(seq, type, "");
            
        if (next_ack != -1) {
            size_t ack_len;
            formDatagram(buffer, bufferlen, next_ack, 'A', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, ack_len);
            sendto(Sapi, (const char*)buffer, ack_len, 0, (SOCKADDR *) &routerAddr, sizeof(routerAddr));
            if (window.connected) {
                std::cout << "[ACK] Enviado ACK " << next_ack << ". Conexão estabelecida!\n" << std::endl;
                break; 
            }
        }
    }

    if (!window.connected)
    {
        std::cout << "Falha: não foi possível estabelecer conexão após múltiplas tentativas." << std::endl;
        closesocket(Sapi);
        WSACleanup();
        return 0;
    }

    // === RECEBIMENTO DE DADOS ===
    std::cout << "[ETAPA 2] Aguardando pacotes de dados...\n" << std::endl;

    while (!window.finished)
    {
        res = recvfrom(Sapi, (char *)buffer, bufferlen, 0, (SOCKADDR *) &sendback, &sendbackSize);

        if (res == SOCKET_ERROR)
        {
            if (WSAGetLastError() == WSAETIMEDOUT) {
                std::cout << "[TIMEOUT] Esperando pacote. Nenhuma ação." << std::endl;
                continue;
            } else {
                wprintf(L"Recvfrom falhou com erro %d\n", WSAGetLastError());
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
            int sent = sendto(Sapi, (const char *)buffer, ack_len, 0, (SOCKADDR *) &routerAddr, sizeof(routerAddr));

            if (sent < 0)
            {
                perror("Erro ao enviar ACK");
                break;
            } 
            std::cout << "[ACK] " << action << " enviado.\n" << std::endl;
        }
    }
   
    // ==========================================================
    // ETAPA 3: ESTADO DE TIME_WAIT
    // ==========================================================
    
    // O loop 'while' terminou, o que significa que window.finished = True
    // O ACK para o FIN do servidor já foi enviado dentro do loop.
    
    std::cout << "\n[FIM] Conexão encerrada pelo servidor. Entrando em TIME_WAIT por "
              << (TIMEOUT_MS * 2) / 1000.0 << " seg." << std::endl;

    // Mudo o timeout do socket para o tempo de TIME_WAIT
    DWORD timeout_wait = TIMEOUT_MS * 2;
    setsockopt(Sapi, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout_wait, sizeof(timeout_wait));

    // Tento receber um pacote (esperando um FIN duplicado)
    res = recvfrom(Sapi, (char *)buffer, bufferlen, 0, (SOCKADDR *) &sendback, &sendbackSize);

    if (res == SOCKET_ERROR)
    {
        if (WSAGetLastError() == WSAETIMEDOUT) {
            // Este é o caminho feliz!
            std::cout << "[TIME_WAIT] Tempo esgotado. Nenhuma duplicata recebida. Fechando." << std::endl;
        } else {
            // Outro erro
            wprintf(L"[TIME_WAIT] recvfrom falhou com erro %d\n", WSAGetLastError());
        }
    }
    else if (res > 0)
    {
        // Recebi algo. É um FIN duplicado?
        if (!isCorrupted((char*)buffer, res))
        {
            uint8_t seq = buffer[0];
            char type = (char)buffer[1];

            if (type == 'F') {
                // É um FIN duplicado! Meu ACK se perdeu.
                std::cout << "[TIME_WAIT] FIN duplicado recebido. Reenviando ACK final..." << std::endl;
                
                int action = (seq + 1) % N;
                size_t ack_len;
                formDatagram(buffer, bufferlen, action, 'A', destIP.c_str(), destPort, clientIP, clientPort, nullptr, 0, ack_len);
                sendto(Sapi, (const char *)buffer, ack_len, 0, (SOCKADDR *) &routerAddr, sizeof(routerAddr));
                std::cout << "[ACK] " << action << " reenviado." << std::endl;
            }
        }
    }


    // === FIM ===
    closesocket(Sapi);
    std::cout << "\n=== Conexão finalizada ===" << std::endl;
    std::cout << "Mensagens recebidas:" << std::endl;
    for (const auto& msg : window.appData) {
        std::cout << "- " << msg << std::endl;
    }

    WSACleanup();
    return 0;
}