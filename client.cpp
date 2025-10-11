#ifndef UNICODE
#define UNICODE
#endif

#define WIN32_LEAN_AND_MEAN
const int N = 16;
#define WINDOW_SIZE 5
#define TIMEOUT 1000
#define ATTEMPTS 5
//g++ client.cpp -o client.exe -lws2_32 -lcrypto


#include <winsock2.h>
#include <Ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <vector>
#include <thread>
#include <atomic>
#include <condition_variable>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <openssl/md5.h>
#include <sstream>
#include <iomanip>
#include <string>

#pragma comment(lib, "Ws2_32.lib")

std::mutex mtx;
std::condition_variable cv;
bool answered = false;
bool timeout = false;

void thread_timer() {
    std::unique_lock<std::mutex> lock(mtx);
    if (!cv.wait_for(lock, std::chrono::milliseconds(TIMEOUT), [] { return answered; })) {
        timeout = true;
        cv.notify_all(); 
    }
}

void thread_connect(int sockfd, char buffer[], int bufferlen) {
    sockaddr_in remetente{};
    socklen_t remetente_len = sizeof(remetente);

    ssize_t bytes = recvfrom(sockfd, buffer, bufferlen - 1, 0,
                             (sockaddr*)&remetente, &remetente_len);

    if (bytes > 0) {
        buffer[bytes] = '\0';
        std::unique_lock<std::mutex> lock(mtx);
        answered = true;
        cv.notify_all();  
    }
}

class TransmissionWindow{
    public:
    std::vector<bool> received = std::vector<bool>(N, false);
    std::vector<std::string> appData;
    int expected;
    bool connected = false;
    bool closing = false;
    int receive(int seqNumber, char type, std::string message)
    {
        if (type == 'C')
        {
            if (!connected && !closing && seqNumber >= 0 && seqNumber <= 15)
            {
                expected = seqNumber;
                connected = true;
                return answer(seqNumber);
            }
        }
        else if (connected)
        {

            if (type == 'A')
            {
                if (closing && expected == seqNumber)
                {
                    closing = false;
                    connected = false;
                    return -1;
                }
            }

            else if (type == 'D')
            {
                appData.push_back(message);
                return answer(seqNumber);
            }

            else if (type == 'F')
            {
                if (connected)
                {
                    closing = true;
                    return answer(seqNumber);
                }
            }
            std::cout << "Pacote ignorado. Estado invalido." << std::endl;
            return expected;
        }
        return -1;
    }

    int answer(int seqNumber)
    {
        int number = seqNumber;

        if (number == expected)
        {
            received[number] = false;
            int i = number + 1;
            while(true)
            {
                i %= 15;
                if (!received[i])
                {
                    expected = i;
                    return i;
                } 
                else
                {
                    received[i] = false;
                }
                i++;
            }
        }

        else if ((number - expected + N) % N < WINDOW_SIZE)
        {
            received[number] = true;
            return expected;
        }

        else
        {
            return expected;
        }
    }
};

std::string md5(const std::string &str) {
    unsigned char hash[MD5_DIGEST_LENGTH];
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str.c_str(), str.size());
    MD5_Final(hash, &md5);

    std::stringstream ss;
    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    return ss.str();
}

void md5_raw(const std::string &str, unsigned char out[MD5_DIGEST_LENGTH]) {
    MD5_CTX md5;
    MD5_Init(&md5);
    MD5_Update(&md5, str.c_str(), str.size());
    MD5_Final(out, &md5);
}

bool isCorrupted(char datagram[], int size)
{
    std::string message(datagram, size - 16);
    std::string receivedHash(datagram + size - 16, size);
    unsigned char hash[16];
    md5_raw(message, hash);
    for (int i = 0; i < 16; i++)
    {
        if (hash[i] != (unsigned char)receivedHash[i]) return true;
    }
    return false;
}

constexpr size_t HASH_LEN = 16;
constexpr size_t HEADER_SEQ_AND_TYPE = 2;
constexpr size_t HEADER_IP = 4;
constexpr size_t HEADER_PORT = 2;

bool formDatagram(uint8_t *buf, size_t buf_len,
                             uint8_t seq, char type,
                             const char *dest_ip_str, uint16_t dest_port,
                             const char *src_ip_str, uint16_t src_port,
                             const uint8_t *payload, size_t payload_len,
                             size_t &total_len_out)
{
    if (!buf || !dest_ip_str || !src_ip_str) return false;

    // calcular tamanho total esperado
    const size_t total_len = HEADER_SEQ_AND_TYPE + HEADER_IP + HEADER_PORT
                             + HEADER_IP + HEADER_PORT // origem
                             + payload_len + HASH_LEN;

    if (buf_len < total_len) return false;

    size_t offset = 0;

    buf[offset++] = seq;
    buf[offset++] = static_cast<uint8_t>(type);

    in_addr dest_addr{};
    if (inet_pton(AF_INET, dest_ip_str, &dest_addr) != 1) return false;
    memcpy(buf + offset, &dest_addr.s_addr, HEADER_IP);
    offset += HEADER_IP;

    uint16_t dest_port_net = htons(dest_port);
    memcpy(buf + offset, &dest_port_net, HEADER_PORT);
    offset += HEADER_PORT;

    in_addr src_addr{};
    if (inet_pton(AF_INET, src_ip_str, &src_addr) != 1) return false;
    memcpy(buf + offset, &src_addr.s_addr, HEADER_IP);
    offset += HEADER_IP;

    uint16_t src_port_net = htons(src_port);
    memcpy(buf + offset, &src_port_net, HEADER_PORT);
    offset += HEADER_PORT;

    if (payload_len > 0 && payload != nullptr) {
        memcpy(buf + offset, payload, payload_len);
        offset += payload_len;
    }

    MD5_CTX md5ctx;
    MD5_Init(&md5ctx);
    MD5_Update(&md5ctx, buf, offset);
    unsigned char digest[HASH_LEN];
    MD5_Final(digest, &md5ctx);

    memcpy(buf + offset, digest, HASH_LEN);

    total_len_out = total_len;
    return true;
}
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
    std::cout << "Bem vindo ao cliente RDT 4.0. Em qual porta deseja operar?" << std::endl;
    std::cin >> clientPort;


    SOCKET Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        // Descobre IP local automaticamente
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
    std::cout << "IP local detectado: " << clientIP << std::endl;


    Sapi = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    sockaddr_in clientaddr;
    clientaddr.sin_family = AF_INET;
    clientaddr.sin_port = htons(clientPort);
    inet_pton(AF_INET, clientIP, &clientaddr.sin_addr);

    res = bind(Sapi,(SOCKADDR *) &clientaddr, sizeof(clientaddr));
    if (res == SOCKET_ERROR)
    {
        wprintf(L": Ligacao do socket falhou com erro%u\n", WSAGetLastError());
        closesocket(Sapi);
        WSACleanup();
        return 1;
    }

    else
    {
        wprintf(L"Bind finalizada com sucesso\n");
    }
    int serverPort;
    std::string serverIP;
    std::cout << "IP da rede intermediaria: ";
    std::cin >> serverIP;
    std::cout << "Porta da rede intermediaria: ";
    std::cin >> serverPort;
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIP.c_str(), &serverAddr.sin_addr); //IP DO SERVIDOR (A SER TESTADO)

    int destinyPort;
    std::string destinyIP;
    std::cout << "IP do destino: ";
    std::cin >> destinyIP;
    std::cout << "Porta do destino: ";
    std::cin >> destinyPort;

    sockaddr_in sendback;
    int sendbackSize = sizeof(sendback);
    int bufferlen = 1024;
    uint8_t buffer[bufferlen];

    int seqIni;

    do
    {
        std::cout << "Numero de sequencia inicial: ";
        std::cin >> seqIni;
    } while(seqIni < 0 || seqIni > 15);

    int tries = 0;
    uint8_t bufferConnection[1024]; 
    size_t lentotal;
    if (!formDatagram(bufferConnection, 1023, seqIni, 'C', destinyIP.c_str(), destinyPort, clientIP, clientPort, nullptr, 0, lentotal))
    {
        perror("Nao foi possivel formar o segmento");
        return 0;
    }

    while (tries < ATTEMPTS)
    {
        answered = false;
        timeout = false;

        int sent = sendto(Sapi, (const char*)bufferConnection, lentotal, 0, (SOCKADDR *) &serverAddr, sizeof(serverAddr));

        if (sent < 0)
        {
            perror("Erro ao enviar pedido de conexão");
            break;
        }

        std::cout << "Tentativa " << tries + 1 << ". Enviando" << std::endl;
        

        std::thread th_connect(thread_connect, Sapi, (char *)bufferConnection, 1024);
        std::thread th_timer(thread_timer);

        
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait(lock, [] { return answered || timeout; });
        }

        th_connect.detach();
        th_timer.detach();

        if (answered) {
            std::cout << "Conexao estabelecida. Servidor vai iniciar carga de dados\n";
            break;
        } else if (timeout) {
            std::cout << "Timeout atingido. Reenviando...\n";
            tries++;
        }
    }

    if (!answered)
    {
        std::cout << "Nao foi possivel estabelecer conexao com o servidor apos " << ATTEMPTS << " tentativas" << std::endl;
        return 0;
    }
    TransmissionWindow window;
    wprintf(L"Recebendo datagramas do servidor...\n");
    while (true)
    {
        res = recvfrom(Sapi, (char *)buffer, bufferlen, 0, (SOCKADDR *) &sendback, &sendbackSize);
        if (res == SOCKET_ERROR)
        {
            wprintf(L"Recvfrom falhou com erro %d\n", WSAGetLastError());
        }
        for (int i = 0; i < res; i++)
        {
            printf("%c", buffer[i]);
        }
        printf("\n");
        int action;
        if (!isCorrupted((char*)buffer, res))
        {
            printf("Pacote nao corrompido");
            std::string package((char*)buffer, res - 16);
            int seq = (int)package[0];
            char type = package[1];
            std::string message((char*)buffer + 2*(HEADER_IP + HEADER_PORT), res -16);
            action = window.receive(seq, type, message);

            if (action >= 0)
            {
                formDatagram(buffer, bufferlen, action, 'A', destinyIP.c_str(), destinyPort, clientIP, clientPort, nullptr, 0, lentotal);

            int sent = sendto(Sapi, (const char *)buffer, lentotal, 0, (SOCKADDR *) &serverAddr, sizeof(serverAddr));

            if (sent < 0)
            {
                perror("Erro ao enviar ACK");
                break;
            } 
            }
        }
        else
        {
            printf("Pacote corrompido. Descartando");
        }

    }
   
    wprintf(L"Fim do recebimento. Fechando socket\n");
    res = closesocket(Sapi);
    if (res == SOCKET_ERROR) {
        wprintf(L"Fechamento falhou com erro %d\n", WSAGetLastError());
        return 1;
    }

    wprintf(L"Saindo.\n");
    WSACleanup();
    return 0;
}