import socket
import struct
import hashlib
import threading
import time
from collections import deque

WINDOW_SIZE = 5
TIMEOUT = 20.0
MAX_SEQ_NUM = 16
HASH_LEN = 16

base = 0
next_seq_num = 0
lock = threading.Lock()
timer = None
send_window = {}
client_addr = None
router_addr = None

def calcular_md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()

def criar_datagrama(seq_num, tipo, ip_origem, porta_origem, ip_destino, porta_destino, data=b''):
    ip_dest_bytes = socket.inet_aton(ip_destino)
    ip_origem_bytes = socket.inet_aton(ip_origem)
    porta_dest_bytes = struct.pack('!H', porta_destino)
    porta_origem_bytes = struct.pack('!H', porta_origem)
    pacote_sem_hash = (
        seq_num.to_bytes(1, 'big') +
        tipo.encode('ascii') +
        ip_dest_bytes +
        porta_dest_bytes +
        ip_origem_bytes +
        porta_origem_bytes +
        data
    )
    digest = calcular_md5(pacote_sem_hash)
    return pacote_sem_hash + digest

def in_window(seq):
    if base <= (next_seq_num - 1) % MAX_SEQ_NUM:
        return base <= seq <= (next_seq_num - 1) % MAX_SEQ_NUM
    else:
        return seq >= base or seq <= (next_seq_num - 1) % MAX_SEQ_NUM

def reenviar_janela(sock):
    global timer, router_addr
    with lock:
        print(f"\n[TIMEOUT] Timeout para pacote base {base}. Reenviando janela...")
        for seq, pacote in send_window.items():
            print(f"Reenviando pacote {seq}")
            if router_addr:
                sock.sendto(pacote, router_addr)
        timer = threading.Timer(TIMEOUT, reenviar_janela, args=(sock,))
        timer.start()

def receber_acks(sock):
    global base, timer, send_window, router_addr
    while True:
        try:
            ack_data, addr = sock.recvfrom(1024)
            ack_seq = ack_data[0]
            ack_tipo = ack_data[1:2].decode('ascii')
            hash_recebido = ack_data[-HASH_LEN:]
            pacote_sem_hash = ack_data[:-HASH_LEN]
            if calcular_md5(pacote_sem_hash) != hash_recebido:
                continue
            if ack_tipo != 'A':
                continue
            with lock:
                if in_window(ack_seq):
                    print(f"[ACK RECEBIDO] seq={ack_seq}")
                    while base != ack_seq:
                        if base in send_window:
                            del send_window[base]
                        base = (base + 1) % MAX_SEQ_NUM
                    if send_window:
                        if timer:
                            timer.cancel()
                        timer = threading.Timer(TIMEOUT, reenviar_janela, args=(sock,))
                        timer.start()
                    else:
                        if timer:
                            timer.cancel()
                        print("[INFO] Todos pacotes confirmados.")
        except Exception as e:
            print(f"[ERRO] Recebendo ACK: {e}")
            break

if __name__ == "__main__":
    SERVER_IP = "192.168.45.213"
    SERVER_PORT = 9000
    CLIENT_IP = input("Digite o IP do cliente (ex: 127.0.0.1): ")
    CLIENT_PORT = int(input("Digite a porta do cliente (ex: 5000): "))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    print(f"Servidor RDT 4.0 operando em {SERVER_IP}:{SERVER_PORT}")

    print("\nAguardando pedido de conexão do cliente...")
    try:
        connect_packet, router_addr = server_socket.recvfrom(1024)
        print(f"Pacote de conexão recebido de {router_addr}")
        seq_inicial_cliente = connect_packet[0]
        confirm_pacote = criar_datagrama(
            seq_num=seq_inicial_cliente, tipo='C',
            ip_origem=SERVER_IP, porta_origem=SERVER_PORT,
            ip_destino=CLIENT_IP, porta_destino=CLIENT_PORT
        )
        server_socket.sendto(confirm_pacote, router_addr)
        print(f"Enviado pacote de confirmação tipo 'C' com seq={seq_inicial_cliente}")
        print("Aguardando ACK do cliente...")
        while True:
            ack_data, addr = server_socket.recvfrom(1024)
            ack_seq = ack_data[0]
            ack_tipo = ack_data[1:2].decode('ascii')
            if ack_tipo == 'A':
                print(f"ACK recebido do cliente (seq={ack_seq}). Conexão estabelecida!\n")
                base = next_seq_num = (seq_inicial_cliente + 1) % MAX_SEQ_NUM
                break
    except Exception as e:
        print(f"Erro durante o handshake: {e}")
        server_socket.close()
        exit()

    ack_thread = threading.Thread(target=receber_acks, args=(server_socket,), daemon=True)
    ack_thread.start()

    mensagens = [f"Este é o pacote de dados número {i}" for i in range(15)]
    pacotes_a_enviar = deque(mensagens)
    print("Iniciando envio de pacotes de dados...")

    while pacotes_a_enviar or send_window:
        with lock:
            while len(send_window) < WINDOW_SIZE and pacotes_a_enviar:
                data = pacotes_a_enviar.popleft().encode('utf-8')
                seq_atual = next_seq_num % MAX_SEQ_NUM
                pacote = criar_datagrama(
                    seq_num=seq_atual, tipo='D',
                    ip_origem=SERVER_IP, porta_origem=SERVER_PORT,
                    ip_destino=CLIENT_IP, porta_destino=CLIENT_PORT,
                    data=data
                )
                send_window[seq_atual] = pacote
                print(f"[ENVIANDO] Pacote de dados (seq={seq_atual})")
                server_socket.sendto(pacote, router_addr)
                if base == next_seq_num:
                    if timer:
                        timer.cancel()
                    timer = threading.Timer(TIMEOUT, reenviar_janela, args=(server_socket,))
                    timer.start()
                next_seq_num = (next_seq_num + 1) % MAX_SEQ_NUM
        time.sleep(0.01)

    print("\nTodos os pacotes foram enviados e confirmados.")
    if timer:
        timer.cancel()

    print("Enviando pacote de finalização (FIN)...")
    fin_pacote = criar_datagrama(
        seq_num=next_seq_num % MAX_SEQ_NUM, tipo='F',
        ip_origem=SERVER_IP, porta_origem=SERVER_PORT,
        ip_destino=CLIENT_IP, porta_destino=CLIENT_PORT
    )
    server_socket.sendto(fin_pacote, router_addr)
    server_socket.close()
    print("Servidor encerrado.")
