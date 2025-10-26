import socket
import struct
import hashlib
import threading
import time
from collections import deque

#variaveis globais
WINDOW_SIZE = 5
TIMEOUT = 40.0
MAX_SEQ_NUM = 16
HASH_LEN = 16
base = 0
next_seq_num = 0
lock = threading.Lock()
timer = None
send_window = {}
router_addr = None
servidor_rodando = True

# --- NOVAS GLOBAIS PARA FAST RETRANSMIT ---
duplicate_ack_count = 0
FAST_RETRANSMIT_THRESHOLD = 3
# ----------------------------------------

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
    end_of_window = (next_seq_num - 1 + MAX_SEQ_NUM) % MAX_SEQ_NUM
    if base <= end_of_window:
        return base <= seq <= end_of_window
    else:
        return seq >= base or seq <= end_of_window

def reenviar_janela(sock):
    global timer, router_addr
    with lock:
        if not servidor_rodando:
            return
            
        print(f"\n[TIMEOUT] Timeout para pacote base {base}. Reenviando janela...")
        for seq, pacote in send_window.items():
            print(f"Reenviando pacote {seq}")
            if router_addr:
                sock.sendto(pacote, router_addr)
        
        if send_window:
            timer = threading.Timer(TIMEOUT, reenviar_janela, args=(sock,))
            timer.start()


# THREAD DE RECEBIMENTO DE ACKs
def receber_acks(sock):
    global base, timer, send_window, router_addr, servidor_rodando, duplicate_ack_count
    
    while servidor_rodando:
        try:
            ack_data, addr = sock.recvfrom(1024)
            
            if not servidor_rodando:
                break
                
            # Eu preciso checar a corrupção de duas formas:
            # 1. O tipo é um byte ASCII válido?
            # 2. O hash MD5 bate?

            try:
                # 1. Tentar decodificar o tipo
                ack_tipo = ack_data[1:2].decode('ascii')
            except UnicodeDecodeError:
                # Se o byte de 'tipo' for lixo (como 0xa5), é corrompido.
                print(f"[PACOTE CORROMPIDO] Tipo de pacote invalido (nao-ASCII). Ignorando.")
                continue # Pula este pacote e espera o próximo

            # 2. Se o tipo é ASCII, checo o hash
            hash_recebido = ack_data[-HASH_LEN:]
            pacote_sem_hash = ack_data[:-HASH_LEN]
            if calcular_md5(pacote_sem_hash) != hash_recebido:
                print(f"[PACOTE CORROMPIDO] Hash MD5 falhou. Ignorando.")
                continue # Pula este pacote

            # Se cheguei aqui, o pacote é válido e não-corrompido.
            ack_seq = ack_data[0]
            
            if ack_tipo != 'A':
                # É um pacote válido, mas não é um ACK
                print(f"[PACOTE IGNORADO] Nao e um ACK (Tipo={ack_tipo}, Seq={ack_seq}).")
                continue
            
            # ==========================================================
            # INÍCIO DA LÓGICA CORRIGIDA (WRAP-AROUND)
            # ==========================================================
            with lock:
                
                # 1. Checa se é um ACK duplicado
                if ack_seq == base:
                    # --- ACK DUPLICADO ---
                    duplicate_ack_count += 1
                    print(f"[ACK DUPLICADO] Recebido ACK {ack_seq} (base={base}). Contagem = {duplicate_ack_count}")
                    
                    if duplicate_ack_count >= FAST_RETRANSMIT_THRESHOLD:
                        print(f"!!! [FAST RETRANSMIT] Limite atingido. Reenviando pacote {base}...")
                        if base in send_window:
                            sock.sendto(send_window[base], router_addr)
                        else:
                            print(f"[FAST RETRANSMIT] Erro: Pacote {base} não está na janela.")
                        
                        if timer: timer.cancel()
                        if send_window:
                            timer = threading.Timer(TIMEOUT, reenviar_janela, args=(sock,))
                            timer.start()
                        duplicate_ack_count = 0
                    continue # Importante: não continua para a próxima verificação

                # 2. Checa se é um ACK Novo (cumulativo)
                # Esta lógica calcula se o ack_seq está "à frente" da base,
                # lidando com o wrap-around (ex: base=15, ack_seq=0)
                is_new = False
                if base < next_seq_num: # Caso normal (ex: base=5, next=8)
                    is_new = ack_seq > base and ack_seq <= next_seq_num
                elif base > next_seq_num: # Caso de wrap-around (ex: base=14, next=2)
                    # O ACK é novo se for > 14 OU <= 2
                    is_new = ack_seq > base or ack_seq <= next_seq_num
                elif base == next_seq_num and len(send_window) > 0: # Caso do FIN (base=0, next=0, mas janela=1)
                    # Este é o caso do bug do FIN que corrigimos.
                    # O next_seq_num esperado é (base+1)
                    if ack_seq == (base + 1) % MAX_SEQ_NUM:
                        is_new = True
                
                if is_new:
                    # --- NOVO ACK CUMULATIVO ---
                    print(f"[ACK RECEBIDO] seq={ack_seq}. Base avançando de {base} para {ack_seq}")
                    
                    # CORREÇÃO: A nova base é o próprio ack_seq
                    new_base = ack_seq 
                    
                    while base != new_base:
                        if base in send_window:
                            del send_window[base]
                        base = (base + 1) % MAX_SEQ_NUM
                    
                    # Resetar a contagem de ACKs duplicados
                    duplicate_ack_count = 0
                    
                    # Reiniciar o timer
                    if timer: timer.cancel()
                    if send_window:
                        timer = threading.Timer(TIMEOUT, reenviar_janela, args=(sock,))
                        timer.start()
                
                else: 
                    # --- ACK ANTIGO ---
                    # Se não é duplicado e não é novo, é antigo.
                    print(f"[ACK ANTIGO] Ignorando ACK {ack_seq} (base={base})")
            
            # ==========================================================
            # FIM DA LÓGICA CORRIGIDA
            # ==========================================================

        # ou bugs de programação inesperados
        except Exception as e:
            if servidor_rodando:
                print(f"[ERRO] Thread de ACK parou inesperadamente: {e}")
            else:
                print(f"[INFO] Thread de ACK encerrando...")
            break # Sai do loop


# PROGRAMA PRINCIPAL (SERVIDOR)
if __name__ == "__main__":
    SERVER_IP = "192.168.18.253"
    SERVER_PORT = 9000
    CLIENT_IP = input("Digite o IP do cliente (ex: 127.0.0.1): ")
    CLIENT_PORT = int(input("Digite a porta do cliente (ex: 5000): "))

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    print(f"Servidor RDT 4.0 operando em {SERVER_IP}:{SERVER_PORT}")


    # ETAA 1: HANDSHAKE (C -> C -> A)
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
                base = (seq_inicial_cliente + 1) % MAX_SEQ_NUM
                next_seq_num = base
                break
    except Exception as e:
        print(f"Erro durante o handshake: {e}")
        server_socket.close()
        exit()

    # ETAPA 2: ENVIO DE DADOS
    ack_thread = threading.Thread(target=receber_acks, args=(server_socket,), daemon=True)
    ack_thread.start()

    mensagens = [f"Este é o pacote de dados número {i}" for i in range(15)]
    pacotes_a_enviar = deque(mensagens) 
    print("Iniciando envio de pacotes de dados...")

    while pacotes_a_enviar or send_window:
        with lock:
            while len(send_window) < WINDOW_SIZE and pacotes_a_enviar:
                data = pacotes_a_enviar.popleft().encode('utf-8')
                seq_atual = next_seq_num
                
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

    print("\nTodos os pacotes de dados foram enviados e confirmados.")
    if timer:
        timer.cancel() 

    # ETAPA 3: FINALIZAÇÃO (FIN) CONFIÁVEL
    print("Enviando pacote de finalização (FIN)...")
    fin_seq_num = next_seq_num
    
    fin_pacote = criar_datagrama(
        seq_num=fin_seq_num, tipo='F',
        ip_origem=SERVER_IP, porta_origem=SERVER_PORT,
        ip_destino=CLIENT_IP, porta_destino=CLIENT_PORT
    )
    
    with lock:
        send_window[fin_seq_num] = fin_pacote
        server_socket.sendto(fin_pacote, router_addr)
        print(f"[ENVIANDO] Pacote de finalização (seq={fin_seq_num})")
        
        # <<< CORREÇÃO DO BUG DO FIN >>>
        # Incrementa o next_seq_num para que o 'ACK 1' (do FIN 0) seja
        # reconhecido como novo.
        next_seq_num = (next_seq_num + 1) % MAX_SEQ_NUM
        
        if timer:
            timer.cancel()
        timer = threading.Timer(TIMEOUT, reenviar_janela, args=(server_socket,))
        timer.start()
        
    while True:
        with lock:
            if not send_window:
                break
        time.sleep(0.1) 

    print(f"[ACK DO FIN RECEBIDO] ACK para {fin_seq_num} recebido.")
    
    if timer:
        timer.cancel()
    
    print("Sinalizando para a thread de ACKs parar...")
    servidor_rodando = False
    server_socket.close()
    
    print("Servidor encerrado.")