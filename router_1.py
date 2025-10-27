import socket
import os 
import struct
import sys
import random
from threading import Thread
import threading
import time 
from typing_extensions import final


'''Estrutura do datagrama RDT 4.0
1. Numero de sequência - 1 byteb -> 0 
2. Tipo - 1 byte -> 1  
3.  IP de destino - 4 bytes  
4. Porta de destino - 2 bytes 
5. IP de origem - 4 bytes
6. Porta de origem - 2 bytes
.N - 16 Hash MD5 - 16 bytes (em hex)'''

HASH_LEN = 16 
HEADER_SEQ_AND_TYPE = 2
HEADER_IP = 4 
HEADER_PORT = 2 
RDT_HEADER_LEN = 14 #HEADER_SEQ_AND_TYPE + 2 * HEADER_IP + 2 * HEADER_PORT
BUFFER_SIZE = 1024 
ROUTER_EVENT = "TRANSPARENCIA" #por default não aplica erros 
EVENT_LOCK = False #evita mudança de eventos enquanto processamos o evento 


def get_destination_addr(datagram_bytes):
    if len (datagram_bytes) < RDT_HEADER_LEN:
        print("Error: pacote de tamanho insuficiente")
        return None,None 

    try:
        #extrai o endereço ip de destino 
        destination_ip = datagram_bytes[2:6]
        destination_ip_string = socket.inet_ntoa(destination_ip)
        #extrai a porta de ip 
        destination_port = datagram_bytes[6:8]
        dest_port_value = struct.unpack('!H', destination_port)[0]

        return destination_ip_string,dest_port_value
    except Exception as e:
        print(f"Router: Erro ao descompactar o cabeçalho : {e}\n")
        return None, None 

def corrupt_field(data : bytes) -> bytes:
    
    fields = {"seq" : (0,1),
              "type" : (1,2),
              "ip_dest" : (2,6),
              "port_dest" : (6,8),
              "ip_org" : (8,12),
              "port_org" : (12,14),
              "hash_md5" : (14,30),
              "payload" : (30,len(data))
              }
    
   
    chosen_field = random.choice(list(fields.keys()))
    start_byte, end_byte = fields[chosen_field]
    
    #checagem caso o campo tenha o valor menor que o esperado 
    if end_byte > len(data):
        end_byte = len(data)

    index = random.randint(start_byte, end_byte - 1)
    corrupted_byte = bytes([data[index] ^ random.randint(0,255)]) #cria um campo corrompido fazendo campo original XOR numero aleatorio no intervalo 

    #bytes são imutaveis em python antes que pergutem
    data_corrupted = data[:index] + corrupted_byte + data[index + 1:]
    
    print(f"\nRouter: Campo({chosen_field}) corrompido!!!")
    return data_corrupted

def menu_evento(datagrama,timeout = 5):
    global ROUTER_EVENT

    Num_seq = datagrama[0]
    print("\n--- Menu de Eventos do Roteador ---")
    print(f"Evento Atual: {ROUTER_EVENT}")
    print(f"Numero de Seq do Pacote atual: {Num_seq}")
    print("1. TRANSPARÊNCIA (Encaminhamento normal)")
    print("2. CORROMPER UM CAMPO (Modifica 1 byte aleatório no payload)")
    print("3. ATRASAR PACOTE (Atraso de 5 segundos)")
    print("4. DESCARTAR PACOTE (Perda)")
    print(f"A escolha tem um tempo Limite de {timeout} segundos\n")
    
    escolha = [""] 

    def input_thread():
        try:
            escolha[0] = input("escolha o evento: ").strip() 
        except EOFError:
            pass 
    
    t = threading.Thread(target = input_thread)
    t.daemon = True
    t.start()
    t.join(timeout)

    if not escolha[0]:
        print("\nTempo esgotado - Pacote enviado Normalmente.\n")
    else:
        op = escolha[0].strip()
        if op == '1':
            ROUTER_EVENT = "TRANSPARENCIA"
        elif op == '2':   
            ROUTER_EVENT = "CORROMPER"
        elif op == '3':
            ROUTER_EVENT = "ATRASAR"
        elif op == '4':
            ROUTER_EVENT = "DESCARTAR"  
        else:
            print("Opção inválida. Tente novamente.")
    
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
    print(f"Router: Evento selecionado ->{ROUTER_EVENT}\n")


def router_main():
    try:
        router_port = int(input("Defina a porta de escuta do roteador:"))
    except ValueError:
        print("porta invalida")
        return 
    
    try:
        sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.bind(('0.0.0.0',router_port))
        print(f"Router: Escutando de 0.0.0.0:{router_port}")
    except socket.error as e:
        print(f"Router: falha no processo de bind com o socket")
        sys.exit(1)
  
    try:
        while True:
            print("Router: aguardando pacotes...")
            data, sender_addr = sock.recvfrom(BUFFER_SIZE)
            sender_ip,sender_port = sender_addr
            print(f"pacote recebido de (Socket):{sender_ip}:{sender_port})")

            destination_ip,destination_port = get_destination_addr(data)

            if destination_ip is None or destination_port is None:
                print("Router: erro ao ler o cabeçalho, descartando pacote") 
                continue 
        
            #cinema 
            final_destination = (destination_ip,destination_port)
            
            menu_evento(data,timeout=5) 
            current_event = ROUTER_EVENT
        
            if current_event == "DESCARTAR":
                print("Router: Evento de erro -> pacote Descartado")
                EVENT_LOCK = False
                continue 
            
            elif current_event == "ATRASAR":
                delay_time = 25 #segundos 
                print(f"Router: Evento de erro -> Atrasando os pacotes em {delay_time}seg")
                time.sleep(delay_time) 
            
            elif current_event == "CORROMPER":
                new_data = corrupt_field(data)
                if data is not None:
                    data = new_data
                else:
                    print("Router: Algum erro ocorreu ao tentar corromper os dados, enviando o pacote normal")

            elif current_event == "TRANSPARENCIA":
                print(f"Router: modo de transparencia")
            
            origem_ip = socket.inet_ntoa(data[8:12])
            origem_porta = struct.unpack('!H', data[12:14])[0]
            print(f"Router: Origem no cabeçalho -> {origem_ip}:{origem_porta}")
            sock.sendto(data, final_destination)
            print(f"Router: Pacote encaminhado para {destination_ip}:{destination_port}")

    except socket.error as e:
        print(f"Router: Erro de socket: {e}")
    except KeyboardInterrupt:
        print("ROTEADOR ENCERRADO") 
    finally:
        sock.close() 
        sys.exit(0)

if __name__ == "__main__":
    router_main()
