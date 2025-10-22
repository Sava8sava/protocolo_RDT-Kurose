import socket
import threading
import random
import string


#Cliente<->Roteador 
ROUTER_HOST = "127.0.0.1" 
ROUTER_PORT = 8000

#Roteador<->Servidor 
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 8001 

BUFFER_SIZE = 1024

#adiciona ruido no inicio,meio ou fim da mensagem  
def noise_corrution(mensagem):
    noise = "".join(random.choices(string.ascii_letters + string.digits, k=5))
    mensagem_corrompida = f"{noise}{mensagem}" 
    print("Roteador: Mensagem com bits aleatorios na transmissão")
    return mensagem_corrompida
    

#inverte a mensagem:
def inversion_corruption(mensagem):
    mensagem_corrompida = mensagem[::-1]
    print("Roteador: Mensagem invertida")
    return mensagem_corrompida


#troca uma letra por outra letra 
def replacement_corruption(mensagem):
    if not mensagem:
        return ""
        
    charlist = list(mensagem)
    
    #escolhe uma posição aleatória para a troca
    posi= random.randint(0, len(charlist) - 1)
    #escolhe um caracterer aletorio
    new_char= random.choice(string.ascii_letters)
 
    charlist[posi] = new_char
    mensagem_corrompida = "".join(charlist)
    print(f"Router: Mensagem com letra trocadas")
    return mensagem_corrompida

def Menu_for_mensagens(mensagem):
    print('Router: Opções de Modifcações da mensagem')
    print("1.Transparencia de Mensagem.")
    print("2.Corromper a Mensagem")

    op = input("Escolha uma das opções")

    if op == '1':
        return mensagem
    elif op == '2':
        corruption_methodes = [noise_corrution,inversion_corruption,replacement_corruption]
        
        #escolhe uma opção aleatoria entre os metodos 
        func = random.choice(corruption_methodes)
        mensagem_corrompida = func(mensagem)
        return mensagem_corrompida
    
    else:
        print("Roteador: opção invalida tente,  escolhendo Transparencia por padrão")
        return mensagem


def conection_cliente_router(client_conn, client_addr):
    print(f"Roteador: cliente conectado: endereço {client_addr}")

    try:
        #passo 1 -> recebe a mensagem do cliente 
        data = client_conn.recv(BUFFER_SIZE)
        if not data:
            return
        
        mensagem_cliente = data.decode('utf-8')
        print(f"Roteador: Recebido do cliente: '{mensagem_cliente.strip()}'")
       
        ''' LOGICA DE MODIFICAÇÃO DE MENSAGEM FICA AQUI'''
        mensagem_from_menu = Menu_for_mensagens(mensagem_cliente)
        data_for_server = mensagem_from_menu.encode("utf-8")

        #passo 2 -> conecta com o servirdor para enviar a mensagem
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as server_sock:
            server_sock.connect((SERVER_HOST,SERVER_PORT))
            print(f"Roteador: conectado ao Server {SERVER_HOST}:{SERVER_PORT}")
            
            #encaminha a mensagem do cliente para o servirdor
            server_sock.sendall(data_for_server)
            print("Roteador: mensagem transmitida para o servidor")

            # passo 3 -> recebe a resposta do servidor 
            data_server = server_sock.recv(BUFFER_SIZE)
            resposta_server = data_server.decode('utf-8')
            print(f"Roteador: Recebido do Server: '{resposta_server}'")
            
            #passo 4 -> envia a resposta para o cliente 
            client_conn.sendall(data_server)
            print('Roteador:resposta enviada ao server')

    except Exception as e:
        print(f"Roteador: Erro na comunicação: '{e}'")
        
    finally:
        client_conn.close()
        print(f"Roteador: conexão com o cliente:{client_addr} encerrada")


def start_router():
    #AF_INET = IVP4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((ROUTER_HOST,ROUTER_PORT))
        sock.listen()
        print(f"Roteador: Observando conexões dos clientes em {ROUTER_HOST}:{ROUTER_PORT}")

        while True:
            client_conn, cliente_addr = sock.accept()

            #inicia uma thread para permitir que o roteador lide com os multiplos clientes 
            thread_client = threading.Thread(
                target= conection_cliente_router, 
                args = (client_conn,cliente_addr)
            )
            thread_client.start()

if __name__ == "__main__":
    start_router()







