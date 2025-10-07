import socket

ROUTER_HOST = '127.0.0.1' #endereço ip 
ROUTER_PORT = 8000
BUFFER_SIZE = 1024

def start_client():
    mensagem = input("Cliente: Digite a mensagem para o servidor: ")

    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
        try:
            #cliente se conecta ao roteador
            sock.connect((ROUTER_HOST,ROUTER_PORT))
        
            sock.sendall(mensagem.encode('utf-8'))
            print("Cliente: mensagem enviada ao servidor")
            
            #recebe a resposta do servidor 
            data = sock.recv(BUFFER_SIZE)
            print(f"Cliente: Resposta recebida do server: {data.decode('utf-8')}")
        except ConnectionRefusedError:
            print("Cliente: Erro de conexão")
        except Exception as e:
            print(f"Cliente: Erro: '{e}'")

if __name__ == "__main__":
    start_client()

