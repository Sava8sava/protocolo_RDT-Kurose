import socket

ROUTER_HOST = '127.0.0.1' #endereço ip 
ROUTER_PORT = 12345
BUFFER_SIZE = 1024

def start_client():
    mensagem = input("Cliente: Digite a mensagem para o servidor: ")

    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
        try:
            #ativar essa linha caso mudem pra TCP
            #sock.connect((ROUTER_HOST,ROUTER_PORT)) 
        
            sock.sendto(mensagem.encode('utf-8'),(ROUTER_HOST,ROUTER_PORT))
            print("Cliente: mensagem enviada ao servidor")
            
            #aguarda resposta
            sock.settimeout(5)
            #recebe a resposta do servidor 

            data , addr = sock.recvfrom(BUFFER_SIZE)
            print(f"Cliente: Resposta recebida do server({addr}): {data.decode('utf-8')}")

        except socket.timeout:
            print("Cliente: Limite de tempo atingindo")
        except Exception as e:
            print(f"Cliente: Erro: '{e}'")

if __name__ == "__main__":
    start_client()

