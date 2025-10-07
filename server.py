import socket

HOST = '127.0.0.1' #endereço ip 
PORT = 8001
BUFFER_SIZE = 1024

def start_server():
    #AF_INET = IVP4, SOCK_STREAM = TCP
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST,PORT))
        sock.listen()
        print(f"SERVER:aguardando conexão com cliente em {HOST}:{PORT}")

        #servidor aceita a conexão com o roteador 
        conn , addr = sock.accept()
        with conn:
            print(f"SERVER: Conectado com {HOST}")

            while True:
                #recebe a mensagem do clinte que passou do router 
                data = conn.recv(BUFFER_SIZE)
                
                if not data:
                    break 
                mensagem_cliente = data.decode('utf-8')
                #strip remove espaços em branco no final
                print(f"Cliente:{mensagem_cliente.strip()}")
                resposta = "Server: Salve de raçã"
                conn.sendall(resposta.encode('utf-8'))
                print('Server: resposta enviada ao cliente')

            print("Conexão encerrada")

if __name__ == "__main__":
    start_server()


