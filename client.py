import socket

def create_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    host = '127.0.0.1'  # 'localhost'
    port = 53000
    
    try:
        client_socket.connect((host, port))
        print(f"Server {host}:{port}")
        
        while True:
            message = input("Enter a message: ")
            
            if message.lower() == 'exit':
                break
                
            client_socket.send(message.encode('utf-8'))
            
            response = client_socket.recv(1024)
            print(f"Server responce: {response.decode('utf-8')}")
            
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Socket is closed")

if __name__ == "__main__":
    create_client()
