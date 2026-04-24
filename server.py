import socket
import threading

def handle_arifmetic_operation(message):
    operation = ''
    for oper in '+-*/':
        if oper in message:
            operation = oper
            break

    if operation == '':
        return f"{message} + server = love"

    match operation:
        case '+':
            operands = message.split('+')
            operands = [int(operand) for operand in operands]
            return str(operands[0] + operands[1])

        case '-':
            operands = message.split('-')
            operands = [int(operand) for operand in operands]
            return str(operands[0] - operands[1])

        case '*':
            operands = message.split('*')
            operands = [int(operand) for operand in operands]
            return str(operands[0] * operands[1])

        case '/':
            operands = message.split('/')
            operands = [int(operand) for operand in operands]
            return str(operands[0] / operands[1])


def handle_client(client_socket, client_address):
    try:
        while True:
            data = client_socket.recv(1024)
            if not data:
                break

            message = data.decode('utf-8')
            print(f"Client {client_address} message: {message}")

            try:
                response = handle_arifmetic_operation(message)
            except Exception as e:
                response = f"Error: {e}"

            client_socket.send(response.encode('utf-8'))

    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()
        print("Socket is closed")


def create_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # host = '10.249.16.44'
    host = '127.0.0.1'  # 'localhost'
    port = 53000
    server_socket.bind((host, port))

    server_socket.listen(5)
    print(f"Server {host}:{port}")
    print("Wait...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print(f"Client: {client_address}")

            client_thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address)
            )

            client_thread.daemon = True
            client_thread.start()

            print(f'Active threads: {threading.active_count() - 1}')

    except Exception as e:
        print(f"Error: {e}")
    finally:
        server_socket.close()


if __name__ == "__main__":
    create_server()
