import socket
import struct
import sys
import time
import ipaddress
import platform

from Color import Color

MAX_HOPS = 30
TIMEOUT = 2
# PORT = 33434
PORT = 55203

def is_local(ip):
    ip_obj = ipaddress.ip_address(ip)
    return ip_obj.is_private or ip_obj.is_loopback

def whois_query(server, query):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server, 43))

    sock.sendall((query + "\r\n").encode())

    response = b""

    while True:
        data = sock.recv(4096)
        if not data:
            break
        response += data

    sock.close()

    return response.decode(errors="ignore")

def get_whois_server(ip):
    response = whois_query("whois.iana.org", ip)

    for line in response.splitlines():
        if "refer" in line.lower():
            return line.split(":")[1].strip()

    return "whois.ripe.net"

def get_whois_info(ip):
    server = get_whois_server(ip)

    response = whois_query(server, ip)

    netname = None
    country = None
    asn = None

    for line in response.splitlines():
        l = line.lower()

        if netname is None and "netname" in l:
            netname = line.split(":")[1].strip()

        if country is None and "country" in l:
            country = line.split(":")[1].strip()

        if asn is None and "origin" in l:
            asn = line.split(":")[1].strip().upper().replace("AS", "")

    return netname, asn, country


def format_whois(netname, asn, country):
    parts = []

    if netname:
        parts.append(netname)

    if asn:
        parts.append(asn)

    if country and "EU" not in country:
        parts.append(country)

    return ", ".join(parts)

def traceroute(dest_name):

    if platform.system() == "Windows":
        IPPROTO_IP = socket.IPPROTO_IP
    else:
        IPPROTO_IP = socket.SOL_IP

    try:
        dest_addr = socket.gethostbyname(dest_name)   #dns запрос
    except socket.gaierror:  #домен не существует
        print(f"{dest_name} is invalid")
        return

    print(f"traceroute to {dest_name} ({dest_addr})")

    for ttl in range(1, MAX_HOPS + 1):
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        recv_socket.settimeout(TIMEOUT)

        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        # send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        send_socket.setsockopt(IPPROTO_IP, socket.IP_TTL, ttl)

        send_socket.bind(("", PORT))
        # recv_socket.bind(("", PORT))

        curr_addr = None
        icmp_type = None

        try:
            send_socket.sendto(b"", (dest_name, PORT + ttl))
            # start = time.time()

            data, addr = recv_socket.recvfrom(512)
            # elapsed = (time.time() - start) * 1000

            curr_addr = addr[0]  # адрес текущего узла

            icmp_header = data[20:28]
            icmp_type, code, checksum = struct.unpack("!BBH", icmp_header[:4])  # два 1-байтовых и одно 2-байтовое

        except socket.timeout:
            pass
        except KeyboardInterrupt:
            print("\nПрограмма остановлена")
            break
        finally:
            send_socket.close()
            recv_socket.close()

        print(f"{ttl}. ", end="")

        if curr_addr is None:
            print("*")
        else:
            # print(curr_addr)
            if is_local(curr_addr):
                print(curr_addr, "local")
            else:
                netname, asn, country = get_whois_info(curr_addr)
                print(curr_addr, format_whois(netname, asn, country))

        if icmp_type == 3:  #Destination Unreachable
            break


# def print_banner():
#     print("""
#         ████████╗██████╗  █████╗  ██████╗███████╗██████╗  ██████╗ ██╗   ██╗████████╗███████╗
#         ╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗██╔═══██╗██║   ██║╚══██╔══╝██╔════╝
#            ██║   ██████╔╝███████║██║     █████╗  ██████╔╝██║   ██║██║   ██║   ██║   █████╗
#            ██║   ██╔══██╗██╔══██║██║     ██╔══╝  ██╔══██╗██║   ██║██║   ██║   ██║   ██╔══╝
#            ██║   ██║  ██║██║  ██║╚██████╗███████╗██║  ██║╚██████╔╝╚██████╔╝   ██║   ███████╗
#            ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝    ╚═╝   ╚══════╝
#         """)

def print_banner():
    BANNER = r"""
__/\\\\\\\\\\\\\\\____/\\\\\\\\\_________/\\\\\\\\\___________/\\\\\\\\\__/\\\\\\\\\\\\\\\____/\\\\\\\\\______/\\\\\\\\\\\\\\\_        
 _\///////\\\/////___/\\\///////\\\_____/\\\\\\\\\\\\\______/\\\////////__\/\\\///////////___/\\\///////\\\___\///////\\\/////__       
  _______\/\\\_______\/\\\_____\/\\\____/\\\/////////\\\___/\\\/___________\/\\\_____________\/\\\_____\/\\\_________\/\\\_______      
   _______\/\\\_______\/\\\\\\\\\\\/____\/\\\_______\/\\\__/\\\_____________\/\\\\\\\\\\\_____\/\\\\\\\\\\\/__________\/\\\_______     
    _______\/\\\_______\/\\\//////\\\____\/\\\\\\\\\\\\\\\_\/\\\_____________\/\\\///////______\/\\\//////\\\__________\/\\\_______    
     _______\/\\\_______\/\\\____\//\\\___\/\\\/////////\\\_\//\\\____________\/\\\_____________\/\\\____\//\\\_________\/\\\_______   
      _______\/\\\_______\/\\\_____\//\\\__\/\\\_______\/\\\__\///\\\__________\/\\\_____________\/\\\_____\//\\\________\/\\\_______  
       _______\/\\\_______\/\\\______\//\\\_\/\\\_______\/\\\____\////\\\\\\\\\_\/\\\\\\\\\\\\\\\_\/\\\______\//\\\_______\/\\\_______ 
        _______\///________\///________\///__\///________\///________\/////////__\///////////////__\///________\///________\///________
        """  # noqa: E501

    print(f"{Color.RED}{BANNER}{Color.RESET}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"usage: python3 tracert.py <host>")
        sys.exit(1)

    print_banner()

    try:
        traceroute(sys.argv[1])
    except PermissionError:
        print("Not enough privileges to create raw socket. Run with sudo.")
