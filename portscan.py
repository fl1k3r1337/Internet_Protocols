import struct
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import socket
import sys


def dns_request():
    return (
        b"\xaa\xbb"
        b"\x01\x00"
        b"\x00\x01"
        b"\x00\x00\x00\x00\x00\x00"
        b"\x06google\x03com\x00"
        b"\x00\x01"
        b"\x00\x01"
    )


def ntp_probe():
    pkt = bytearray(48)
    pkt[0] = 0x1B
    return bytes(pkt)


def get_udp_probe(port):
    if port == 53:
        return dns_request()
    if port == 123:
        return ntp_probe()
    return b"\x00"


def detect_udp(data):
    if len(data) >= 12:
        flags = struct.unpack("!H", data[2:4])[0]
        if flags & 0x8000:  # dns-ответ
            return "DNS"

    if len(data) >= 48:
        if (data[0] & 0x07) == 4:  # 4 - server
            return "NTP"

    return None

def scan_udp(host, port):
    try:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            sock.connect((host, port))
            probe = dns_request()
            sock.send(probe)

            data = sock.recv(1024)
            sock.close()
            if len(data) >= 12:
                flags = struct.unpack("!H", data[2:4])[0]
                if flags & 0x8000:  # dns-ответ
                    return "UDP", port, "DNS"
        except Exception:
            pass
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            sock.connect((host, port))
            probe = ntp_probe()
            sock.send(probe)

            data = sock.recv(1024)
            sock.close()
            if len(data) >= 48:
                if (data[0] & 0x07) == 4:  # 4 - server
                    return "NTP"
            return "UDP", port, "NTP"

        except Exception:
            pass
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)

            sock.connect((host, port))
            probe = b"\x00"
            sock.send(probe)

            data = sock.recv(1024)
            sock.close()
            if data:
                return "UDP", port, ""
        except Exception:
            pass

    except ConnectionRefusedError:
        return None

    except Exception:
        return None



# def scan_udp(host, port):
#     try:
#         sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#         sock.settimeout(3)
#
#         sock.connect((host, port))
#         probe = get_udp_probe(port)
#         sock.send(probe)
#
#         try:
#             data = sock.recv(1024)
#             sock.close()
#             proto = detect_udp(data)
#             return "UDP", port, proto
#         except socket.timeout:
#             sock.close()
#             return None
#
#     except ConnectionRefusedError:
#         return None
#
#     except Exception:
#         return None


def detect_tcp(host, port):
    # if port not in [21, 22, 25, 80, 110, 143]:
    #     return None

    banner = b""

    try:
        sock = socket.create_connection((host, port), timeout=1.5)
        sock.settimeout(3)

        try:
            banner = sock.recv(1024)
        except socket.timeout:
            pass

        sock.close()
    except Exception:
        return None

    if banner:
        b = banner.lower()

        if b.startswith(b"220"):
            if b"ftp" in b:
                return "FTP"
            return "SMTP"

        if b.startswith(b"+ok"):
            return "POP3"

        if b.startswith(b"* ok"):
            return "IMAP"

        if b.startswith(b"ssh-"):
            return "SSH"

    try:
        sock = socket.create_connection((host, port), timeout=2)

        request = b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n"
        sock.send(request)

        sock.settimeout(3)
        data = sock.recv(512)

        sock.close()

        if b"http/" in data.lower() or b"server" in data.lower():
            return "HTTP"

    except Exception:
        pass

    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.send(b"EHLO test \r\n")

        sock.settimeout(3)
        data = sock.recv(512)
        sock.close()

        if b"smtp" in data.lower() or data.startswith(b"250"):
            return "SMTP"
    except Exception:
        pass

    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.send(b"USER test \r\n")

        sock.settimeout(3)
        data = sock.recv(512)
        sock.close()

        if b"+ok" in data.lower():
            return "POP3"

    except Exception:
        pass

    try:
        sock = socket.create_connection((host, port), timeout=2)
        sock.send(b"a1 CAPABILITY\r\n")

        sock.settimeout(3)
        data = sock.recv(512)
        sock.close()

        if b"* capability" in data.lower():
            return "IMAP"

    except Exception:
        pass

    return None


def scan_tcp(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)

        if sock.connect_ex((host, port)) != 0:
            sock.close()
            return None

        sock.close()

        proto = detect_tcp(host, port)
        return "TCP", port, proto

    except Exception:
        return None


def parse_args():
    parser = argparse.ArgumentParser(description="Port scanner")

    parser.add_argument("host", help="IP-адрес или домен")
    parser.add_argument(
        "-t", "--tcp", action="store_true", help="Сканировать tcp порты"
    )
    parser.add_argument(
        "-u", "--udp", action="store_true", help="Сканировать udp порты"
    )
    parser.add_argument("--start", type=int, default=1, help="Начальный порт")
    parser.add_argument("--count", type=int, default=100, help="Количество портов")

    return parser.parse_args()


def validate_args(args):
    if not args.tcp and not args.udp:
        print("Укажите --tcp(-t) и/или --udp(-u)", file=sys.stderr)
        sys.exit(1)

    if not (1 <= args.start <= 65535):
        print("Некорректный начальный порт", file=sys.stderr)
        sys.exit(1)

    if args.count < 1:
        print("count должен быть >= 1", file=sys.stderr)
        sys.exit(1)

    if args.start + args.count - 1 > 65535:
        print("Диапазон выходит за пределы портов", file=sys.stderr)
        sys.exit(1)


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Не удалось разрешить хост {host}", file=sys.stderr)
        sys.exit(1)


def main():
    args = parse_args()
    validate_args(args)

    host_ip = resolve_host(args.host)
    ports = list(range(args.start, args.start + args.count))

    print(f"Сканируем {args.host} ({host_ip}) порты {args.start}-{ports[-1]}")

    results = []

    if args.tcp:
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = []

            for port in ports:
                futures.append(executor.submit(scan_tcp, host_ip, port))

            for future in as_completed(futures):
                try:
                    res = future.result()
                except Exception:
                    continue
                if res:
                    results.append(res)

    if args.udp:
        with ThreadPoolExecutor(max_workers=64) as executor:
            futures = []

            for port in ports:
                futures.append(executor.submit(scan_udp, host_ip, port))

            for future in as_completed(futures):
                try:
                    res = future.result()
                except Exception:
                    continue
                if res:
                    results.append(res)

    results.sort(key=lambda x: (x[1], 0 if x[0] == "TCP" else 1))

    if len(results) == 0:
        print("Открытых портов не обнаружено")
    else:
        for kind, port, proto in results:
            if proto:
                print(f"{kind} {port} {proto}")
            else:
                print(f"{kind} {port}")


if __name__ == "__main__":
    main()


# Отказаться от нумерации портов,