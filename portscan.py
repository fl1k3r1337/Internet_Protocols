#!/usr/bin/env python3
"""
TCP/UDP Port Scanner with protocol detection.
Works on Linux and Windows.

Usage:
    python portscan.py <host> -t -u --start N --count M

Examples:
    python3 portscan.py 127.0.0.1 --tcp --start 1 --count 1000
    python3 portscan.py 127.0.0.1 -t -u --start 1 --count 500
    python3 portscan.py example.com --tcp --udp --start 50 --count 100
"""

import socket
import struct
import sys
import threading
import argparse
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple

# ── Настройки ──────────────────────────────────────────────────────────────

TCP_TIMEOUT    = 1.5
UDP_TIMEOUT    = 3.0
BANNER_TIMEOUT = 1.5
BASE_WORKERS   = 64
RATE_LIMIT     = 0.001   # задержка между задачами (сек)


# ── UDP probes ─────────────────────────────────────────────────────────────

def _dns_probe() -> bytes:
    """Минимальный DNS A-запрос для google.com."""
    return (
        b'\xaa\xbb'                     # Transaction ID
        b'\x01\x00'                     # Flags: standard query + RD
        b'\x00\x01'                     # Questions: 1
        b'\x00\x00\x00\x00\x00\x00'    # Answers / Authority / Additional: 0
        b'\x06google\x03com\x00'        # QNAME
        b'\x00\x01'                     # QTYPE: A
        b'\x00\x01'                     # QCLASS: IN
    )


def _ntp_probe() -> bytes:
    """Минимальный NTPv3 client request."""
    pkt = bytearray(48)
    pkt[0] = 0x1B   # LI=0, VN=3, Mode=3 (client)
    return bytes(pkt)


def _udp_probe(port: int) -> bytes:
    if port == 53:
        return _dns_probe()
    if port == 123:
        return _ntp_probe()
    return b'\x00'


# ── Определение UDP-протокола ──────────────────────────────────────────────

def _detect_udp(port: int, data: bytes) -> Optional[str]:
    # DNS: QR-бит (бит 15 поля флагов) должен быть 1
    if port == 53 and len(data) >= 12:
        flags = struct.unpack('!H', data[2:4])[0]
        if flags & 0x8000:
            return 'DNS'

    # NTP/SNTP: Mode == 4 (server)
    if port == 123 and len(data) >= 48:
        if (data[0] & 0x07) == 4:
            return 'SNTP'

    return None


# ── Определение TCP-протокола ──────────────────────────────────────────────

def _detect_tcp(host: str, port: int) -> Optional[str]:
    """
    Сначала читает баннер (многие протоколы говорят первыми),
    затем делает HTTP-probe если баннера нет.
    """
    banner = b''
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT) as s:
            s.settimeout(BANNER_TIMEOUT)
            try:
                banner = s.recv(1024)
                print(banner.decode('utf-8'))
            except socket.timeout:
                pass
    except Exception:
        return None

    if banner:
        b = banner.lower()
        if b.startswith(b'http/'):
            return 'HTTP'
        if b.startswith(b'220'):
            return 'FTP' if b'ftp' in b else 'SMTP'
        if b.startswith(b'+ok'):
            return 'POP3'
        if b.startswith(b'* ok'):
            return 'IMAP'
        if b.startswith(b'ssh-'):
            return 'SSH'

    # HTTP fallback для серверов, которые ждут запроса первыми
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT) as s:
            s.sendall(b'HEAD / HTTP/1.0\r\nHost: ' + host.encode() + b'\r\n\r\n')
            s.settimeout(BANNER_TIMEOUT)
            data = s.recv(256)
            if data.lower().startswith(b'http/'):
                return 'HTTP'
    except Exception:
        pass

    return None


# ── TCP scan ───────────────────────────────────────────────────────────────

def scan_tcp(host: str, port: int) -> Optional[Tuple[str, int, Optional[str]]]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TCP_TIMEOUT)
            if s.connect_ex((host, port)) != 0:
                return None

        proto = _detect_tcp(host, port)
        return ('TCP', port, proto)

    except PermissionError:
        _warn_permission('TCP', port)
        return None
    except Exception:
        return None


# ── UDP scan ───────────────────────────────────────────────────────────────

def scan_udp(host: str, port: int) -> Optional[Tuple[str, int, Optional[str]]]:
    """
    Использует connect() + send() + recv() вместо sendto/recvfrom.
    Это необходимо для корректной обработки ICMP Port Unreachable
    как на Linux, так и на Windows.

    Исходы:
      - Пришёл ответ              → порт открыт
      - ConnectionRefusedError    → ICMP port-unreachable → закрыт
      - Timeout                   → open|filtered, пропускаем (→ None)
    """
    probe = _udp_probe(port)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(UDP_TIMEOUT)
            s.connect((host, port))   # нужен для получения ICMP-ошибок на Windows
            s.send(probe)
            try:
                data = s.recv(1024)
                print(data.decode('utf-8'))
                proto = _detect_udp(port, data)
                return ('UDP', port, proto)
            except socket.timeout:
                # open|filtered — не можем различить, пропускаем
                return None

    except ConnectionRefusedError:
        # ICMP port-unreachable → порт точно закрыт
        return None
    except PermissionError:
        _warn_permission('UDP', port)
        return None
    except Exception:
        return None


# ── Вывод и утилиты ────────────────────────────────────────────────────────

def _warn_permission(kind: str, port: int) -> None:
    print(
        f"Недостаточно прав для сканирования {kind} порта {port}. "
        f"Попробуйте запустить с правами администратора.",
        file=sys.stderr,
    )


def _print_result(kind: str, port: int, proto: Optional[str]) -> None:
    line = f"{kind} {port} {proto}" if proto else f"{kind} {port}"
    sys.stdout.write(line + '\r\n')
    sys.stdout.flush()


# ── MAIN ───────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description='TCP/UDP port scanner with protocol detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  %(prog)s 127.0.0.1 --tcp --start 1 --count 1000\n'
            '  %(prog)s 127.0.0.1 -t -u --start 1 --count 200\n'
            '  %(prog)s example.com --tcp --udp --start 50 --count 100'
        ),
    )
    parser.add_argument('host', help='Target IP address or hostname')
    parser.add_argument('--tcp', '-t', action='store_true', help='Scan TCP ports')
    parser.add_argument('--udp', '-u', action='store_true', help='Scan UDP ports')
    parser.add_argument('--start', type=int, default=1, metavar='N',
                        help='First port in range (default: 1)')
    parser.add_argument('--count', type=int, default=100, metavar='M',
                        help='Number of ports to scan (default: 100)')
    args = parser.parse_args()

    # ── Валидация ──────────────────────────────────────────────────────────
    if not args.tcp and not args.udp:
        parser.error('Укажите хотя бы один протокол для сканирования: --tcp или --udp')

    if not (1 <= args.start <= 65535):
        parser.error('--start должен быть в диапазоне 1–65535')

    if args.count < 1:
        parser.error('--count должен быть >= 1')

    end_port = args.start + args.count - 1
    if end_port > 65535:
        parser.error(f'Диапазон выходит за пределы: последний порт {end_port} > 65535')

    # ── Резолвинг хоста ────────────────────────────────────────────────────
    try:
        host_ip = socket.gethostbyname(args.host)
    except socket.gaierror as exc:
        print(f"Не удалось разрешить имя хоста «{args.host}»: {exc}", file=sys.stderr)
        sys.exit(1)

    ports = range(args.start, args.start + args.count)
    num_protocols = args.tcp + args.udp
    max_workers = min(BASE_WORKERS, len(ports) * num_protocols)

    results = []
    lock = threading.Lock()

    def worker(kind: str, port: int) -> None:
        time.sleep(RATE_LIMIT)
        res = scan_tcp(host_ip, port) if kind == 'TCP' else scan_udp(host_ip, port)
        if res is not None:
            with lock:
                results.append(res)

    tasks = []
    if args.tcp:
        tasks += [('TCP', p) for p in ports]
    if args.udp:
        tasks += [('UDP', p) for p in ports]

    print(
        f"Сканирование {args.host} ({host_ip}), "
        f"порты {args.start}–{end_port} "
        f"({'TCP' if args.tcp else ''}{'+'  if args.tcp and args.udp else ''}{'UDP' if args.udp else ''}) ...",
        file=sys.stderr,
    )

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(worker, k, p) for k, p in tasks]
        try:
            for f in as_completed(futures):
                f.result()
        except KeyboardInterrupt:
            print("\nПрервано пользователем.", file=sys.stderr)
            sys.exit(0)

    # Сортировка: по номеру порта, TCP перед UDP
    results.sort(key=lambda x: (x[1], 0 if x[0] == 'TCP' else 1))

    for kind, port, proto in results:
        _print_result(kind, port, proto)

    if not results:
        print("Открытых портов не обнаружено.", file=sys.stderr)


if __name__ == '__main__':
    main()