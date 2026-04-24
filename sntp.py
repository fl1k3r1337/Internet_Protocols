#!/usr/bin/env python3
"""
SNTP «обманывающий» сервер времени.

Запуск:
    python sntp.py -d 5        # сервер добавляет 5 секунд к текущему времени
    python sntp.py -d -3600    # сервер отнимает 1 час
    python sntp.py -d 0 -p 123 # стандартный NTP-порт (требует root)

Проверка:
    ntpdate -d -q localhost
    rdate -u -n -v -p localhost
"""

import argparse
import socket
import struct
import time
import logging
from concurrent.futures import ThreadPoolExecutor

# ─── Константы ────────────────────────────────────────────────────────────────

# Разница между NTP-эпохой (1 янв 1900) и Unix-эпохой (1 янв 1970), секунды
NTP_DELTA = 2_208_988_800

DEFAULT_PORT      = 123
THREAD_POOL_SIZE  = 16   # максимальное число одновременных обработчиков
RECV_BUF          = 1024  # размер буфера приёма UDP

# Биты LI/VN/Mode (первый байт NTP-пакета)
NTP_MODE_CLIENT = 3
NTP_MODE_SERVER = 4

# ─── Работа с временны́ми метками ─────────────────────────────────────────────

def unix_to_ntp(unix_ts: float) -> int:
    """
    Преобразует Unix-время (float, секунды) в 64-битную NTP-метку:
      старшие 32 бита — целые секунды с 1900-01-01
      младшие 32 бита — дробная часть секунды (2^32 долей)
    """
    ntp_ts   = unix_ts + NTP_DELTA
    seconds  = int(ntp_ts)
    fraction = int((ntp_ts - seconds) * (2 ** 32))
    return (seconds << 32) | (fraction & 0xFFFF_FFFF)


# ─── Разбор входящего пакета ──────────────────────────────────────────────────

def parse_ntp_packet(data: bytes) -> dict | None:
    """
    Разбирает NTP-пакет (минимум 48 байт).
    Возвращает словарь с полями или None, если пакет некорректен.

    Структура пакета (RFC 4330):
      0      : LI(2) | VN(3) | Mode(3)
      1      : Stratum
      2      : Poll
      3      : Precision  (знаковый байт)
      4-7    : Root Delay (16.16 fixed-point)
      8-11   : Root Dispersion
      12-15  : Reference Identifier
      16-23  : Reference Timestamp (64-bit NTP)
      24-31  : Originate Timestamp
      32-39  : Receive Timestamp
      40-47  : Transmit Timestamp
    """
    if len(data) < 48:
        return None

    unpacked = struct.unpack("!B B b b I I 4s Q Q Q Q", data[:48])
    byte0 = unpacked[0]

    return {
        "li"       : (byte0 >> 6) & 0x3,
        "vn"       : (byte0 >> 3) & 0x7,
        "mode"     : byte0 & 0x7,
        "stratum"  : unpacked[1],
        "poll"     : unpacked[2],
        "precision": unpacked[3],
        "root_delay"     : unpacked[4],
        "root_dispersion": unpacked[5],
        "ref_id"         : unpacked[6],
        "ref_ts"         : unpacked[7],
        "orig_ts"        : unpacked[8],
        "recv_ts"        : unpacked[9],
        "transmit_ts"    : unpacked[10],
    }


# ─── Формирование ответа ──────────────────────────────────────────────────────

def build_ntp_response(client_transmit_ts: int, delay: int) -> bytes:
    """
    Собирает NTP-ответ (Mode 4 — server).

    client_transmit_ts — поле Transmit Timestamp из запроса клиента;
                         оно копируется в Originate Timestamp ответа,
                         чтобы клиент мог верифицировать ответ.
    delay              — смещение, добавляемое к текущему времени (секунды).
    """
    now_real = time.time()          # реальное время (для Receive Timestamp)
    now_fake = now_real + delay     # «обманное» время

    # Byte 0: LI=0 (нет предупреждения), VN=4, Mode=4 (server)
    li_vn_mode = (0 << 6) | (4 << 3) | NTP_MODE_SERVER

    # Stratum 1 — первичный эталон (LOCL = local clock)
    stratum   = 1
    poll      = 4       # интервал опроса — 2^4 = 16 с
    precision = -20     # точность ≈ 2^-20 с ≈ 1 мкс (знаковый байт)

    root_delay      = 0  # задержка до эталона (мы и есть эталон)
    root_dispersion = 0  # разброс (мы и есть эталон)
    ref_id          = b"LOCL"  # идентификатор источника

    ref_ts      = unix_to_ntp(now_fake)   # Reference  — когда обновлялись
    orig_ts     = client_transmit_ts      # Originate  — из запроса клиента
    recv_ts     = unix_to_ntp(now_real)   # Receive    — реальный момент приёма
    transmit_ts = unix_to_ntp(now_fake)   # Transmit   — «обманное» время отправки

    return struct.pack(
        "!B B b b I I 4s Q Q Q Q",
        li_vn_mode,
        stratum,
        poll,
        precision,
        root_delay,
        root_dispersion,
        ref_id,
        ref_ts,
        orig_ts,
        recv_ts,
        transmit_ts,
    )


# ─── Обработка одного запроса (выполняется в пуле потоков) ───────────────────

def handle_request(sock: socket.socket, data: bytes,
                   addr: tuple, delay: int) -> None:
    client_ip, client_port = addr
    logging.info("Запрос от %s:%d", client_ip, client_port)

    packet = parse_ntp_packet(data)
    if packet is None:
        logging.warning("Слишком короткий пакет от %s — игнорируем", client_ip)
        return

    # Принимаем только клиентские запросы (Mode == 3)
    if packet["mode"] != NTP_MODE_CLIENT:
        logging.warning(
            "Неверный Mode=%d от %s — ожидается %d (client)",
            packet["mode"], client_ip, NTP_MODE_CLIENT,
        )
        return

    response = build_ntp_response(packet["transmit_ts"], delay)

    # sendto безопасен для UDP из нескольких потоков одновременно
    sock.sendto(response, addr)
    logging.info(
        "Ответ отправлен %s (смещение %+d с, фиктивное время: %s)",
        client_ip,
        delay,
        time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(time.time() + delay)),
    )


# ─── Главный цикл сервера ─────────────────────────────────────────────────────

def run_server(port: int, delay: int) -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("", port))

        logging.info("SNTP-сервер запущен на порту %d", port)
        logging.info(
            "Смещение времени: %+d с  |  пул потоков: %d",
            delay, THREAD_POOL_SIZE,
        )

        with ThreadPoolExecutor(max_workers=THREAD_POOL_SIZE,
                                thread_name_prefix="sntp-worker") as pool:
            while True:
                try:
                    data, addr = sock.recvfrom(RECV_BUF)
                    pool.submit(handle_request, sock, data, addr, delay)
                except KeyboardInterrupt:
                    logging.info("Сервер остановлен.")
                    break
                except OSError as exc:
                    logging.error("Ошибка сокета: %s", exc)


# ─── Точка входа ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SNTP-сервер, добавляющий смещение к текущему времени.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-d", "--delay",
        type=int, default=0, metavar="N",
        help="смещение времени в секундах (по умолчанию 0)",
    )
    parser.add_argument(
        "-p", "--port",
        type=int, default=DEFAULT_PORT, metavar="PORT",
        help=f"порт UDP для прослушивания (по умолчанию {DEFAULT_PORT})",
    )
    args = parser.parse_args()
    run_server(args.port, args.delay)


if __name__ == "__main__":
    main()