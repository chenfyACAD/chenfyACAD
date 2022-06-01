import ipaddress
import socket
import sys
import threading
import time
from collections import defaultdict

LOCAL_HOST = "127.0.0.1"
BUFFER_SIZE = 1024
RESERVED_BITS = 0
PACKET_SIZE = 1500
UDP_PACKET_SIZE = 55296

# Modes
DISCOVERY = 0x01
OFFER = 0x02
REQUEST = 0x03
ACK = 0x04
ASK = 0x06
DATA = 0x05
READY = 0x07
LOCATION = 0x08
DISTANCE = 0x09
MORE_FRAG = 0x0a
END_FRAG = 0x0b
INVALID = 0x00

lock = threading.Lock()


def add_distance_to_packet(packet, distance):
    if distance > 1000:
        packet.append(1)
        packet.append(0)
        packet.append(0)
        packet.append(0)
    else:
        packet.append(0)
        packet.append(0)
        packet.append(distance // 256)
        packet.append(distance % 256)
    return packet


def get_distance(x2, x1, y2, y1):
    return int(((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5)


def create_packet(mode, source_ip, dest_ip, data):
    packet = bytearray()
    # append source ip
    for elem in socket.inet_aton(source_ip):
        packet.append(elem)
    # append dest ip
    for elem in socket.inet_aton(dest_ip):
        packet.append(elem)
    # append reserve
    for _ in range(3):
        packet.append(RESERVED_BITS)
    # append mode
    packet.append(mode)
    # append data
    try:
        socket.inet_aton(data)
    except:
        # latitude and longitude
        for number in data:
            packet.append(number // 256)
            packet.append(number % 256)
    else:
        # append assigned address
        for elem in socket.inet_aton(data):
            packet.append(elem)
    return packet


def check_pos_int(number):
    try:
        integer = int(number)
        if integer < 0:
            return False
        else:
            return True
    except:
        return False


def check_ip(ip):
    if len(ip) - len(ip.replace("/", "")) != 1:
        return False
    else:
        CIDR_part = ip.split("/")[1]
        try:
            integer = int(CIDR_part)
            if integer <= 0 or integer > 32:
                return False
        except:
            return False
    if len(ip) - len(ip.replace(".", "")) != 3:
        return False
    else:
        IP_part = ip.split("/")[0]
        for number in IP_part.split("."):
            try:
                integer = int(number)
                if integer < 0 or integer > 255:
                    return False
            except:
                return False
    return True


def get_next_ip(ip):
    addr_parts = ip.split(".")
    final_part = addr_parts[3]
    change = int(final_part) + 1
    point = '.'
    addr_parts[3] = str(change)
    return point.join(addr_parts)


def get_ip_pool(ip, mask):
    pool = list()
    if mask > 23:
        pass
    return pool


def fragmentation(packet):
    packets = list()
    if len(packets) > 1500:
        header = packet[:12]
        datas = packet[12:]
        slices = len(datas) // 1488
        header[11] = MORE_FRAG
        for _ in range(slices):
            data = datas[:1488]
            packet = header + data
            packets.append(packet)
        packets[-1][11] = END_FRAG
    else:
        packets.append(packet)
    return packets


class Switch:
    def __init__(self):
        self.argument = sys.argv[1:]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.local_ip = None  # for the switch listening udp
        self.local_mask = None
        self.num_local_ips = None  # the number of IPs available for allocation
        self.current_local_ip = None  # IP currently available for assignment

        self.global_ip = None  # for the switch listening tcp
        self.global_mask = None
        self.num_global_ips = None  # the number of IPs available for allocation
        self.current_global_ip = None  # ip currently available for assignment

        self.location = list()
        self.adapters = defaultdict(list)
        self.switches = defaultdict(list)

    def choose_switch_type(self):
        if self.argument[0] == "local":
            if len(self.argument) == 4:
                if check_ip(self.argument[1]) and check_pos_int(self.argument[2]) and check_pos_int(self.argument[3]):
                    self.run_udp()
            elif len(self.argument) == 5:
                if check_ip(self.argument[1]) and check_ip(self.argument[2]) and check_pos_int(self.argument[3]) \
                        and check_pos_int(self.argument[4]):
                    self.run_udp_tcp()
        elif self.argument[0] == "global":
            if len(self.argument) == 4:
                if check_ip(self.argument[1]) and check_pos_int(self.argument[2]) and check_pos_int(self.argument[3]):
                    self.run_tcp()

    def run_udp(self):
        self.udp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)

        self.local_ip = self.argument[1].split("/")[0]
        self.local_mask = self.argument[1].split("/")[1]
        self.num_local_ips = 2 ** (32 - int(self.local_mask)) - int(self.local_ip.split(".")[3]) - 1
        self.current_local_ip = get_next_ip(self.local_ip)

        self.location = [int(self.argument[2]), int(self.argument[3])]

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()

        self.udp_listener()

    # does not have "connect" command
    def run_udp_tcp(self):
        self.udp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)

        self.local_ip = self.argument[1].split("/")[0]
        self.local_mask = self.argument[1].split("/")[1]
        self.num_local_ips = 2 ** (32 - int(self.local_mask)) - int(self.local_ip.split(".")[3]) - 1
        self.current_local_ip = get_next_ip(self.local_ip)

        self.tcp.bind((LOCAL_HOST, 0))
        self.tcp.listen()
        print(self.tcp.getsockname()[1], flush=True)

        self.global_ip = self.argument[2].split("/")[0]
        self.global_mask = self.argument[2].split("/")[1]
        self.num_global_ips = 2 ** (32 - int(self.global_mask)) - int(self.global_ip.split(".")[3]) - 1
        self.current_global_ip = get_next_ip(self.global_ip)

        self.location = [int(self.argument[3]), int(self.argument[4])]

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()
        tcp = threading.Thread(target=self.tcp_listener)
        tcp.start()
        udp = threading.Thread(target=self.udp_listener)
        udp.start()

    def run_tcp(self):
        self.tcp.bind((LOCAL_HOST, 0))
        self.tcp.listen()
        print(self.tcp.getsockname()[1], flush=True)

        self.global_ip = self.argument[1].split("/")[0]
        self.global_mask = self.argument[1].split("/")[1]
        self.num_global_ips = 2 ** (32 - int(self.global_mask)) - int(self.global_ip.split(".")[3]) - 1
        self.current_global_ip = get_next_ip(self.global_ip)

        self.location = [int(self.argument[2]), int(self.argument[3])]

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()
        self.tcp_listener()

    def udp_listener(self):
        while True:
            packet, address = self.udp.recvfrom(UDP_PACKET_SIZE)
            if len(packet):
                port = address[1]
                mode = packet[11]
                if port not in self.adapters.keys():
                    if mode == 1 and len(self.adapters) < self.num_local_ips:
                        offer = create_packet(OFFER, source_ip=self.local_ip, dest_ip='0.0.0.0',
                                              data=self.current_local_ip)
                        self.udp.sendto(offer, address)
                        self.adapters[port].append(self.current_local_ip)
                        self.current_local_ip = get_next_ip(self.current_local_ip)
                else:
                    if mode == 3:
                        ip = str(ipaddress.IPv4Address(int.from_bytes(packet[12:16], byteorder='big')))
                        if ip == self.adapters[port][0]:
                            ack = create_packet(ACK, source_ip=self.local_ip, dest_ip=ip, data=ip)
                            self.udp.sendto(ack, address)
                            self.adapters[port].append("DONE")
                    if self.adapters[port][1] == "DONE":
                        if mode == 5:
                            print(packet)

                            pass

    def tcp_listener(self):
        while True:
            client, address = self.tcp.accept()
            new_connect = threading.Thread(target=self.tcp_greeting, args=(client, address))
            new_connect.start()

    def tcp_greeting(self, client, address):
        while True:
            packet = client.recv(PACKET_SIZE)
            if len(packet):
                source = str(ipaddress.IPv4Address(int.from_bytes(packet[:4], byteorder='big')))
                dest = str(ipaddress.IPv4Address(int.from_bytes(packet[4:8], byteorder='big')))
                RESERVED = str(ipaddress.IPv4Address(int.from_bytes(packet[8:11], byteorder='big')))
                mode = packet[11]
                data = str(ipaddress.IPv4Address(int.from_bytes(packet[12:], byteorder='big')))
                if mode == 1:
                    tcp_offer = create_packet(OFFER, source_ip=self.global_ip, dest_ip='0.0.0.0',
                                              data=self.current_global_ip)
                    client.send(tcp_offer)
                    self.current_global_ip = get_next_ip(self.current_global_ip)
                elif mode == 3:
                    ip = data
                    ack = create_packet(ACK, self.global_ip, ip, ip)
                    client.send(ack)
                elif mode == 8:
                    ip = source
                    position = create_packet(LOCATION, self.global_ip, ip, self.location)
                    client.send(position)
                    x2 = packet[12] * 256
                    x2 += packet[13]
                    y2 = packet[14] * 256
                    y2 += packet[15]
                    distance = get_distance(x2, self.location[0], y2, self.location[1])

                    if self.local_ip is not None:
                        distance_from_local = create_packet(DISTANCE, self.global_ip, ip, self.local_ip)
                        distance_from_local = add_distance_to_packet(distance_from_local, distance)
                        client.send(distance_from_local)

                    target_ip = source
                    self.switches[target_ip].append(self.global_ip)
                    self.switches[target_ip].append(client)
                    self.switches[target_ip].append(distance)
                    for switch_ip in self.switches.keys():
                        ass_ip = self.switches[switch_ip][0]
                        if switch_ip != target_ip:
                            distance_packet = create_packet(DISTANCE, ass_ip, switch_ip, target_ip)
                            distance += self.switches[switch_ip][2]
                            distance_packet = add_distance_to_packet(distance_packet, distance)
                            self.switches[switch_ip][1].send(distance_packet)
                elif mode == 9:
                    if packet[16] == 1:
                        return
                    else:
                        distance = packet[18] * 256 + packet[19]
                        ip_pool = list()
                        s_ip = str(ipaddress.IPv4Address(packet[:4]))
                        d_ip = str(ipaddress.IPv4Address(packet[4:8]))
                        t_ip = str(ipaddress.IPv4Address(packet[12:16]))
                        ip_pool.append(s_ip)
                        ip_pool.append(d_ip)
                        ip_pool.append(t_ip)
                        for switch_ip in self.switches.keys():
                            ass_ip = self.switches[switch_ip][0]
                            if switch_ip not in ip_pool:
                                distance_packet = create_packet(DISTANCE, ass_ip, switch_ip, s_ip)
                                distance += self.switches[switch_ip][2]
                                distance_packet = add_distance_to_packet(distance_packet, distance)
                                self.switches[switch_ip][1].send(distance_packet)

    def take_input(self):
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError:
                return
            else:
                self.send_command(user_input)

    def send_command(self, user_input):
        user_inputs = user_input.split(" ")
        if len(user_inputs) != 2:
            return
        command = user_inputs[0]
        try:
            port = int(user_inputs[1])
            if port < 0:
                return
        except:
            return
        if len(self.argument) != 4:
            return
        if command == "connect":
            connect_thread = threading.Thread(target=self.connect_to_tcp(port))
            connect_thread.start()
        else:
            return

    def connect_to_tcp(self, port):
        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            client.connect((LOCAL_HOST, port))
        except ConnectionRefusedError:
            # print("it is not an available port")
            return
        discovery = create_packet(DISCOVERY, '0.0.0.0', '0.0.0.0', '0.0.0.0')
        client.send(discovery)
        while True:
            packet = client.recv(PACKET_SIZE)
            if len(packet):
                mode = packet[11]
                if mode == 2:
                    switch_ip = str(ipaddress.IPv4Address(packet[:4]))
                    ass_ip = str(ipaddress.IPv4Address(int.from_bytes(packet[12:16], byteorder='big')))
                    request = create_packet(REQUEST, source_ip='0.0.0.0', dest_ip=switch_ip, data=ass_ip)
                    client.send(request)
                elif mode == 4:
                    switch_ip = str(ipaddress.IPv4Address(packet[:4]))
                    ass_ip = str(ipaddress.IPv4Address(int.from_bytes(packet[12:16], byteorder='big')))
                    position = create_packet(LOCATION, source_ip=ass_ip, dest_ip=switch_ip, data=self.location)
                    client.send(position)
                elif mode == 8:
                    x2 = packet[12] * 256
                    x2 += packet[13]
                    y2 = packet[14] * 256
                    y2 += packet[15]
                    target_ip = str(ipaddress.IPv4Address(packet[:4]))
                    self.switches[target_ip].append(str(ipaddress.IPv4Address(packet[4:8])))
                    self.switches[target_ip].append(client)
                    distance = get_distance(x2, self.location[0], y2, self.location[1])
                    self.switches[target_ip].append(distance)
                    for switch_ip in self.switches.keys():
                        ass_ip = self.switches[switch_ip][0]
                        if switch_ip != target_ip:
                            distance_packet = create_packet(DISTANCE, ass_ip, switch_ip, target_ip)
                            distance += self.switches[switch_ip][2]
                            distance_packet = add_distance_to_packet(distance_packet, distance)
                            self.switches[switch_ip][1].send(distance_packet)
                elif mode == 9:
                    if packet[16] == 1:
                        return
                    else:
                        distance = packet[18] * 256 + packet[19]
                        ip_pool = list()
                        s_ip = str(ipaddress.IPv4Address(packet[:4]))
                        d_ip = str(ipaddress.IPv4Address(packet[4:8]))
                        t_ip = str(ipaddress.IPv4Address(packet[12:16]))
                        ip_pool.append(s_ip)
                        ip_pool.append(d_ip)
                        ip_pool.append(t_ip)
                        for switch_ip in self.switches:
                            ass_ip = self.switches[switch_ip][0]
                            if switch_ip not in ip_pool:
                                distance_packet = create_packet(DISTANCE, ass_ip, switch_ip, s_ip)
                                distance += self.switches[switch_ip][2]
                                distance_packet = add_distance_to_packet(distance_packet, distance)
                                self.switches[switch_ip][1].send(distance_packet)


def main():
    switch = Switch()
    switch.choose_switch_type()


if __name__ == '__main__':
    main()
