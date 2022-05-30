import socket
import sys
import threading
import ipaddress

LOCAL_HOST = "127.0.0.1"
BUFFER_SIZE = 1024
RESERVED_BITS = 0
PACKET_SIZE = 1500

# Modes
DISCOVERY_01 = 0x01
OFFER_02 = 0x02
REQUEST_03 = 0x03
ACK_04 = 0x04
ASK_06 = 0x06
DATA_05 = 0x05
READY_07 = 0x07
LOCATION_08 = 0x08
FRAGMENT_0A = 0x0a
FRAGMENT_END_0B = 0x0b


def create_packet(mode, source_ip='0.0.0.0', dest_ip='0.0.0.0', data='0.0.0.0'):
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

    try:
        socket.inet_aton(data)
    except socket.error:
        for char in data:
            packet.append(ord(char))
    else:
        # append assigned address
        for elem in socket.inet_aton(data):
            packet.append(elem)
    return packet


def get_next_ip(ip):
    addr_parts = ip.split(".")
    final_part = addr_parts[3]
    change = int(final_part) + 1
    point = '.'
    addr_parts[3] = str(change)
    return point.join(addr_parts)


class Switch:
    def __init__(self):
        self.argument = sys.argv[1:]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.local_ip = None
        self.local_mask = None
        self.num_local_ips = None  # Number of IPs available for allocation
        self.current_available_local_ip = None

        self.global_ip = None
        self.global_mask = None
        self.num_global_ips = None  # Number of IPs available for allocation
        self.current_available_global_ip = None

        self.adapters = dict()
        self.switches = dict()

    def choose_switch_type(self):
        if self.argument[0] == "local":
            if len(self.argument) == 4:
                self.run_udp()
            elif len(self.argument) == 5:
                self.run_udp_tcp()
        elif self.argument[0] == "global":
            self.run_tcp()

    def run_udp(self):
        self.udp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)

        self.local_ip = self.argument[1].split("/")[0]
        self.local_mask = self.argument[1].split("/")[1]
        self.num_local_ips = 2 ** (32 - int(self.local_mask)) - 2
        self.current_available_local_ip = get_next_ip(self.local_ip)

        listen_thread = threading.Thread(target=self.listen_udp())
        listen_thread.start()

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()

    # does not have "connect" command
    def run_udp_tcp(self):
        self.udp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)
        self.tcp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)

        self.local_ip = self.argument[1].split("/")[0]
        self.local_mask = self.argument[1].split("/")[1]
        self.num_local_ips = 2 ** (32 - int(self.local_mask)) - 2
        self.current_available_local_ip = get_next_ip(self.local_ip)

        listen_thread = threading.Thread(target=self.listen_udp())
        listen_thread.start()

        self.global_ip = self.argument[1].split("/")[0]
        self.global_mask = self.argument[1].split("/")[1]
        self.num_global_ips = 2 ** (32 - int(self.global_mask)) - 2
        self.current_available_local_ip = get_next_ip(self.global_ip)

        listen_thread = threading.Thread(target=self.listen_tcp())
        listen_thread.start()

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()

    def run_tcp(self):
        self.tcp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)

        self.global_ip = self.argument[1].split("/")[0]
        self.global_mask = self.argument[1].split("/")[1]
        self.num_global_ips = 2 ** (32 - int(self.global_mask)) - 2
        self.current_available_local_ip = get_next_ip(self.global_ip)

        listen_thread = threading.Thread(target=self.listen_tcp())
        listen_thread.start()

        input_thread = threading.Thread(target=self.take_input)
        input_thread.start()

    def listen_udp(self):
        while True:
            packet, address = self.udp.recvfrom(PACKET_SIZE)
            if packet[11] == 1 or packet[11] == 3:
                self.greeting(packet, packet[11], address, address[1], self.num_local_ips)

    def listen_tcp(self):
        while True:
            packet, address = self.tcp.recvfrom(PACKET_SIZE)
            if packet[11] == 1 or packet[11] == 3:
                self.greeting(packet, packet[11], address, address[1], self.num_global_ips)

    def greeting(self, packet, mode, address, port, num_ips):
        if port not in self.adapters.keys():
            if mode == 1 and len(self.adapters) < num_ips:
                offer = create_packet(OFFER_02, source_ip=self.local_ip, dest_ip='0.0.0.0',
                                      data=self.current_available_local_ip)
                self.udp.sendto(offer, address)
                self.adapters[port] = self.current_available_local_ip
                self.current_available_local_ip = get_next_ip(self.current_available_local_ip)
        else:
            if mode == 3:
                ip = str(ipaddress.IPv4Address(int.from_bytes(packet[12:16], byteorder='big')))
                if ip == self.adapters[port]:
                    ack = create_packet(ACK_04, self.local_ip, ip, ip)
                    self.udp.sendto(ack, address)

    def take_input(self):
        """
        Take command from stdin. Acceptable command is 'connect'
        """
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError:
                return
            else:
                self.send_command(user_input)

    def send_command(self, user_input):
        user_input_split = user_input.split(" ")
        if len(user_input_split) != 2:
            return
        command = user_input_split[0]
        try:
            port = int(user_input_split[1])
        except:
            return
        if command == "connect":
            discovery = create_packet(DISCOVERY_01)
            send_address = (LOCAL_HOST, port)
            nowConnection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            nowConnection.sendto(discovery, send_address)
            offer = nowConnection.recvfrom(PACKET_SIZE)

        else:
            return


def main():
    switch = Switch()
    switch.choose_switch_type()


if __name__ == '__main__':
    main()
