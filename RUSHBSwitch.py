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


def create_packet(mode, source_ip, dest_ip='0.0.0.0', data='0.0.0.0'):
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


class Switch:
    def __init__(self):
        self.argument = sys.argv[1:]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.local_host_ip = None
        self.local_host_subst_mask = None
        self.global_host_ip = None
        self.global_host_subst_mask = None
        self.adapters = dict()
        print(self.argument)

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
        self.local_host_ip = self.argument[1].split("/")[0]
        self.local_host_subst_mask = self.argument[1].split("/")[1]

        print(self.local_host_ip)

        thread_stdin = threading.Thread(target=self.listen_udp())
        thread_stdin.start()

    # does not have "connect" command
    def run_udp_tcp(self):
        self.udp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)
        self.tcp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)
        self.local_host_ip = self.argument[1]
        self.global_host_ip = self.argument[2]

    def run_tcp(self):
        self.tcp.bind((LOCAL_HOST, 0))
        print(self.udp.getsockname()[1], flush=True)
        self.global_host_ip = self.argument[1]

    def listen_udp(self):
        while True:
            packet, address = self.udp.recvfrom(PACKET_SIZE)
            # print(packet)
            # print(address)
            # print(packet[11])
            if address[1] not in self.adapters.keys():
                if packet[11] == 1:
                    assigned_ip = self.get_next_ip()
                    offer = create_packet(OFFER_02, self.local_host_ip, '0.0.0.0', data='192.168.0.2')
                    self.udp.sendto(offer, address)
                    self.adapters[address[1]] = 0
            else:
                if packet[11] == 3 and self.adapters[address[1]] == 0:
                    ack = create_packet(ACK_04, self.local_host_ip, '192.168.0.2', data='192.168.0.2')
                    self.udp.sendto(ack, address)
                    self.adapters[address[1]] = 1

    def get_next_ip(self):
        number_of_subnet = 2 ** (32 - int(self.local_host_subst_mask)) - 2

        pass

    # def take_input(self):
    #     while True:
    #         print('> ', end='', flush=True)
    #         try:
    #             user_input = input()
    #         except EOFError:
    #             return
    #         else:
    #             self.send_command(user_input)


def main():
    switch = Switch()
    switch.choose_switch_type()


if __name__ == '__main__':
    # main()
    print(socket.inet_aton('192.168.0.2'))
    print('1.' + '1')
