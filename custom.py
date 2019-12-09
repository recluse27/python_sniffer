import socket
import struct
import textwrap
import argparse
from datetime import datetime


TAB_1 = '- '
TAB_2 = '\t'
TAB_3 = '\t\t'#'\t\t\t - '


def sniff(number, filename):
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) # Linux
    # conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP) # Windows
    with open(filename + '.txt', 'a+') as file:
        for i in range(1, number + 1):
            raw_data, addr = conn.recvfrom(65536)
            dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

            file.write("Ethernet Packet #" + str(i) + ':\n')
            file.write(TAB_1 + 'Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto) + '\n')

            if eth_proto == 8:
                (version, header_length, ttl, proto, src, target, data) = ipv4_Packet(data)

                file.write(TAB_1 + "IPV4 Packet:" + '\n')
                file.write(TAB_2 + 'Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl) + '\n')
                file.write(TAB_2 + 'protocol: {}, Source: {}, Target: {}'.format(proto, src, target) + '\n')

                # ICMP
                if proto == 1:
                    icmp_type, code, checksum, data = icmp_packet(data)

                    file.write(TAB_1 + 'ICMP Packet:' + '\n')
                    file.write('  Type: {}, Code: {}, Checksum: {},'.format(icmp_type, code, checksum) + '\n')
                    file.write('  ICMP Data:' + '\n')
                    output = format_output_line('  ', data) if format_output_line('  ', data) else ""
                    file.write(output + '\n')

                # TCP
                elif proto == 6:
                    src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin = struct.unpack(
                '! H H L L H H H H H H', raw_data[:24])

                    file.write(TAB_1 + 'TCP Segment:' + '\n')
                    file.write(TAB_2 + 'Source Port: {}, Destination Port: {}'.format(src_port, dest_port) + '\n')
                    file.write(TAB_2 + 'Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment) + '\n')
                    file.write(TAB_2 + 'Flags:' + '\n')
                    file.write(TAB_3 + 'URG: {}, ACK: {}, PSH: {}'.format(flag_urg, flag_ack, flag_psh) + '\n')
                    file.write(TAB_3 + 'RST: {}, SYN: {}, FIN:{}'.format(flag_rst, flag_syn, flag_fin) + '\n')

                    if len(data) > 0:
                        # HTTP
                        if src_port == 80 or dest_port == 80:
                            file.write(TAB_1 + 'HTTP Data:' + '\n')
                            try:
                                http = HTTP(data)
                                http_info = str(http.data).split('\n')
                                for line in http_info:
                                    file.write('  ' + str(line) + '\n')
                            except:
                                output = format_output_line('  ', data) if format_output_line('  ', data) else ""
                                file.write(output + '\n')
                        elif format_output_line('  ', data):
                            file.write(TAB_1 + 'TCP Data:' + '\n')
                            output = format_output_line('  ', data) if format_output_line('  ', data) else ""
                            file.write(output + '\n')
                # UDP
                elif proto == 17:
                    src_port, dest_port, length, data = udp_seg(data)
                    file.write(TAB_1 + 'UDP Segment:' + '\n')
                    file.write(TAB_2 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, length) + '\n')

                # Other IPv4
                else:
                    file.write(TAB_1 + 'Other IPv4 Data:' + '\n')
                    output = format_output_line(TAB_2, data) if format_output_line(TAB_2, data) else ""
                    file.write(output + '\n')

            else:
                file.write(TAB_1 + 'Ethernet Data:' + '\n')
                output = format_output_line(TAB_2, data) if format_output_line(TAB_2, data) else ""
                file.write(output + '\n')
            file.write('\n')


def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return (get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:])


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = ':'.join(bytes_str).upper()
    return mac_addr


def ipv4_Packet(data):
    version_header_len = data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return (version, header_len, ttl, proto, ipv4(src), ipv4(target), data[header_len:])


def ipv4(addr):
    return '.'.join(map(str, addr))


def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return (icmp_type, code, checksum, data[4:])


def tcp_seg(data):
    (src_port, destination_port, sequence, acknowledgenment, offset_reserv_flag) = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserv_flag >> 12) * 4
    flag_urg = (offset_reserved_flag & 32) >> 5
    flag_ack = (offset_reserved_flag & 32) >>4
    flag_psh = (offset_reserved_flag & 32) >> 3
    flag_rst = (offset_reserved_flag & 32) >> 2
    flag_syn = (offset_reserved_flag & 32) >> 1
    flag_fin = (offset_reserved_flag & 32) >> 1

    return (src_port, dest_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])


def udp_seg(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return (src_port, dest_port, size, data[8:])


def format_output_line(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size-= 1
            return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])


if __name__ == "__main__":
    programDescription = '''
        Command Line Tool: python sniffer using socket; Need to run with `sudo`
    '''

    parser = argparse.ArgumentParser(description=programDescription)
    parser.add_argument("--number", "-n", help="number of packets")
    parser.add_argument("--filename", "-f", help="filename to save")
    args = parser.parse_args()

    number = abs(int(args.number)) if args.number else 50
    filename = args.filename if args.filename else "result"
    
    sniff(number, filename)

    print('Sniffing is completed at %s' % datetime.now())
