import socket
import struct
import threading
import matplotlib.pyplot as plt
import io
import base64
from django.shortcuts import render
from django.http import JsonResponse, HttpResponse

# 设置捕获条件的IP地址
FILTER_IP = "10.136.8.70"  # 修改为需要捕获的IP地址
packets = []
report = {
        'ICMP': 0,
        'TCP': {
            'count': 0,
            'HTTP': 0,
            'HTTPS': 0
        },
        'UDP': {
            'count': 0,
            'DNS': 0,
            'DHCP': 0
        }
    }
STOP = False

def parse_ip_header(data):
    ip_header = data[0:20]
    ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
    version_ihl = ip_fields[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0x0F
    ttl = ip_fields[5]
    protocol = ip_fields[6]
    src_address = socket.inet_ntoa(ip_fields[8])
    dst_address = socket.inet_ntoa(ip_fields[9])

    # 解析扩展头（如果有）
    options = data[20:20 + (ihl - 5) * 4] if ihl > 5 else b''

    return version, src_address, dst_address, ttl, protocol, options

def parse_tcp(data):
    tcp_header = data[20:40]
    tcp_fields = struct.unpack('!HHLLBBHHH', tcp_header)
    return tcp_fields[0], tcp_fields[1]  # Source port, Destination port

def parse_udp(data):
    udp_header = data[20:28]
    udp_fields = struct.unpack('!HHHH', udp_header)
    return udp_fields[0], udp_fields[1]  # Source port, Destination port

def parse_dns(data):
    dns_header = data[28:42]  # 解析DNS头部
    dns_fields = struct.unpack('!HHHHHH', dns_header)
    return {
        'id': dns_fields[0],
        'flags': dns_fields[1],
        'questions': dns_fields[2],
        'answers': dns_fields[3],
        'authority': dns_fields[4],
        'additional': dns_fields[5],
    }

def parse_dhcp(data):
    dhcp_header = data[28:300]  # DHCP数据从UDP报头之后开始，假设最大长度为272字节
    dhcp_fields = struct.unpack('!BBBBIHHIIIIII', dhcp_header[:240])
    message_type = dhcp_fields[0]  # DHCP消息类型
    return {
        'message_type': message_type,
        'client_ip': socket.inet_ntoa(dhcp_fields[1:5]),
        'your_ip': socket.inet_ntoa(dhcp_fields[5:9]),
        'server_ip': socket.inet_ntoa(dhcp_fields[9:13]),
        'gateway_ip': socket.inet_ntoa(dhcp_fields[13:17])
    }

def parse_http(data):
    # 基本提取HTTP请求
    http_data = data[20:].decode('utf-8', errors='ignore')
    return http_data.splitlines()[0]  # 返回请求行

def analyze_protocol(protocol):
    if protocol == 1:
        return "ICMP"
    elif protocol == 6:
        return "TCP"
    elif protocol == 17:
        return "UDP"
    elif protocol == 2:
        return "IGMP"
    elif protocol == 47:
        return "GRE"
    else:
        return "Other"

def capture_packets():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sock.bind((FILTER_IP, 0))
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("Permission denied: You need to run this script with administrator privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")

    while True and not STOP:
        raw_data, _ = sock.recvfrom(65535)
        version, src, dst, ttl, protocol, options = parse_ip_header(raw_data)
        protocol_name = analyze_protocol(protocol)
        if protocol_name in ["TCP", "UDP"]:
            report[protocol_name]['count'] += 1
        elif protocol_name == "ICMP":
            report['ICMP'] += 1

        packet_info = {
            'version': version,
            'src_address': src,
            'dst_address': dst,
            'ttl': ttl,
            'protocol': protocol_name,
            'data': None,
            'options': options.hex()
        }

        if protocol == 6:  # TCP
            src_port, dst_port = parse_tcp(raw_data)
            packet_info['data'] = f"TCP - Source Port: {src_port}, Destination Port: {dst_port}"
            if dst_port == 80:  # HTTP
                http_info = parse_http(raw_data)
                packet_info['data'] += f", HTTP Data: {http_info}"
                report[protocol_name]["HTTP"] += 1
            elif dst_port == 443:  # HTTPS
                packet_info['data'] += ", HTTPS Data: Encrypted"
                report[protocol_name]["HTTPS"] += 1
        elif protocol == 17:  # UDP
            src_port, dst_port = parse_udp(raw_data)
            packet_info['data'] = f"UDP - Source Port: {src_port}, Destination Port: {dst_port}"
            if dst_port == 53:  # DNS
                dns_info = parse_dns(raw_data)
                packet_info['data'] += f", DNS Query ID: {dns_info['id']}"
                report[protocol_name]["DNS"] += 1
            elif dst_port in [67, 68]:  # DHCP
                dhcp_info = parse_dhcp(raw_data)
                packet_info['data'] += f", DHCP Message Type: {dhcp_info['message_type']}, Client IP: {dhcp_info['client_ip']}"
                report[protocol_name]["DHCP"] += 1
        elif protocol == 1:  # ICMP
            packet_info['data'] = "ICMP packet"

        packets.append(packet_info)
        print("---------- Append Packet ---------")
    sock.close()
    print("Close Socket Connection")

# 启动捕获线程
capture_thread = threading.Thread(target=capture_packets, daemon=True)
# capture_thread.start()

def index(request):
    return render(request, 'index.html')

def get_packets(request):
    src_ip = request.GET.get('src_ip', '').strip()
    dst_ip = request.GET.get('dst_ip', '').strip()

    filtered_packets = []
    for packet in packets:
        if (not src_ip or packet['src_address'] == src_ip) and (not dst_ip or packet['dst_address'] == dst_ip):
            filtered_packets.append(packet)

    return JsonResponse(filtered_packets, safe=False)

# def set_ip(request):
#     FILTER_IP = request.GET.get('filter_ip', '').strip()
#     capture_thread.start()

def set_ip(request):
    global STOP
    global FILTER_IP
    global capture_thread
    if capture_thread.is_alive():
        STOP = True
        capture_thread.join()
    FILTER_IP = request.GET.get('set_ip', '').strip()
    packets.clear()
    report['ICMP'] = 0
    report['TCP']['count'] = 0
    report['TCP']['HTTP'] = 0
    report['TCP']['HTTPS'] = 0
    report['UDP']['count'] = 0
    report['UDP']['DNS'] = 0
    report['UDP']['DHCP'] = 0
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return HttpResponse()

def generate_report(request):

    for packet in packets:
        protocol = packet['protocol']
        if protocol == 'ICMP':
            report['ICMP'] += 1
        elif protocol == 'TCP':
            report['TCP']['count'] += 1
            # 这里可以进一步解析端口来区分HTTP和HTTPS
            # 假设这里有对HTTP和HTTPS的逻辑
        elif protocol == 'UDP':
            report['UDP']['count'] += 1
            # 这里可以进一步解析端口来区分DNS和DHCP
            # 假设这里有对DNS和DHCP的逻辑

    return JsonResponse({'report': report})