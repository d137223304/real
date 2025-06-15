import datetime
import time
import heapq
import os
import argparse
import csv
import random
from scapy.utils import PcapWriter
from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR
gateway_traffic_pcap_writer = None
TARGET_SDN_NET = "10.0.0.0/24"
ATTACKER_NET = "192.168.100.0/24"
ROUTER_INTERNAL_IP = "10.0.0.1"
ROUTER_EXTERNAL_IP = "192.168.100.1"
FAUCET_CONTROLLER_VM_IP = "10.0.0.2"
VICTIM_WEBSRV_DVWA_IP = "10.0.0.101"
VICTIM_WEBSRV_DVWA_HOSTNAME = "dvwa.internal.local"
VICTIM_VULNSRV_METASPLOITABLE_IP = "10.0.0.102"
CLIENT_NORMAL_1_IP = "10.0.0.201"
CLIENT_NORMAL_2_IP = "10.0.0.202"
ATTACKER_EXT_KALI_IP = "192.168.100.50"
DNS_SERVER_IP = ROUTER_INTERNAL_IP
DNS_QUERY_NAME = VICTIM_WEBSRV_DVWA_HOSTNAME + "."
HTTP_SERVER_PORT = 80
CLIENT1_HTTP_INIT_PORT = 49200
DVWA_PAGES = [
    "/dvwa/login.php",
    "/dvwa/index.php",
    "/dvwa/instructions.php",
    "/dvwa/setup.php",
    "/dvwa/vulnerabilities/brute/",
    "/dvwa/vulnerabilities/exec/",
    "/dvwa/vulnerabilities/csrf/",
    "/dvwa/vulnerabilities/fi/?page=include.php",
    "/dvwa/vulnerabilities/upload/",
    "/dvwa/vulnerabilities/sqli/",
    "/dvwa/vulnerabilities/sqli_blind/",
    "/dvwa/vulnerabilities/xss_d/",
    "/dvwa/vulnerabilities/xss_r/",
    "/dvWA/vulnerabilities/xss_s/",
    "/dvwa/security.php",
    "/dvwa/phpinfo.php",
    "/dvwa/about.php",
    "/articles/article1.html",
    "/products/product_page.php?id=123",
    "/services/details.asp",
    "/contact.php",
    "/blog/categories/news/",
    "/docs/api/v1/",
    "/user/profile.php",
    "/search?query=example",
    "/static/css/theme.css",
    "/static/js/main.js",
    "/img/logo.png",
    "/img/banner.jpeg",
    "/dvwa/css/main_theme.css",
    "/dvwa/js/common_utils.js",
    "/dvwa/images/logo_banner.png"
]
CLIENT1_BROWSE_DURATION_PERCENTAGE = 0.8
CLIENT1_PAGES_PER_FORM_SUBMISSION = 3
CLIENT2_STREAMING_DURATION_PERCENTAGE = 0.75
DVWA_LOGIN_PAYLOAD = "username=admin&password=password&Login=Login"
DVWA_BENIGN_FORM_TARGET = "/dvwa/vulnerabilities/exec/"
DVWA_BENIGN_FORM_PAYLOAD = "ip=127.0.0.1&submit=Submit"
DVWA_BENIGN_FORMS = [
    {'target': "/dvwa/vulnerabilities/exec/", 'payload': "ip=127.0.0.1&submit=Submit", 'method': 'POST'},
    {'target': "/dvwa/vulnerabilities/csrf/", 'payload': "password_new=benignpass&password_conf=benignpass&Change=Change", 'method': 'POST'},
    {'target': "/dvwa/vulnerabilities/sqli/", 'payload': "id=1&Submit=Submit", 'method': 'GET'},
    {'target': "/dvwa/vulnerabilities/xss_r/", 'payload': "name=BenignTester", 'method': 'GET'},
    {'target': "/dvwa/vulnerabilities/brute/", 'payload': "username=benign&password=test&Login=Login", 'method': 'GET'},
    {'target': "/dvwa/vulnerabilities/upload/", 'payload': "MAX_FILE_SIZE=100000&uploaded_file=&Upload=Upload", 'method': 'POST'},
    {'target': "/dvwa/security.php", 'payload': "security=low&form=submit", 'method': 'POST'},
    {'target': "/dvwa/vulnerabilities/fi/?page=include.php", 'payload': "", 'method': 'GET'},
    {'target': "/dvWA/vulnerabilities/xss_s/", 'payload': "txtName=BenignUser&mtxMessage=HelloThisIsBenign&btnSign=Sign+Guestbook", 'method': 'POST'}
]
HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
NMAP_TARGET_IPS = [VICTIM_WEBSRV_DVWA_IP, VICTIM_VULNSRV_METASPLOITABLE_IP]
NMAP_TARGET_PORTS_COMMON = list(set([
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 500, 512, 513, 514, 515, 520, 546, 547, 554, 587, 631, 636,
    873, 990, 993, 995, 1080, 1194, 1433, 1434, 1521, 1701, 1723, 1812, 1813, 2000, 2049,
    2222, 2375, 3000, 3260, 3283, 3306, 3389, 4369, 5000, 5060, 5061, 5222, 5432, 5631,
    5666, 5672, 5900, 5901, 5902, 5903, 6000, 6001, 6379, 6443, 6667, 7000, 7070, 8000,
    8009, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9300, 9418, 10000, 11211, 27017, 27018
] + list(range(1, 1025))))
NMAP_TARGET_PORTS_COMMON = sorted(list(set(NMAP_TARGET_PORTS_COMMON)))
OPEN_PORTS = {
    VICTIM_WEBSRV_DVWA_IP: {80, 443},
    VICTIM_VULNSRV_METASPLOITABLE_IP: {
        21,
        22,
        23,
        25,
        53,
        80,
        111,
        139,
        445,
        512,
        513,
        514,
        1099,
        1524,
        2049,
        2121,
        3306,
        3632,
        5432,
        5900,
        6000,
        6667,
        8009,
        8180,
    }
}
ATTACKER_NMAP_INIT_SPORT = 50000
NMAP_SCAN_DELAY_PER_PACKET = 0.03
NMAP_SCAN_START_DELAY_SECONDS = 10
NMAP_SCAN_INTERVAL_MINUTES = 15
ATTACKER_PID_NMAP = 7000
SIMULATED_WEBSERVER_PID = 80
ATTACKER_HTTP_INIT_PORT = 51000
SQLI_TARGET_PATH = "/dvwa/vulnerabilities/sqli/?id={payload}&Submit=Submit#"
SQLI_PAYLOADS = [
    "1' OR '1'='1",
    "1' OR '1'='1' -- ",
    "1' OR '1'='1' # ",
    "1' OR 1=1 -- ",
    "1' OR 1=1 # ",
    "1' OR 'a'='a",
    "1' OR 'a'='a' -- ",
    "1' OR 'a'='a' # ",
    "1' OR 1 -- ",
    "1' OR 1 #",
    "1 UNION SELECT NULL, @@version -- ",
    "1 UNION SELECT NULL, version() -- ",
    "1 UNION SELECT NULL, table_name FROM information_schema.tables -- ",
    "1 UNION SELECT NULL, schema_name FROM information_schema.schemata -- ",
    "1' AND 1=2 UNION SELECT user, password FROM users WHERE user_id = '1",
    "1' UNION SELECT group_concat(column_name), NULL FROM information_schema.columns WHERE table_name='users' -- ",
    "'; SELECT SLEEP(5); --",
    "1 OR SLEEP(5)",
    "1' OR IF(1=1, SLEEP(5), 0) --",
    "1 AND BENCHMARK(5000000,MD5('A'))"
]
CMD_INJ_TARGET_PATH = "/dvwa/vulnerabilities/exec/"
CMD_INJ_FIELD_NAME = "ip"
CMD_INJ_PAYLOADS = [
    "127.0.0.1; ls -la",
    "127.0.0.1 && id",
    "127.0.0.1; uname -a",
    "127.0.0.1 && pwd",
    "127.0.0.1; cat /etc/passwd",
    "127.0.0.1 && cat /etc/hosts",
    "127.0.0.1; ps aux",
    "127.0.0.1 && netstat -tulnp",
    "127.0.0.1; find / -name config.php 2>/dev/null",
    "127.0.0.1 && echo '<script>alert(1)</script>' > /var/www/html/dvwa/hackable/uploads/test.html",
    "| ls -la",
    "& id",
    "; uname -a",
    "`id`",
    "$(uname -a)"
]
ATTACKER_PID_EXPLOIT = 7001
DVWA_APACHE_PID = SIMULATED_WEBSERVER_PID
DVWA_SHELL_PID = 1080
ATTACKER_EXPLOIT_DURATION_MINUTES = 20
METASPLOITABLE_FTP_PORT = 21
VSFTPD_BACKDOOR_PASSWORD = "password"
METASPLOITABLE_BINDSHELL_PORT = 6200
ATTACKER_FTP_CLIENT_PORT_START = 52000
ATTACKER_PID_FTP_EXPLOIT = 7002
METASPLOITABLE_VSFTPD_PID = 1200
METASPLOITABLE_SHELL_PID = 1201
STREAMING_CLIENT_INIT_PORT = 49152
STREAMING_SERVER_PORT = 443
VIDEO_PACKET_SIZE_MIN = 1370
VIDEO_PACKET_SIZE_MAX = 1370
INTER_PACKET_DELAY_SECONDS = 0.001
SIMULATED_CLIENT_PID_START = 5000
DEFAULT_CLIENT_UID = 1000
DEFAULT_SERVER_UID = 0
HOSTNAME_METASPLOITABLE = "metasploitable.internal.local"
HOSTNAME_CLIENT_NORMAL_1 = "client-normal-1.internal.local"
HOSTNAME_CLIENT_NORMAL_2 = "client-normal-2.internal.local"
HOSTNAME_ATTACKER_KALI = "kali.attacker.net"
HOSTNAME_FAUCET_CONTROLLER = "faucet-controller.internal.local"
HOSTNAME_ROUTER_GATEWAY = "router.internal.local"
def create_base_packet(clock, src_ip, sport, dst_ip, dport, flags="", payload=None, seq=None, ack=None, eth_src=None, eth_dst=None):
    if eth_src is None or eth_dst is None:
        raise ValueError("eth_src and eth_dst must be provided to create_base_packet")
    eth = Ether(src=eth_src, dst=eth_dst)
    ip = IP(src=src_ip, dst=dst_ip)
    tcp = TCP(sport=sport, dport=dport, flags=flags)
    if seq is not None:
        tcp.seq = seq
    if ack is not None:
        tcp.ack = ack
    pkt = eth/ip/tcp
    if payload:
        pkt = pkt/Raw(load=payload)
    if clock:
        current_sim_time = clock.get_time()
        if isinstance(current_sim_time, datetime.datetime):
            pkt.time = current_sim_time.timestamp()
        else:
            pkt.time = current_sim_time
    else:
        pkt.time = datetime.datetime.now().timestamp()
    return pkt
class Host:
    def __init__(self, ip_address, hostname, output_dir="output", mac_address: str | None = None):
        self.ip_address = ip_address
        self.hostname = hostname
        if mac_address is None:
            self.mac_address = f"00:1A:2B:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}:{random.randint(0, 255):02X}"
        else:
            self.mac_address = mac_address
        self.host_events = []
        self.pcap_writer = None
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
    def add_host_event(self, timestamp_obj: datetime.datetime, pid, ppid, uid, comm,
                       event_type, syscall, src_ip, dst_ip, src_port, dst_port, details):
        formatted_timestamp = timestamp_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
        event_row = {
            "Timestamp": formatted_timestamp,
            "PID": pid,
            "PPID": ppid,
            "UID": uid,
            "Comm": comm,
            "EventType": event_type,
            "Syscall": syscall,
            "SrcIP": src_ip,
            "DstIP": dst_ip,
            "SrcPort": src_port,
            "DstPort": dst_port,
            "Details": details
        }
        self.host_events.append(event_row)
    def init_pcap_writer(self, pcap_filename: str | None):
        if pcap_filename:
            full_path = os.path.join(self.output_dir, pcap_filename)
            self.pcap_writer = PcapWriter(full_path, append=True, sync=True)
            print(f"PCAP writer initialized for {self.hostname} at {full_path}")
    def add_packet_to_pcap(self, packet, timestamp: float | None = None):
        if self.pcap_writer:
            if timestamp is not None:
                packet.time = timestamp
            self.pcap_writer.write(packet)
    def close_pcap_writer(self):
        if self.pcap_writer:
            self.pcap_writer.close()
            print(f"PCAP writer closed for {self.hostname}")
            self.pcap_writer = None
    def write_events_to_csv(self, csv_filename: str | None):
        if csv_filename:
            full_path = os.path.join(self.output_dir, csv_filename)
            print(f"Attempting to write {len(self.host_events)} events for {self.hostname} to {full_path}...")
            default_fieldnames = [
                "Timestamp", "PID", "PPID", "UID", "Comm", "EventType",
                "Syscall", "SrcIP", "DstIP", "SrcPort", "DstPort", "Details"
            ]
            with open(full_path, 'w', newline='') as csvfile:
                if self.host_events:
                    fieldnames = self.host_events[0].keys()
                    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                    writer.writeheader()
                    writer.writerows(self.host_events)
                    print(f"Finished writing {len(self.host_events)} events for {self.hostname} to {full_path}")
                else:
                    writer = csv.DictWriter(csvfile, fieldnames=default_fieldnames)
                    writer.writeheader()
                    print(f"Finished writing header (0 events) for {self.hostname} to {full_path}")
        else:
            print(f"Skipping CSV writing for {self.hostname} as csv_filename was not provided.")
class Attacker(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.http_sessions = {}
        self.http_client_port_counter = ATTACKER_HTTP_INIT_PORT
    def start_dvwa_exploitation(self, scheduler, clock, dvwa_server_host: 'WebServerDVWA',
                                router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                exploitation_start_dt: datetime.datetime):
        self.add_host_event(exploitation_start_dt, ATTACKER_PID_EXPLOIT, 1, 0, "exploit.py",
                            "process_exec", "", self.ip_address, "", "", "",
                            "Begin DVWA exploitation (SQLi, CmdInj)")
        self.http_client_port_counter += random.randint(1, 50)
        client_http_port = self.http_client_port_counter
        client_initial_seq = random.randint(0, 2**32 - 1)
        session_key = (dvwa_server_host.ip_address, HTTP_SERVER_PORT)
        self.http_sessions[session_key] = {
            'client_seq': client_initial_seq,
            'server_ack': 0,
            'client_http_port': client_http_port,
            'process_pid': ATTACKER_PID_EXPLOIT,
            'logged_in': False,
            'exploitation_end_time': exploitation_start_dt + datetime.timedelta(minutes=ATTACKER_EXPLOIT_DURATION_MINUTES)
        }
        actions = []
        for i in range(len(SQLI_PAYLOADS) * 2):
            actions.append(f'sqli_{i % len(SQLI_PAYLOADS)}')
        for i in range(len(CMD_INJ_PAYLOADS) * 2):
            actions.append(f'cmd_inj_{i % len(CMD_INJ_PAYLOADS)}')
        random.shuffle(actions)
        self.http_sessions[session_key]['actions'] = actions
        next_action_details = {'type': 'EXPLOIT_INIT_CONNECTION'}
        event_time = exploitation_start_dt
        scheduler.add_event(Event(event_time, 2, self.send_http_syn_for_exploit,
                                  f"Attacker SYN for DVWA Exploit to {dvwa_server_host.ip_address}",
                                  args=(clock, scheduler, dvwa_server_host, router_gateway_host,
                                        faucet_controller_host, client_http_port, client_initial_seq,
                                        next_action_details, session_key)))
        print(f"{clock.get_timestamp_str(exploitation_start_dt)}: Attacker {self.ip_address} (PID {ATTACKER_PID_EXPLOIT}) scheduled DVWA exploitation sequence.")
    def send_http_syn_for_exploit(self, clock, scheduler, target_server_host: 'WebServerDVWA',
                                  router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                  client_http_port: int, client_seq: int, next_action_details: dict, session_key: tuple):
        current_time = clock.get_time()
        syn_pkt = create_base_packet(clock, self.ip_address, client_http_port, target_server_host.ip_address,
                                     HTTP_SERVER_PORT, flags="S", seq=client_seq,
                                     eth_src=self.mac_address,
                                     eth_dst=router_gateway_host.mac_address_external)
        packet_timestamp = current_time.timestamp()
        syn_pkt.time = packet_timestamp
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(syn_pkt)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        session = self.http_sessions.get(session_key)
        if session:
             session['client_seq'] = client_seq + 1
             self.add_host_event(current_time, session['process_pid'], 1, 0, "exploit.py",
                                "network_connect", "connect", self.ip_address, target_server_host.ip_address,
                                client_http_port, HTTP_SERVER_PORT, f"HTTP SYN to {target_server_host.ip_address} for exploit session")
        event_time = current_time + datetime.timedelta(seconds=0.02)
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_syn,
                                  f"DVWA handles Attacker HTTP SYN from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt,
                                        self.handle_http_syn_ack_for_exploit, next_action_details, router_gateway_host)))
    def handle_http_syn_ack_for_exploit(self, clock, scheduler, target_server_host: 'WebServerDVWA',
                                        router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                        server_syn_ack_pkt: IP, next_action_details: dict):
        current_time = clock.get_time()
        client_http_port = server_syn_ack_pkt[TCP].dport
        server_ip = server_syn_ack_pkt[IP].src
        session_key = (server_ip, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if not session or session['client_http_port'] != client_http_port:
            print(f"Error: Attacker received unexpected SYN-ACK for exploit session from {server_ip}:{server_syn_ack_pkt[TCP].sport}")
            return
        self.add_packet_to_pcap(server_syn_ack_pkt, timestamp=current_time.timestamp())
        session['server_ack'] = server_syn_ack_pkt[TCP].seq + 1
        ack_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                     eth_src=self.mac_address,
                                     eth_dst=router_gateway_host.mac_address_external)
        packet_timestamp = current_time.timestamp()
        ack_pkt.time = packet_timestamp
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(ack_pkt)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        event_time = current_time + datetime.timedelta(seconds=0.01)
        scheduler.add_event(Event(event_time, 2, self.send_next_exploit_request,
                                  "Attacker sends first exploit request",
                                  args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
    def send_next_exploit_request(self, clock, scheduler, target_server_host: 'WebServerDVWA',
                                  router_gateway_host: 'RouterGateway', faucet_controller_host: Host, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session or not session['actions']:
            print(f"{clock.get_timestamp_str(clock.get_time())}: No more exploit actions for Attacker on session {session_key}.")
            return
        action_key = session['actions'].pop(0)
        exploit_details = {}
        action_parts = action_key.split('_')
        action_type = action_parts[0]
        payload_index = int(action_parts[1])
        if action_type == 'sqli':
            if payload_index < len(SQLI_PAYLOADS):
                chosen_payload = SQLI_PAYLOADS[payload_index]
                payload_url_encoded = chosen_payload.replace(" ", "%20").replace("'", "%27").replace(";", "%3B").replace("&", "%26").replace("=", "%3D").replace("#", "%23")
                path = SQLI_TARGET_PATH.format(payload=payload_url_encoded)
                exploit_details = {'type': 'GET', 'path': path, 'description': f'SQLi Attempt: {chosen_payload[:30]}...', 'action_type': 'sqli', 'payload_content': chosen_payload}
            else:
                print(f"Warning: SQLi payload index {payload_index} out of bounds for session {session_key}")
                if session['actions'] and clock.get_time() < session.get('exploitation_end_time', clock.get_time()):
                     scheduler.add_event(Event(clock.get_time() + datetime.timedelta(seconds=0.1), 2, self.send_next_exploit_request,
                                               "Attacker sends next exploit request (SQLi index error)",
                                               args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
                return
        elif action_type == 'cmd_inj':
            if payload_index < len(CMD_INJ_PAYLOADS):
                chosen_payload = CMD_INJ_PAYLOADS[payload_index]
                cmd_payload_encoded = chosen_payload.replace(" ", "%20").replace(";", "%3B").replace("&", "%26").replace("`", "%60").replace("(", "%28").replace(")", "%29")
                post_body = f"{CMD_INJ_FIELD_NAME}={cmd_payload_encoded}&Submit=Submit"
                exploit_details = {'type': 'POST', 'path': CMD_INJ_TARGET_PATH, 'payload_str': post_body, 'description': f'CmdInj Attempt: {chosen_payload[:30]}...', 'action_type': 'cmd_inj', 'payload_content': chosen_payload}
            else:
                print(f"Warning: CmdInj payload index {payload_index} out of bounds for session {session_key}")
                if session['actions'] and clock.get_time() < session.get('exploitation_end_time', clock.get_time()):
                     scheduler.add_event(Event(clock.get_time() + datetime.timedelta(seconds=0.1), 2, self.send_next_exploit_request,
                                               "Attacker sends next exploit request (CmdInj index error)",
                                               args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
                return
        else:
            print(f"Unknown exploit action key prefix: {action_type} in {action_key}")
            if session['actions']:
                 scheduler.add_event(Event(clock.get_time() + datetime.timedelta(seconds=0.1), 2, self.send_next_exploit_request,
                                           "Attacker sends next exploit request (after unknown key)",
                                           args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
            return
        if not exploit_details:
            print(f"Warning: Exploit details not prepared for action {action_key}. Skipping this attempt.")
            if session['actions']:
                 scheduler.add_event(Event(clock.get_time() + datetime.timedelta(seconds=0.1), 2, self.send_next_exploit_request,
                                           "Attacker sends next exploit request (after no details prepared)",
                                           args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
            return
        self.send_http_exploit_payload(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, exploit_details, session_key)
    def send_http_exploit_payload(self, clock, scheduler, target_server_host: 'WebServerDVWA',
                                  router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                  exploit_details: dict, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: No active HTTP session for exploit payload for session {session_key}")
            return
        client_http_port = session['client_http_port']
        current_time = clock.get_time()
        path = exploit_details['path']
        method = exploit_details['type']
        payload_body_str = exploit_details.get('payload_str', "")
        http_request_line_and_headers = f"{method} {path} HTTP/1.1\r\nHost: {VICTIM_WEBSRV_DVWA_HOSTNAME.rstrip('.')}\r\nUser-Agent: {HTTP_USER_AGENT} (Kali Attacker Exploit Tool)\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml;q=0.9\r\n"
        if method == "POST":
            http_request_line_and_headers += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload_body_str.encode('utf-8'))}\r\n"
        full_http_request_payload = (http_request_line_and_headers + "\r\n" + payload_body_str).encode('utf-8')
        request_pkt = create_base_packet(clock, self.ip_address, client_http_port, target_server_host.ip_address,
                                         HTTP_SERVER_PORT, flags="PA", payload=full_http_request_payload,
                                         seq=session['client_seq'], ack=session['server_ack'],
                                         eth_src=self.mac_address,
                                         eth_dst=router_gateway_host.mac_address_external)
        packet_timestamp = current_time.timestamp()
        request_pkt.time = packet_timestamp
        self.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(request_pkt)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        log_action_type = exploit_details.get('action_type', 'unknown_exploit')
        event_type_log = f"{log_action_type}_sent"
        payload_summary_for_log = exploit_details.get('payload_content', '')[:50] if log_action_type == 'sqli' else payload_body_str[:50]
        details_log = f"exploit_sent:type={log_action_type.upper()},target_url={target_server_host.ip_address}{path},payload_summary='{payload_summary_for_log}'"
        self.add_host_event(current_time, session['process_pid'], 1, 0, "exploit.py",
                            event_type_log, "send", self.ip_address, target_server_host.ip_address,
                            client_http_port, HTTP_SERVER_PORT, details_log)
        session['client_seq'] += len(full_http_request_payload)
        print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} sent exploit payload: {exploit_details['description']}")
        event_time = current_time + datetime.timedelta(seconds=0.05)
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_request,
                                  f"DVWA handles Attacker Exploit Req ({exploit_details['description'][:20]})",
                                  args=(clock, scheduler, self, faucet_controller_host, request_pkt)))
    def handle_http_response_for_exploit(self, clock, scheduler, target_server_host: 'WebServerDVWA',
                                         router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                         server_response_packet: IP):
        current_time = clock.get_time()
        server_ip = server_response_packet[IP].src
        session_key = (server_ip, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: Attacker received HTTP response for exploit but no session found for {session_key}")
            return
        client_http_port = session['client_http_port']
        self.add_packet_to_pcap(server_response_packet, timestamp=current_time.timestamp())
        payload_len = 0
        if Raw in server_response_packet:
            payload_len = len(server_response_packet[Raw].load)
        session['server_ack'] = server_response_packet[TCP].seq + payload_len
        ack_for_response_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                                  flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                                  eth_src=self.mac_address,
                                                  eth_dst=router_gateway_host.mac_address_external)
        packet_timestamp = current_time.timestamp()
        ack_for_response_pkt.time = packet_timestamp
        self.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(ack_for_response_pkt)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        if session['actions'] and clock.get_time() < session.get('exploitation_end_time', clock.get_time()):
            delay_seconds = random.uniform(0.2, 1.0)
            event_time = current_time + datetime.timedelta(seconds=delay_seconds)
            scheduler.add_event(Event(event_time, 2, self.send_next_exploit_request,
                                      "Attacker sends next exploit request",
                                      args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
        else:
            if clock.get_time() >= session.get('exploitation_end_time', clock.get_time()):
                print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} DVWA exploitation time ended for session {session_key}.")
            else:
                print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} finished all DVWA exploit actions for session {session_key}.")
    def start_nmap_scan(self, scheduler, clock, target_ips: list, ports_to_scan: list,
                        router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                        all_hosts_map: dict, scan_start_dt: datetime.datetime,
                        is_rescan: bool = False, simulation_end_time: datetime.datetime | None = None):
        log_prefix = "Nmap Rescan" if is_rescan else "Nmap Scan"
        self.add_host_event(scan_start_dt, ATTACKER_PID_NMAP, 1, 0, "nmap",
                            "process_exec", "", self.ip_address, "", "", "",
                            f"{log_prefix}: -sS scan initiated against {', '.join(target_ips)} for {len(ports_to_scan)} ports each.")
        current_delay_offset = 0.0
        current_sport = ATTACKER_NMAP_INIT_SPORT
        for target_ip_str in target_ips:
            target_host_obj = all_hosts_map.get(target_ip_str)
            if not target_host_obj:
                print(f"Warning: Target host {target_ip_str} not found in all_hosts_map. Skipping Nmap for this target.")
                continue
            for port in ports_to_scan:
                event_time = scan_start_dt + datetime.timedelta(seconds=current_delay_offset)
                action_args = (clock, scheduler, target_host_obj, port, current_sport,
                               router_gateway_host, faucet_controller_host)
                scheduler.add_event(Event(event_time, 3, self.send_nmap_syn_packet,
                                          f"Attacker Nmap SYN to {target_ip_str}:{port}",
                                          args=action_args))
                current_delay_offset += NMAP_SCAN_DELAY_PER_PACKET
                current_sport += 1
                if current_sport > 65530:
                    current_sport = ATTACKER_NMAP_INIT_SPORT
        print(f"{clock.get_timestamp_str(scan_start_dt)}: Attacker {self.ip_address} (PID {ATTACKER_PID_NMAP}) scheduled {len(target_ips) * len(ports_to_scan)} Nmap -sS {log_prefix.lower()} packets.")
        if not is_rescan and simulation_end_time:
            next_scan_time = scan_start_dt + datetime.timedelta(minutes=NMAP_SCAN_INTERVAL_MINUTES)
            if next_scan_time < simulation_end_time:
                scheduler.add_event(Event(next_scan_time, 3, self.start_nmap_scan,
                                          f"Attacker periodic Nmap Rescan to {', '.join(target_ips)}",
                                          args=(scheduler, clock, target_ips, ports_to_scan,
                                                router_gateway_host, faucet_controller_host,
                                                all_hosts_map, next_scan_time, True, simulation_end_time)))
                print(f"{clock.get_timestamp_str(scan_start_dt)}: Scheduled next Nmap rescan at {clock.get_timestamp_str(next_scan_time)}")
            else:
                print(f"{clock.get_timestamp_str(scan_start_dt)}: Next Nmap rescan time {clock.get_timestamp_str(next_scan_time)} is beyond simulation end {clock.get_timestamp_str(simulation_end_time)}. Not scheduling.")
    def send_nmap_syn_packet(self, clock, scheduler, target_host: Host, target_port: int,
                             src_port: int, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        target_ip = target_host.ip_address
        current_time = clock.get_time()
        client_initial_seq = random.randint(0, 2**32 - 1)
        syn_pkt = create_base_packet(clock, self.ip_address, src_port, target_ip, target_port,
                                     flags="S", seq=client_initial_seq,
                                     eth_src=self.mac_address,
                                     eth_dst=router_gateway_host.mac_address_external)
        packet_timestamp = current_time.timestamp()
        syn_pkt.time = packet_timestamp
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(syn_pkt)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                            "network_packet", "sendto", self.ip_address, target_ip,
                            src_port, target_port, f"Nmap SYN to {target_ip}:{target_port}")
        event_time = current_time + datetime.timedelta(seconds=0.005)
        scheduler.add_event(Event(event_time, 1, target_host.handle_nmap_syn,
                                  f"Target {target_ip} handles Nmap SYN from {self.ip_address}:{src_port}",
                                  args=(clock, scheduler, syn_pkt, self, router_gateway_host, faucet_controller_host)))
    def handle_nmap_target_response(self, clock, scheduler, response_pkt: IP,
                                    router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        current_time = clock.get_time()
        self.add_packet_to_pcap(response_pkt, timestamp=current_time.timestamp())
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=current_time.timestamp())
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(response_pkt)
        if TCP in response_pkt and response_pkt[TCP].flags.SA:
            target_ip = response_pkt[IP].src
            target_port = response_pkt[TCP].sport
            attacker_orig_sport = response_pkt[TCP].dport
            rst_seq = response_pkt[TCP].ack
            rst_pkt = create_base_packet(clock, self.ip_address, attacker_orig_sport, target_ip, target_port,
                                         flags="R", seq=rst_seq,
                                         eth_src=self.mac_address,
                                         eth_dst=router_gateway_host.mac_address_external)
            rst_pkt_timestamp = current_time.timestamp()
            rst_pkt.time = rst_pkt_timestamp
            self.add_packet_to_pcap(rst_pkt, timestamp=rst_pkt_timestamp)
            if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(rst_pkt)
            if faucet_controller_host:
                faucet_controller_host.add_packet_to_pcap(rst_pkt, timestamp=rst_pkt_timestamp)
            self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                                "nmap_scan_result", "recvfrom/sendto", self.ip_address, target_ip,
                                attacker_orig_sport, target_port,
                                f"Nmap_response:target={target_ip},port={target_port},status=OPEN,action=sent_RST")
        elif TCP in response_pkt and response_pkt[TCP].flags.RA:
            target_ip = response_pkt[IP].src
            target_port = response_pkt[TCP].sport
            attacker_orig_sport = response_pkt[TCP].dport
            self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                                "nmap_scan_result", "recvfrom", self.ip_address, target_ip,
                                attacker_orig_sport, target_port,
                                f"Nmap_response:target={target_ip},port={target_port},status=CLOSED")
class WebServerDVWA(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.active_streams = {}
        self.http_sessions = {}
    def handle_nmap_syn(self, clock, scheduler, nmap_syn_packet: IP,
                        attacker_host: Attacker, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        src_ip = nmap_syn_packet[IP].src
        src_port = nmap_syn_packet[TCP].sport
        dst_port = nmap_syn_packet[TCP].dport
        current_time = clock.get_time()
        self.add_packet_to_pcap(nmap_syn_packet, timestamp=current_time.timestamp())
        is_open = dst_port in OPEN_PORTS.get(self.ip_address, set())
        response_pkt = None
        log_message = ""
        event_desc = ""
        if is_open:
            server_initial_seq = random.randint(0, 2**32 - 1)
            ack_to_attacker_seq = nmap_syn_packet[TCP].seq + 1
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="SA", seq=server_initial_seq, ack=ack_to_attacker_seq,
                                              eth_src=self.mac_address,
                                              eth_dst=router_gateway_host.mac_address_internal)
            log_message = f"Nmap SYN on OPEN port {dst_port} from {src_ip}:{src_port}. Sent SYN-ACK."
            event_desc = f"Target {self.ip_address} SYN-ACK for Nmap (port {dst_port} open)"
        else:
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="RA", seq=0, ack=nmap_syn_packet[TCP].seq + 1,
                                              eth_src=self.mac_address,
                                              eth_dst=router_gateway_host.mac_address_internal)
            log_message = f"Nmap SYN on CLOSED port {dst_port} from {src_ip}:{src_port}. Sent RST-ACK."
            event_desc = f"Target {self.ip_address} RST-ACK for Nmap (port {dst_port} closed)"
        response_pkt.time = current_time.timestamp()
        self.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(response_pkt)
        event_time = current_time + datetime.timedelta(seconds=0.005)
        scheduler.add_event(Event(event_time, 1, attacker_host.handle_nmap_target_response,
                                  event_desc,
                                  args=(clock, scheduler, response_pkt, router_gateway_host, faucet_controller_host)))
    def handle_http_syn(self, clock, scheduler, client_host, faucet_controller_host, client_syn_packet,
                        client_syn_ack_handler_method,
                        next_client_action_details, router_gateway_ref=None):
        client_ip = client_syn_packet[IP].src
        client_port = client_syn_packet[TCP].sport
        server_initial_seq = random.randint(0, 2**32 - 1)
        session_key = (client_ip, client_port)
        self.http_sessions[session_key] = {
            'server_seq': server_initial_seq + 1,
            'client_ack': client_syn_packet[TCP].seq + 1,
            'logged_in': False,
            'server_tcp_stream_id': random.randint(1000,2000)
        }
        syn_ack_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                         flags="SA", seq=server_initial_seq, ack=client_syn_packet[TCP].seq + 1,
                                         eth_src=self.mac_address, eth_dst=client_host.mac_address)
        packet_time = clock.get_time()
        self.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        client_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        self.add_host_event(packet_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                            "network_connect", "accept", self.ip_address, client_ip,
                            HTTP_SERVER_PORT, client_port, f"HTTP SYN-ACK to {client_ip}:{client_port}")
        event_time = packet_time + datetime.timedelta(seconds=0.01)
        callback_args = None
        if isinstance(client_host, Attacker):
            if router_gateway_ref is None:
                print(f"CRITICAL WARNING in handle_http_syn: router_gateway_ref is None for an Attacker callback. Client IP: {client_host.ip_address}. This might lead to errors.")
            callback_args = (
                clock,
                scheduler,
                self,
                router_gateway_ref,
                faucet_controller_host,
                syn_ack_pkt,
                next_client_action_details
            )
        else:
            callback_args = (
                clock,
                scheduler,
                self,
                faucet_controller_host,
                syn_ack_pkt,
                next_client_action_details
            )
        scheduler.add_event(Event(event_time, 1, client_syn_ack_handler_method,
                                  f"Client/Attacker {client_ip} handles HTTP SYN-ACK from {self.ip_address}",
                                  args=callback_args))
    def handle_http_request(self, clock, scheduler, client_host, faucet_controller_host, http_request_packet):
        client_ip = http_request_packet[IP].src
        client_port = http_request_packet[TCP].sport
        session_key = (client_ip, client_port)
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: No HTTP session found for {client_ip}:{client_port} at DVWA.")
            return
        raw_payload_bytes = http_request_packet[Raw].load if Raw in http_request_packet else b""
        try:
            http_payload_str = raw_payload_bytes.decode('utf-8', errors='ignore')
        except AttributeError:
             http_payload_str = ""
        response_body = "<html><head><title>Simulated DVWA</title></head><body><h1>Response</h1><p>Request processed.</p></body></html>"
        http_status = "200 OK"
        additional_headers = ""
        is_command_injection = False
        injected_command = None
        if CMD_INJ_TARGET_PATH in http_payload_str and "POST" in http_payload_str:
            post_params = {}
            if "\r\n\r\n" in http_payload_str:
                body = http_payload_str.split("\r\n\r\n", 1)[1]
                params = body.split('&')
                for param_pair in params:
                    if '=' in param_pair:
                        key, value = param_pair.split('=', 1)
                        post_params[key.strip()] = value.replace('+', ' ').replace('%20', ' ').replace('%3B', ';').replace('%26', '&')
            if CMD_INJ_FIELD_NAME in post_params:
                field_value = post_params[CMD_INJ_FIELD_NAME]
                for test_cmd_base in CMD_INJ_PAYLOADS:
                    if "; " in test_cmd_base:
                        cmd_part = test_cmd_base.split("; ", 1)[1]
                        if cmd_part in field_value and field_value.startswith(test_cmd_base.split("; ",1)[0]):
                            is_command_injection = True
                            injected_command = cmd_part
                            break
                    if "&& " in test_cmd_base:
                        cmd_part = test_cmd_base.split("&& ", 1)[1]
                        if cmd_part in field_value and field_value.startswith(test_cmd_base.split("&& ",1)[0]):
                            is_command_injection = True
                            injected_command = cmd_part
                            break
        if is_command_injection and injected_command:
            current_time = clock.get_time()
            self.add_host_event(current_time, DVWA_SHELL_PID, DVWA_APACHE_PID, DEFAULT_SERVER_UID,
                                "/bin/sh", "cmd_injection_executed", "execve",
                                self.ip_address, client_ip,
                                0, 0,
                                f"Command injection executed: /bin/sh -c '{injected_command}' by Apache UID {DEFAULT_SERVER_UID}")
            response_body = f"<html><body><pre>PING {post_params.get(CMD_INJ_FIELD_NAME,'').split(';')[0].split('&&')[0].strip()}\n...simulated output for injected command '{injected_command}'...</pre></body></html>"
            http_status = "200 OK"
            print(f"{clock.get_timestamp_str(current_time)}: DVWA server ({self.ip_address}) detected and logged command injection: {injected_command}")
        elif SQLI_TARGET_PATH.split("?")[0] in http_payload_str and "GET" in http_payload_str:
            is_sqli_attempt = False
            sqli_payload_detected = ""
            uri_payload_part = http_payload_str.split(SQLI_TARGET_PATH.split("?")[0],1)[1] if SQLI_TARGET_PATH.split("?")[0] in http_payload_str else ""
            for p in SQLI_PAYLOADS:
                if p in uri_payload_part:
                    is_sqli_attempt = True
                    sqli_payload_detected = p
                    break
            if is_sqli_attempt:
                current_time = clock.get_time()
                self.add_host_event(current_time, DVWA_APACHE_PID, 1, DEFAULT_SERVER_UID, "apache2",
                                    "sqli_attempt_detected", "http_request_logged",
                                    self.ip_address, client_ip, HTTP_SERVER_PORT, client_port,
                                    f"SQLi attempt detected in URI: {uri_payload_part[:150]}, matched_payload_pattern='{sqli_payload_detected}'")
                print(f"{clock.get_timestamp_str(current_time)}: DVWA server ({self.ip_address}) detected SQLi attempt: {sqli_payload_detected}")
            response_body = "<html><body>SQL Injection Test Page. Your input was processed.</body></html>"
        elif "login.php" in http_payload_str and "POST" in http_payload_str:
            if DVWA_LOGIN_PAYLOAD in http_payload_str:
                session['logged_in'] = True
                response_body = "<html><body>Login Successful! Redirecting to index.php...</body></html>"
                http_status = "302 Found"
                additional_headers = f"Set-Cookie: PHPSESSID=simulatedsessionid_{random.randint(10000,99999)}; path=/\r\nLocation: /dvwa/index.php\r\n"
            else:
                response_body = "<html><body>Login Failed! Invalid credentials.</body></html>"
        elif session.get('logged_in', False) and "/dvwa/index.php" in http_payload_str:
             response_body = "<html><body>Welcome to DVWA, admin! You are logged in.</body></html>"
        elif SQLI_TARGET_PATH.split("?")[0] in http_payload_str and "GET" in http_payload_str:
            response_body = "<html><body>SQL Injection Test Page. Your input was processed.</body></html>"
        content_length = len(response_body.encode('utf-8'))
        http_response_headers = f"HTTP/1.1 {http_status}\r\nServer: Apache/2.4.x (Simulated)\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {content_length}\r\nConnection: keep-alive\r\n{additional_headers}\r\n"
        full_response = (http_response_headers + response_body).encode('utf-8')
        client_data_len = len(raw_payload_bytes)
        server_ack_for_client_data = http_request_packet[TCP].seq + client_data_len
        ack_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                     flags="A", seq=session['server_seq'], ack=server_ack_for_client_data,
                                     eth_src=self.mac_address, eth_dst=client_host.mac_address)
        current_time = clock.get_time()
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        client_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        session['client_ack'] = server_ack_for_client_data
        response_event_time = current_time + datetime.timedelta(seconds=0.001)
        response_data_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                         flags="PA", payload=full_response,
                                         seq=session['server_seq'], ack=session['client_ack'],
                                         eth_src=self.mac_address, eth_dst=client_host.mac_address)
        response_data_pkt.time = response_event_time.timestamp()
        self.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)
        client_host.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)
        self.add_host_event(response_event_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                            "network_data", "send", self.ip_address, client_ip, HTTP_SERVER_PORT, client_port,
                            f"HTTP Response {http_status} for {http_payload_str[:50]}...")
        session['server_seq'] += len(full_response)
        response_ack_handler = None
        if isinstance(client_host, ClientNormal1):
            response_ack_handler = client_host.handle_http_response_ack
        elif isinstance(client_host, Attacker):
            response_ack_handler = client_host.handle_http_response_for_exploit
        if response_ack_handler:
            client_ack_event_time = response_event_time + datetime.timedelta(seconds=0.01)
            scheduler.add_event(Event(client_ack_event_time, 2, response_ack_handler,
                                      f"Client/Attacker {client_ip} ACKs HTTP Resp from DVWA",
                                      args=(clock, scheduler, self, faucet_controller_host, response_data_pkt)))
        else:
            print(f"Warning: Could not determine HTTP response ACK handler for client type {type(client_host)}")
    def handle_streaming_syn(self, clock, scheduler, client_host, faucet_controller_host, client_syn_packet,
                             client_syn_ack_handler_method,
                             actual_stream_duration_seconds):
        client_ip = client_syn_packet[IP].src
        client_port = client_syn_packet[TCP].sport
        server_initial_seq = random.randint(0, 2**32 - 1)
        self.active_streams[(client_ip, client_port)] = {
            'server_seq': server_initial_seq,
            'client_ack_of_server_seq': client_syn_packet[TCP].seq + 1,
            'packets_sent_this_stream': 0
        }
        syn_ack_pkt = create_base_packet(clock, self.ip_address, STREAMING_SERVER_PORT, client_ip, client_port,
                                         flags="SA", seq=server_initial_seq, ack=client_syn_packet[TCP].seq + 1,
                                         eth_src=self.mac_address, eth_dst=client_host.mac_address)
        packet_time = clock.get_time()
        self.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        client_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        self.add_host_event(packet_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                            "video_stream_accepted", "accept", self.ip_address, client_ip,
                            STREAMING_SERVER_PORT, client_port,
                            f"video_stream_accepted:client_ip={client_ip},client_port={client_port}")
        event_time = packet_time + datetime.timedelta(seconds=0.01)
        scheduler.add_event(Event(event_time, 1, client_syn_ack_handler_method,
                                  f"Client {client_ip} ACK stream SYN-ACK from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_ack_pkt, actual_stream_duration_seconds)))
    def send_streaming_data_packet(self, clock, scheduler, client_host, faucet_controller_host, client_ip_port_tuple, stream_end_time):
        client_ip, client_port = client_ip_port_tuple
        current_time = clock.get_time()
        if current_time >= stream_end_time:
            packets_sent = self.active_streams.get(client_ip_port_tuple, {}).get('packets_sent_this_stream', 0)
            self.add_host_event(current_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                                "video_stream_ended_server", "close", self.ip_address, client_ip,
                                STREAMING_SERVER_PORT, client_port,
                                f"video_stream_ended_server:client_ip={client_ip},packets_sent={packets_sent}")
            print(f"{clock.get_timestamp_str(current_time)}: Video stream data finished for {client_ip}:{client_port}. Total packets: {packets_sent}. Initiating FIN (TODO).")
            if client_ip_port_tuple in self.active_streams:
                del self.active_streams[client_ip_port_tuple]
            return
        session = self.active_streams.get(client_ip_port_tuple)
        if not session:
            print(f"{clock.get_timestamp_str(current_time)}: Session for {client_ip}:{client_port} not found. Stopping stream.")
            return
        payload_size = VIDEO_PACKET_SIZE_MAX
        payload = os.urandom(payload_size)
        data_pkt = create_base_packet(clock, self.ip_address, STREAMING_SERVER_PORT, client_ip, client_port,
                                      flags="PA", payload=payload, seq=session['server_seq'], ack=session['client_ack_of_server_seq'],
                                      eth_src=self.mac_address, eth_dst=client_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)
        client_host.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
             faucet_controller_host.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)
        session['packets_sent_this_stream'] = session.get('packets_sent_this_stream', 0) + 1
        if session['packets_sent_this_stream'] % 1000 == 1:
            self.add_host_event(current_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                                "video_stream_progress_server", "send_milestone", self.ip_address, client_ip,
                                STREAMING_SERVER_PORT, client_port,
                                f"video_stream_progress:packets_sent_total={session['packets_sent_this_stream']}")
        session['server_seq'] += payload_size
        next_event_time = current_time + datetime.timedelta(seconds=INTER_PACKET_DELAY_SECONDS)
        scheduler.add_event(Event(next_event_time, 2, self.send_streaming_data_packet,
                                  f"Server {self.ip_address} sends stream data to {client_ip}:{client_port}",
                                  args=(clock, scheduler, client_host, faucet_controller_host, client_ip_port_tuple, stream_end_time)))
class VulnServerMetasploitable(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
    def handle_nmap_syn(self, clock, scheduler, nmap_syn_packet: IP,
                        attacker_host: Attacker, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        src_ip = nmap_syn_packet[IP].src
        src_port = nmap_syn_packet[TCP].sport
        dst_port = nmap_syn_packet[TCP].dport
        current_time = clock.get_time()
        self.add_packet_to_pcap(nmap_syn_packet, timestamp=current_time.timestamp())
        is_open = dst_port in OPEN_PORTS.get(self.ip_address, set())
        response_pkt = None
        log_message = ""
        event_desc = ""
        if is_open:
            server_initial_seq = random.randint(0, 2**32 - 1)
            ack_to_attacker_seq = nmap_syn_packet[TCP].seq + 1
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="SA", seq=server_initial_seq, ack=ack_to_attacker_seq,
                                              eth_src=self.mac_address,
                                              eth_dst=router_gateway_host.mac_address_internal)
            log_message = f"Nmap SYN on OPEN port {dst_port} from {src_ip}:{src_port}. Sent SYN-ACK."
            event_desc = f"Target {self.ip_address} SYN-ACK for Nmap (port {dst_port} open)"
        else:
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="RA", seq=0, ack=nmap_syn_packet[TCP].seq + 1,
                                              eth_src=self.mac_address,
                                              eth_dst=router_gateway_host.mac_address_internal)
            log_message = f"Nmap SYN on CLOSED port {dst_port} from {src_ip}:{src_port}. Sent RST-ACK."
            event_desc = f"Target {self.ip_address} RST-ACK for Nmap (port {dst_port} closed)"
        response_pkt.time = current_time.timestamp()
        self.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        if gateway_traffic_pcap_writer: gateway_traffic_pcap_writer.write(response_pkt)
        event_time = current_time + datetime.timedelta(seconds=0.005)
        scheduler.add_event(Event(event_time, 1, attacker_host.handle_nmap_target_response,
                                  event_desc,
                                  args=(clock, scheduler, response_pkt, router_gateway_host, faucet_controller_host)))
class ClientNormal1(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.http_client_port_counter = CLIENT1_HTTP_INIT_PORT
        self.http_pid_counter = SIMULATED_CLIENT_PID_START + 100
        self.http_sessions = {}
    def start_web_browsing(self, scheduler, clock, target_server_hostname: str,
                           target_http_server_obj: 'WebServerDVWA',
                           dns_server_host: Host, faucet_controller_host: Host,
                           browse_start_dt: datetime.datetime, total_sim_duration_minutes: int):
        self.http_pid_counter += 1
        process_pid = self.http_pid_counter
        browse_duration_seconds = int(total_sim_duration_minutes * 60 * CLIENT1_BROWSE_DURATION_PERCENTAGE)
        browse_end_time = browse_start_dt + datetime.timedelta(seconds=browse_duration_seconds)
        self.add_host_event(browse_start_dt, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "process_exec", "", self.ip_address, "", "", "",
                            f"Start web browsing {target_server_hostname} until {browse_end_time.strftime('%H:%M:%S')}")
        session_key = (target_server_hostname, HTTP_SERVER_PORT)
        self.http_sessions[session_key] = {
            'client_seq': 0,
            'server_ack': 0,
            'dns_resolved_ip': None,
            'current_page_index': 0,
            'pages_since_last_form': 0,
            'logged_in': False,
            'logged_in_attempted': False,
            'process_pid': process_pid,
            'client_http_port': 0,
            'target_server_obj': target_http_server_obj,
            'browse_end_time': browse_end_time
        }
        event = Event(browse_start_dt, 0, self.send_dns_query,
                      f"Client {self.ip_address} DNS Query for {target_server_hostname}",
                      args=(clock, scheduler, target_server_hostname, dns_server_host, faucet_controller_host, process_pid, target_http_server_obj))
        scheduler.add_event(event)
        print(f"{clock.get_timestamp_str(browse_start_dt)}: Client {self.ip_address} (PID {process_pid}) starting web browsing. First event: DNS query for {target_server_hostname}")
    def send_dns_query(self, clock, scheduler, target_hostname: str, dns_server_host: Host,
                       faucet_controller_host: Host, process_pid: int, target_http_server_obj: WebServerDVWA):
        dns_query_id = random.randint(1, 65535)
        client_dns_port = random.randint(40000, 49000)
        fqdn_target_hostname = target_hostname if target_hostname.endswith('.') else target_hostname + '.'
        dest_mac = dns_server_host.mac_address_internal if hasattr(dns_server_host, 'mac_address_internal') else dns_server_host.mac_address
        dns_req_pkt = Ether(src=self.mac_address, dst=dest_mac)/ \
                      IP(dst=dns_server_host.ip_address, src=self.ip_address)/ \
                      UDP(sport=client_dns_port, dport=53)/ \
                      DNS(id=dns_query_id, rd=1, qd=DNSQR(qname=fqdn_target_hostname))
        current_time = clock.get_time()
        dns_req_pkt.time = current_time.timestamp()
        self.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time)
        dns_server_host.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time)
        self.add_host_event(current_time, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "sendto", self.ip_address, dns_server_host.ip_address,
                            client_dns_port, 53, f"DNS query for {fqdn_target_hostname}")
        event_time = current_time + datetime.timedelta(seconds=0.005)
        scheduler.add_event(Event(event_time, 1, dns_server_host.handle_dns_query,
                                  f"Router handles DNS Query from {self.ip_address} for {fqdn_target_hostname}",
                                  args=(clock, scheduler, dns_req_pkt, faucet_controller_host, self, target_http_server_obj)))
    def handle_dns_response(self, clock, scheduler, dns_response_packet: IP,
                            target_server_obj_after_dns: WebServerDVWA,
                            faucet_controller_host: Host):
        current_time = clock.get_time()
        dns_payload = dns_response_packet.getlayer(DNS)
        resolved_ip = None
        if dns_payload and dns_payload.an and isinstance(dns_payload.an, DNSRR) and dns_payload.an.type == 1:
            resolved_ip = dns_payload.an.rdata
            if isinstance(resolved_ip, bytes):
                resolved_ip = resolved_ip.decode('utf-8')
        original_hostname_bytes = dns_payload.qd.qname
        original_hostname = original_hostname_bytes.decode('utf-8')
        session_key = (original_hostname, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if session and resolved_ip:
            session['dns_resolved_ip'] = resolved_ip
            self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                                "network_data", "recvfrom", self.ip_address, dns_response_packet[IP].src,
                                dns_response_packet[UDP].dport, dns_response_packet[UDP].sport,
                                f"DNS response: {original_hostname} -> {resolved_ip}")
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} got DNS response: {original_hostname} -> {resolved_ip}")
            self.http_client_port_counter += random.randint(1, 5)
            client_http_port = self.http_client_port_counter
            session['client_http_port'] = client_http_port
            client_initial_seq = random.randint(0, 2**32 - 1)
            session['client_seq'] = client_initial_seq
            next_action_details = {'type': 'GET', 'path': DVWA_PAGES[0]}
            event_time = current_time + datetime.timedelta(seconds=0.01)
            scheduler.add_event(Event(event_time, 0, self.send_http_syn,
                                      f"Client {self.ip_address} SYN for HTTP to {resolved_ip}",
                                      args=(clock, scheduler, target_server_obj_after_dns, faucet_controller_host, client_http_port, client_initial_seq, next_action_details, session_key)))
        else:
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} failed to process DNS response for {original_hostname} or no session found.")
            if session:
                 self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                                "error_event", "", self.ip_address, "", "", "", f"DNS resolution failed for {original_hostname}")
    def send_http_syn(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host,
                      client_http_port: int, client_seq: int, next_action_details: dict, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session or not session['dns_resolved_ip']:
            print(f"Error: DNS not resolved or no session before sending HTTP SYN for session {session_key}")
            return
        resolved_ip = session['dns_resolved_ip']
        current_time = clock.get_time()
        syn_pkt = create_base_packet(clock, self.ip_address, client_http_port, resolved_ip, HTTP_SERVER_PORT,
                                     flags="S", seq=client_seq,
                                     eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "connect", self.ip_address, resolved_ip,
                            client_http_port, HTTP_SERVER_PORT, f"HTTP SYN to {resolved_ip} for {session_key[0]}")
        session['client_seq'] = client_seq + 1
        event_time = current_time + datetime.timedelta(seconds=0.02)
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_syn,
                                  f"Server {target_server_host.ip_address} handles HTTP SYN from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt, self.handle_http_syn_ack, next_action_details)))
    def handle_http_syn_ack(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host,
                            server_syn_ack_pkt: IP, next_action_details: dict):
        current_time = clock.get_time()
        client_http_port = server_syn_ack_pkt[TCP].dport
        server_ip = server_syn_ack_pkt[IP].src
        session_key = (DNS_QUERY_NAME, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: Client {self.ip_address} could not find HTTP session for {DNS_QUERY_NAME} on SYN-ACK receipt.")
            return
        if session['client_http_port'] != client_http_port:
            print(f"Error: Client {self.ip_address} received SYN-ACK on unexpected port {client_http_port}. Expected {session['client_http_port']}.")
            return
        session['server_ack'] = server_syn_ack_pkt[TCP].seq + 1
        ack_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                     eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        event_time = current_time + datetime.timedelta(seconds=0.01)
        scheduler.add_event(Event(event_time, 2, self.send_http_request,
                                  f"Client {self.ip_address} sends HTTP request for {next_action_details['path']}",
                                  args=(clock, scheduler, target_server_host, faucet_controller_host, next_action_details, session_key)))
    def send_http_request(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host,
                          action_details: dict, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session or not session['dns_resolved_ip'] or session['client_http_port'] == 0:
            print(f"Error: HTTP session/details not fully initialized for {session_key} before sending request.")
            return
        resolved_ip = session['dns_resolved_ip']
        client_http_port = session['client_http_port']
        current_time = clock.get_time()
        path = action_details['path']
        method = action_details['type']
        payload_body_str = ""
        if method == "POST":
            payload_body_str = action_details.get('payload', "")
        http_request_headers = f"{method} {path} HTTP/1.1\r\nHost: {DNS_QUERY_NAME.rstrip('.')}\r\nUser-Agent: {HTTP_USER_AGENT}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n"
        if session['logged_in'] and "PHPSESSID" not in http_request_headers:
             http_request_headers += f"Cookie: PHPSESSID=simulatedsessionid_{random.randint(10000,99999)}; security=low\r\n"
        if method == "POST":
            http_request_headers += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload_body_str.encode('utf-8'))}\r\n"
        full_http_request_str = http_request_headers + "\r\n" + payload_body_str
        request_pkt = create_base_packet(clock, self.ip_address, client_http_port, resolved_ip, HTTP_SERVER_PORT,
                                         flags="PA", payload=full_http_request_str.encode('utf-8'),
                                         seq=session['client_seq'], ack=session['server_ack'],
                                         eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        session['last_requested_path'] = path
        details_str = f"http_request:method={method},path={path},target_ip={resolved_ip},target_port={HTTP_SERVER_PORT}"
        if method == "POST" and payload_body_str:
            details_str += f",form_payload_summary={payload_body_str[:50].replace('&',';')}"
        self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_request", "send", self.ip_address, resolved_ip,
                            client_http_port, HTTP_SERVER_PORT, details_str)
        session['client_seq'] += len(full_http_request_str.encode('utf-8'))
        event_time = current_time + datetime.timedelta(seconds=0.05)
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_request,
                                  f"Server {target_server_host.ip_address} handles HTTP request from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, request_pkt)))
    def handle_http_response_ack(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, server_response_packet: IP):
        current_time = clock.get_time()
        session_key = (DNS_QUERY_NAME, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: Client {self.ip_address} could not find session for {DNS_QUERY_NAME} on HTTP response ACK.")
            return
        resolved_ip = session['dns_resolved_ip']
        client_http_port = session['client_http_port']
        requested_path = session.get('last_requested_path', 'N/A')
        self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "http_response_processed", "recv_ack", self.ip_address, resolved_ip,
                            client_http_port, HTTP_SERVER_PORT,
                            f"http_response_processed:status=200_OK,path={requested_path}")
        payload_len = 0
        if Raw in server_response_packet:
            payload_len = len(server_response_packet[Raw].load)
        session['server_ack'] = server_response_packet[TCP].seq + payload_len
        ack_for_response_pkt = create_base_packet(clock, self.ip_address, client_http_port, resolved_ip, HTTP_SERVER_PORT,
                                                  flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                                  eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        self.schedule_next_http_client_action(clock, scheduler, target_server_host, faucet_controller_host, session_key)
    def schedule_next_http_client_action(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: No session for {session_key} to schedule next HTTP action for Client {self.ip_address}.")
            return
        current_time = clock.get_time()
        if 'browse_end_time' in session and current_time >= session['browse_end_time']:
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} browsing session time ended for {session_key[0]}.")
            return
        next_action = None
        delay_seconds = random.uniform(0.5, 3.0)
        if not session.get('logged_in_attempted', False):
            next_action = {'type': 'POST', 'path': '/dvwa/login.php', 'payload': DVWA_LOGIN_PAYLOAD}
            session['logged_in_attempted'] = True
        else:
            if session.get('pages_since_last_form', 0) >= CLIENT1_PAGES_PER_FORM_SUBMISSION and DVWA_BENIGN_FORMS:
                form_choice = random.choice(DVWA_BENIGN_FORMS)
                next_action = {'type': form_choice['method'], 'path': form_choice['target'], 'payload': form_choice['payload']}
                session['pages_since_last_form'] = 0
            else:
                page_idx = session.get('current_page_index', 0)
                page_path = DVWA_PAGES[page_idx % len(DVWA_PAGES)]
                if page_path == "/dvwa/login.php" and session.get('logged_in_attempted', False) :
                    page_idx +=1
                    session['current_page_index'] = page_idx % len(DVWA_PAGES)
                    page_path = DVWA_PAGES[session['current_page_index']]
                next_action = {'type': 'GET', 'path': page_path}
                session['current_page_index'] = page_idx + 1
                session['pages_since_last_form'] = session.get('pages_since_last_form', 0) + 1
        if next_action:
            event_time = current_time + datetime.timedelta(seconds=delay_seconds)
            action_path_desc = next_action.get('path', 'unknown path')
            description = f"Client {self.ip_address} {next_action['type']} {action_path_desc} to {target_server_host.hostname}"
            scheduler.add_event(Event(event_time, 2, self.send_http_request, description,
                                      args=(clock, scheduler, target_server_host, faucet_controller_host, next_action, session_key)))
        else:
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} no next HTTP action decided for {session_key[0]}. Ending session actions.")
class ClientNormal2(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.current_streaming_port = STREAMING_CLIENT_INIT_PORT
        self.client_pid_counter = SIMULATED_CLIENT_PID_START
        self.active_streams = {}
    def start_video_stream(self, scheduler, clock, target_server_host: 'WebServerDVWA', faucet_controller_host: Host, stream_start_dt: datetime.datetime, total_sim_duration_minutes: int):
        self.current_streaming_port += random.randint(1, 10)
        client_port = self.current_streaming_port
        self.client_pid_counter += 1
        process_pid = self.client_pid_counter
        actual_stream_duration_seconds = int(total_sim_duration_minutes * 60 * CLIENT2_STREAMING_DURATION_PERCENTAGE)
        self.add_host_event(stream_start_dt, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "process_exec", "", self.ip_address, "", "", "",
                            f"video_stream_started:target_server={target_server_host.ip_address},target_port={STREAMING_SERVER_PORT},expected_duration_seconds={actual_stream_duration_seconds}")
        client_initial_seq = random.randint(0, 2**32 - 1)
        self.active_streams[(target_server_host.ip_address, STREAMING_SERVER_PORT)] = {
            'client_seq': client_initial_seq,
            'server_ack_of_client_seq': 0,
            'process_pid': process_pid
        }
        event = Event(stream_start_dt, 0, self.send_streaming_syn,
                      f"Client {self.ip_address}:{client_port} SYN for stream to {target_server_host.ip_address}",
                      args=(clock, scheduler, target_server_host, faucet_controller_host, client_port, client_initial_seq, process_pid, actual_stream_duration_seconds))
        scheduler.add_event(event)
        print(f"{clock.get_timestamp_str(stream_start_dt)}: Client {self.ip_address}:{client_port} (PID: {process_pid}) scheduled video stream to {target_server_host.ip_address}. Duration: {actual_stream_duration_seconds}s.")
    def send_streaming_syn(self, clock, scheduler, target_server_host: 'WebServerDVWA', faucet_controller_host: Host, client_port: int, client_seq: int, process_pid: int, actual_stream_duration_seconds: int):
        current_time = clock.get_time()
        syn_pkt = create_base_packet(clock, self.ip_address, client_port, target_server_host.ip_address,
                                     STREAMING_SERVER_PORT, flags="S", seq=client_seq,
                                     eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        self.add_host_event(current_time, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "connect", self.ip_address, target_server_host.ip_address,
                            client_port, STREAMING_SERVER_PORT, "TCP SYN sent for video stream")
        event_time = current_time + datetime.timedelta(seconds=0.02)
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_streaming_syn,
                                  f"Server {target_server_host.ip_address} handles stream SYN from {self.ip_address}:{client_port}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt, self.handle_streaming_syn_ack, actual_stream_duration_seconds)))
    def handle_streaming_syn_ack(self, clock, scheduler, target_server_host: 'WebServerDVWA', faucet_controller_host: Host, server_syn_ack_pkt: IP, actual_stream_duration_seconds: int):
        current_time = clock.get_time()
        client_port = server_syn_ack_pkt[TCP].dport
        server_ip = server_syn_ack_pkt[IP].src
        session = self.active_streams.get((server_ip, STREAMING_SERVER_PORT))
        if not session:
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_port} received SYN-ACK from {server_ip} but no active session found. Ignoring.")
            return
        session['client_seq'] = server_syn_ack_pkt[TCP].ack
        session['server_ack_of_client_seq'] = server_syn_ack_pkt[TCP].seq + 1
        ack_pkt = create_base_packet(clock, self.ip_address, client_port, server_ip, STREAMING_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack_of_client_seq'],
                                     eth_src=self.mac_address, eth_dst=target_server_host.mac_address)
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        process_pid = session.get('process_pid', 0)
        self.add_host_event(current_time, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "video_stream_established_client", "connect_ack", self.ip_address, server_ip,
                            client_port, STREAMING_SERVER_PORT,
                            f"video_stream_established:server_ip={server_ip}")
        client_ip_port_tuple = (self.ip_address, client_port)
        server_session = target_server_host.active_streams.get(client_ip_port_tuple)
        if server_session:
            server_session['client_ack_of_server_seq'] = session['server_ack_of_client_seq']
        else:
            print(f"WARNING: {clock.get_timestamp_str(current_time)}: Server {target_server_host.ip_address} has no active stream for {client_ip_port_tuple} upon client ACK.")
        stream_end_time = current_time + datetime.timedelta(seconds=actual_stream_duration_seconds)
        event_time = current_time + datetime.timedelta(seconds=INTER_PACKET_DELAY_SECONDS)
        scheduler.add_event(Event(event_time, 2, target_server_host.send_streaming_data_packet,
                                  f"Server {server_ip} starts stream data to {self.ip_address}:{client_port}",
                                  args=(clock, scheduler, self, faucet_controller_host, client_ip_port_tuple, stream_end_time)))
        print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_port} ACKed stream with {server_ip}. Scheduled server's first data packet.")
class FaucetController(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
class RouterGateway(Host):
    def __init__(self, ip_address, hostname, external_ip_address, output_dir="output"):
        self.external_ip_address = external_ip_address
        self.mac_address_internal = f"00:00:00:AA:BB:{random.randint(10,99):02X}"
        self.mac_address_external = f"00:00:00:DD:EE:{random.randint(10,99):02X}"
        super().__init__(ip_address, hostname, output_dir, mac_address=self.mac_address_internal)
    def add_packet_to_pcap(self, packet, timestamp: float | None = None, direction: str | None = None):
        if self.pcap_writer:
            if timestamp is not None:
                packet.time = timestamp
            elif not hasattr(packet, 'time') or packet.time is None:
                packet.time = datetime.datetime.now().timestamp()
            self.pcap_writer.write(packet)
    def handle_dns_query(self, clock, scheduler, query_packet: IP,
                         faucet_controller_host: Host, client_host_who_queried: ClientNormal1,
                         target_http_server_obj: WebServerDVWA):
        current_time = clock.get_time()
        dns_request_layer = query_packet.getlayer(DNS)
        if not dns_request_layer or not dns_request_layer.qd:
            print(f"{clock.get_timestamp_str(current_time)}: Router received non-DNS query or malformed DNS query. Dropping.")
            return
        qname_bytes = dns_request_layer.qd.qname
        qname_str = qname_bytes.decode('utf-8')
        client_ip = query_packet[IP].src
        client_udp_sport = query_packet[UDP].sport
        response_ip_str = None
        if qname_str == DNS_QUERY_NAME:
            response_ip_str = VICTIM_WEBSRV_DVWA_IP
        if response_ip_str:
            dns_response_pkt = Ether(dst=client_host_who_queried.mac_address, src=self.mac_address_internal)/ \
                               IP(dst=client_ip, src=self.ip_address)/ \
                               UDP(dport=client_udp_sport, sport=53)/ \
                               DNS(id=dns_request_layer.id, qr=1, aa=1, qd=dns_request_layer.qd, \
                                   an=DNSRR(rrname=qname_bytes, type='A', rdata=response_ip_str, ttl=600))
            dns_response_pkt.time = current_time.timestamp()
            self.add_packet_to_pcap(dns_response_pkt, timestamp=dns_response_pkt.time)
            if faucet_controller_host:
                faucet_controller_host.add_packet_to_pcap(dns_response_pkt, timestamp=dns_response_pkt.time)
            self.add_host_event(current_time, 0, 0, 0, "dnsmasq",
                                "network_data", "sendto", self.ip_address, client_ip,
                                53, client_udp_sport,
                                f"DNS response for {qname_str} -> {response_ip_str}")
            event_time = current_time + datetime.timedelta(seconds=0.005)
            scheduler.add_event(Event(event_time, 1, client_host_who_queried.handle_dns_response,
                                      f"Client {client_host_who_queried.ip_address} handles DNS Response for {qname_str}",
                                      args=(clock, scheduler, dns_response_pkt, target_http_server_obj, faucet_controller_host)))
        else:
            print(f"{clock.get_timestamp_str(current_time)}: Router ({self.ip_address}) has no DNS record for {qname_str}. NXDOMAIN not implemented.")
            self.add_host_event(current_time, 0, 0, 0, "dnsmasq",
                                "dns_resolution_fail", "", self.ip_address, client_ip,
                                53, client_udp_sport,
                                f"No DNS record for {qname_str}")
class MasterClock:
    def __init__(self, start_time=None):
        self.current_time = start_time if start_time else datetime.datetime.now()
    def get_time(self) -> datetime.datetime:
        return self.current_time
    def advance_time(self, new_time: datetime.datetime):
        if new_time < self.current_time:
            raise ValueError("Cannot advance time to the past.")
        self.current_time = new_time
    def get_timestamp_str(self, dt_obj: datetime.datetime = None) -> str:
        if dt_obj is None:
            dt_obj = self.current_time
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')
class Event:
    def __init__(self, timestamp: datetime.datetime, priority: int, action, description: str, args: tuple = None):
        self.timestamp = timestamp
        self.priority = priority
        self.action = action
        self.description = description
        self.args = args if args is not None else ()
    def __lt__(self, other):
        if self.timestamp == other.timestamp:
            return self.priority < other.priority
        return self.timestamp < other.timestamp
class EventScheduler:
    def __init__(self):
        self._events = []
    def add_event(self, event: Event):
        heapq.heappush(self._events, event)
    def get_next_event(self) -> Event | None:
        if not self.is_empty():
            return heapq.heappop(self._events)
        return None
    def is_empty(self) -> bool:
        return not self._events
def create_output_directory(dir_name="output"):
    os.makedirs(dir_name, exist_ok=True)
    print(f"Output directory '{dir_name}' ensured.")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Master Data Generator for Network Simulation")
    parser.add_argument(
        "--duration",
        type=int,
        default=60,
        help="Total simulation duration in minutes (default: 60)"
    )
    args = parser.parse_args()
    OUTPUT_DIR = "output"
    create_output_directory(OUTPUT_DIR)
    master_clock = MasterClock()
    event_scheduler = EventScheduler()
    print(f"Simulation setup complete. Start time: {master_clock.get_timestamp_str()}. Duration: {args.duration} minutes.")
    attacker = Attacker(ATTACKER_EXT_KALI_IP, HOSTNAME_ATTACKER_KALI, OUTPUT_DIR)
    dvwa_server = WebServerDVWA(VICTIM_WEBSRV_DVWA_IP, VICTIM_WEBSRV_DVWA_HOSTNAME, OUTPUT_DIR)
    metasploitable_server = VulnServerMetasploitable(VICTIM_VULNSRV_METASPLOITABLE_IP, HOSTNAME_METASPLOITABLE, OUTPUT_DIR)
    client1 = ClientNormal1(CLIENT_NORMAL_1_IP, HOSTNAME_CLIENT_NORMAL_1, OUTPUT_DIR)
    client2 = ClientNormal2(CLIENT_NORMAL_2_IP, HOSTNAME_CLIENT_NORMAL_2, OUTPUT_DIR)
    faucet_controller = FaucetController(FAUCET_CONTROLLER_VM_IP, HOSTNAME_FAUCET_CONTROLLER, OUTPUT_DIR)
    router_gateway = RouterGateway(ROUTER_INTERNAL_IP, HOSTNAME_ROUTER_GATEWAY, ROUTER_EXTERNAL_IP, OUTPUT_DIR)
    print("Host instances created.")
    attacker.init_pcap_writer("attacker_traffic.pcap")
    dvwa_server.init_pcap_writer("dvwa_server_traffic.pcap")
    metasploitable_server.init_pcap_writer("metasploitable_server_traffic.pcap")
    client1.init_pcap_writer("client1_traffic.pcap")
    client2.init_pcap_writer("client2_traffic.pcap")
    faucet_controller.init_pcap_writer("faucet_controller_traffic.pcap")
    gateway_traffic_pcap_path = os.path.join(OUTPUT_DIR, "gateway_traffic.pcap")
    gateway_traffic_pcap_writer = PcapWriter(gateway_traffic_pcap_path, append=True, sync=True)
    print(f"Gateway traffic PCAP writer initialized at {gateway_traffic_pcap_path}")
    sim_start_time = master_clock.get_time()
    simulation_end_time = sim_start_time + datetime.timedelta(minutes=args.duration)
    if isinstance(client2, ClientNormal2) and isinstance(dvwa_server, WebServerDVWA) and isinstance(faucet_controller, FaucetController):
        video_stream_start_delay_seconds = 5
        video_stream_event_time = sim_start_time + datetime.timedelta(seconds=video_stream_start_delay_seconds)
        print(f"DEBUG: Scheduling initial video stream for {client2.hostname} at {master_clock.get_timestamp_str(video_stream_event_time)}")
        client2.start_video_stream(event_scheduler, master_clock, dvwa_server, faucet_controller,
                                   video_stream_event_time, args.duration)
    else:
        print(f"WARN: Types mismatch for video stream scheduling: client2={type(client2)}, dvwa_server={type(dvwa_server)}, faucet={type(faucet_controller)}")
    if isinstance(client1, ClientNormal1) and isinstance(dvwa_server, WebServerDVWA) and \
       isinstance(router_gateway, RouterGateway) and isinstance(faucet_controller, FaucetController):
        web_browse_start_delay_seconds = 2
        web_browse_event_time = sim_start_time + datetime.timedelta(seconds=web_browse_start_delay_seconds)
        print(f"DEBUG: Scheduling initial web browsing for {client1.hostname} at {master_clock.get_timestamp_str(web_browse_event_time)}")
        client1.start_web_browsing(event_scheduler, master_clock, DNS_QUERY_NAME, dvwa_server,
                                   router_gateway, faucet_controller, web_browse_event_time, args.duration)
    else:
        print(f"WARN: Types mismatch for web browsing scheduling: client1={type(client1)}, dvwa_server={type(dvwa_server)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")
    ALL_HOSTS = { host.ip_address: host for host in [attacker, dvwa_server, metasploitable_server, client1, client2, faucet_controller, router_gateway] if host}
    if isinstance(attacker, Attacker) and isinstance(router_gateway, RouterGateway) and \
       isinstance(faucet_controller, FaucetController):
        nmap_scan_event_time = sim_start_time + datetime.timedelta(seconds=NMAP_SCAN_START_DELAY_SECONDS)
        print(f"DEBUG: Scheduling initial Nmap scan for {attacker.hostname} at {master_clock.get_timestamp_str(nmap_scan_event_time)}")
        attacker.start_nmap_scan(event_scheduler, master_clock, NMAP_TARGET_IPS,
                                NMAP_TARGET_PORTS_COMMON, router_gateway,
                                faucet_controller, ALL_HOSTS, nmap_scan_event_time,
                                False, simulation_end_time)
    else:
        print(f"WARN: Types mismatch for Nmap scan scheduling: attacker={type(attacker)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")
    if isinstance(attacker, Attacker) and isinstance(dvwa_server, WebServerDVWA) and \
       isinstance(router_gateway, RouterGateway) and isinstance(faucet_controller, FaucetController):
        exploitation_start_delay_seconds = 20
        exploitation_event_time = sim_start_time + datetime.timedelta(seconds=exploitation_start_delay_seconds)
        print(f"DEBUG: Scheduling initial DVWA exploitation for {attacker.hostname} at {master_clock.get_timestamp_str(exploitation_event_time)}")
        attacker.start_dvwa_exploitation(event_scheduler, master_clock, dvwa_server,
                                        router_gateway, faucet_controller, exploitation_event_time)
    else:
        print(f"WARN: Types mismatch for DVWA exploitation scheduling: attacker={type(attacker)}, dvwa_server={type(dvwa_server)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")
    print("\n--- Starting Main Simulation Loop ---")
    processed_event_count = 0
    ALL_HOSTS = {
        attacker.ip_address: attacker,
        dvwa_server.ip_address: dvwa_server,
        metasploitable_server.ip_address: metasploitable_server,
        client1.ip_address: client1,
        client2.ip_address: client2,
        faucet_controller.ip_address: faucet_controller,
        router_gateway.ip_address: router_gateway
    }
    while not event_scheduler.is_empty():
        next_event = event_scheduler.get_next_event()
        if next_event is None:
            break
        if next_event.timestamp > simulation_end_time:
            print(f"Event '{next_event.description}' at {master_clock.get_timestamp_str(next_event.timestamp)} is beyond simulation end time ({master_clock.get_timestamp_str(simulation_end_time)}). Stopping.")
            break
        if next_event.timestamp < master_clock.get_time():
            print(f"Warning: Event '{next_event.description}' timestamp {master_clock.get_timestamp_str(next_event.timestamp)} is in the past compared to current clock {master_clock.get_timestamp_str()}. Potential scheduling issue. Skipping.")
            continue
        master_clock.advance_time(next_event.timestamp)
        if "stream data" not in next_event.description and "ACKs HTTP Response" not in next_event.description :
             print(f"[{master_clock.get_timestamp_str()}] Processing Event ({next_event.priority}): {next_event.description}")
        try:
            next_event.action(*next_event.args)
            processed_event_count += 1
        except Exception as e:
            print(f"ERROR executing event action for '{next_event.description}' at {master_clock.get_timestamp_str()}: {e}")
            import traceback
            traceback.print_exc()
    if event_scheduler.is_empty():
        print(f"--- Event scheduler became empty at simulation time: {master_clock.get_timestamp_str()} ---")
    print(f"--- Main Simulation Loop Finished. Processed {processed_event_count} events. ---")
    print(f"Final Simulation Time: {master_clock.get_timestamp_str()}")
    print("\nStarting cleanup phase...")
    if 'attacker' in locals(): attacker.write_events_to_csv("attacker_events.csv")
    if 'dvwa_server' in locals(): dvwa_server.write_events_to_csv("dvwa_server_events.csv")
    if 'metasploitable_server' in locals(): metasploitable_server.write_events_to_csv("metasploitable_server_events.csv")
    if 'client1' in locals(): client1.write_events_to_csv("client1_events.csv")
    if 'client2' in locals(): client2.write_events_to_csv("client2_events.csv")
    if 'faucet_controller' in locals(): faucet_controller.write_events_to_csv("faucet_controller_events.csv")
    if 'attacker' in locals(): attacker.close_pcap_writer()
    if 'dvwa_server' in locals(): dvwa_server.close_pcap_writer()
    if 'metasploitable_server' in locals(): metasploitable_server.close_pcap_writer()
    if 'client1' in locals(): client1.close_pcap_writer()
    if 'client2' in locals(): client2.close_pcap_writer()
    if 'faucet_controller' in locals(): faucet_controller.close_pcap_writer()
    if 'gateway_traffic_pcap_writer' in locals() and gateway_traffic_pcap_writer:
        if hasattr(gateway_traffic_pcap_writer, 'closed') and not gateway_traffic_pcap_writer.closed:
             gateway_traffic_pcap_writer.close()
        print("Gateway traffic PCAP writer closed.")
    print("Cleanup complete. Simulation finished.")
