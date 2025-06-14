import datetime
import time
import heapq
import os
import argparse
import csv
import random
from scapy.utils import PcapWriter
# Using scapy.all to get common layers and functions like Raw
from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR, DNSRR #, ICMP, ARP, NTP, SSL, TLS # Future use
# from scapy.layers.http import HTTPRequest, HTTPResponse, HTTP # Decided to craft raw HTTP

# Network Configuration Constants
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


# Host Constants (can be moved to a config file later)
# Already defined:
# VICTIM_WEBSRV_DVWA_IP, VICTIM_WEBSRV_DVWA_HOSTNAME
# VICTIM_VULNSRV_METASPLOITABLE_IP
# CLIENT_NORMAL_1_IP
# CLIENT_NORMAL_2_IP
# ATTACKER_EXT_KALI_IP
# FAUCET_CONTROLLER_VM_IP
# ROUTER_INTERNAL_IP

# DNS and Web Browsing Traffic Constants
DNS_SERVER_IP = ROUTER_INTERNAL_IP # Router acts as DNS forwarder/server
DNS_QUERY_NAME = VICTIM_WEBSRV_DVWA_HOSTNAME + "." # Ensure FQDN ends with a dot
HTTP_SERVER_PORT = 80
CLIENT1_HTTP_INIT_PORT = 49200
DVWA_PAGES = ["/dvwa/login.php", "/dvwa/vulnerabilities/sqli/", "/dvwa/vulnerabilities/xss_r/", "/dvwa/phpinfo.php", "/dvwa/about.php"] # Added more diverse pages
DVWA_LOGIN_PAYLOAD = "username=admin&password=password&Login=Login"
DVWA_BENIGN_FORM_TARGET = "/dvwa/vulnerabilities/exec/" # Example target for benign POST
DVWA_BENIGN_FORM_PAYLOAD = "ip=127.0.0.1&submit=Submit" # Benign, as it's just pinging localhost within the container
HTTP_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"


# Nmap Scan Traffic Constants
NMAP_TARGET_IPS = [VICTIM_WEBSRV_DVWA_IP, VICTIM_VULNSRV_METASPLOITABLE_IP]
NMAP_TARGET_PORTS_COMMON = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 3306, 3389, 5432, 5900, 6000, 8009, 8080, 8180]
OPEN_PORTS = {
    VICTIM_WEBSRV_DVWA_IP: {80, 443}, # HTTP, HTTPS (simulated as open for TCP SYN scan)
    VICTIM_VULNSRV_METASPLOITABLE_IP: { # Common Metasploitable2 ports
        21, # FTP
        22, # SSH
        23, # Telnet
        25, # SMTP
        53, # DNS
        80, # HTTP (Apache tomcat)
        111, # RPCbind
        139, # NetBIOS-SSN (Samba smbd)
        445, # Microsoft-DS (Samba smbd)
        512, # exec
        513, # login
        514, # shell (cmd)
        1099, # Java RMI Registry
        1524, # ingreslock (bindshell)
        2049, # NFS
        2121, # CCProxy FTP
        3306, # MySQL
        3632, # distccd
        5432, # PostgreSQL
        5900, # VNC
        6000, # X11
        6667, # UnrealIRCd
        8009, # AJP/1.3 (Apache Tomcat)
        8180, # Apache Tomcat (alternative HTTP)
        # Metasploitable also has many UDP ports, but -sS is TCP SYN scan
    }
}
ATTACKER_NMAP_INIT_SPORT = 50000
NMAP_SCAN_DELAY_PER_PACKET = 0.03
ATTACKER_PID_NMAP = 7000

SIMULATED_WEBSERVER_PID = 80  # Example PID for web server process
# DVWA Exploitation Constants
ATTACKER_HTTP_INIT_PORT = 51000
SQLI_TARGET_PATH = "/dvwa/vulnerabilities/sqli/?id={payload}&Submit=Submit#" # GET request
SQLI_PAYLOADS = ["1' OR '1'='1", "1' AND 1=2 UNION SELECT user, password FROM users WHERE user_id = '1"] # Example payloads
CMD_INJ_TARGET_PATH = "/dvwa/vulnerabilities/exec/" # POST request
CMD_INJ_FIELD_NAME = "ip" # Field to inject into
CMD_INJ_PAYLOADS = ["127.0.0.1; ls -la /tmp", "127.0.0.1 && cat /etc/passwd"] # Example payloads
ATTACKER_PID_EXPLOIT = 7001 # PID for attacker's exploit script/actions
DVWA_APACHE_PID = SIMULATED_WEBSERVER_PID # Defined earlier, e.g., 80
DVWA_SHELL_PID = 1080 # PID for shell spawned by command injection


# Streaming Traffic Constants
STREAMING_CLIENT_INIT_PORT = 49152
STREAMING_SERVER_PORT = 443  # HTTPS
VIDEO_PACKET_SIZE_MIN = 1000
VIDEO_PACKET_SIZE_MAX = 1400
INTER_PACKET_DELAY_SECONDS = 0.05
SIMULATED_CLIENT_PID_START = 5000
DEFAULT_CLIENT_UID = 1000
DEFAULT_SERVER_UID = 0  # Typically root or www-data for server processes

# Hostnames for those not having one yet
HOSTNAME_METASPLOITABLE = "metasploitable.internal.local"
HOSTNAME_CLIENT_NORMAL_1 = "client-normal-1.internal.local"
HOSTNAME_CLIENT_NORMAL_2 = "client-normal-2.internal.local"
HOSTNAME_ATTACKER_KALI = "kali.attacker.net" # External network hostname
HOSTNAME_FAUCET_CONTROLLER = "faucet-controller.internal.local"
HOSTNAME_ROUTER_GATEWAY = "router.internal.local"


# Helper function for packet creation
def create_base_packet(clock, src_ip, sport, dst_ip, dport, flags="", payload=None, seq=None, ack=None, eth_src=None, eth_dst=None):
    """Creates a base Ethernet/IP/TCP packet with optional payload."""
    # Placeholder MAC addresses if not provided - in a real SDN simulation, these would be learned or assigned
    auto_eth_src = "00:00:00:00:00:01" if eth_src is None else eth_src # Example client MAC
    auto_eth_dst = "00:00:00:00:00:02" if eth_dst is None else eth_dst # Example server MAC
    # TODO: MACs should ideally be properties of Host objects or dynamically resolved via ARP simulation

    eth = Ether(src=auto_eth_src, dst=auto_eth_dst)
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
        # Ensure clock.get_time() returns a datetime object, then get timestamp()
        current_sim_time = clock.get_time()
        if isinstance(current_sim_time, datetime.datetime):
            pkt.time = current_sim_time.timestamp()
        else: # Fallback if clock.get_time() is already a timestamp float
            pkt.time = current_sim_time
    else:
        pkt.time = datetime.datetime.now().timestamp() # Fallback for non-simulation use

    return pkt


class Host:
    """Base class for a host in the simulation."""
    def __init__(self, ip_address, hostname, output_dir="output"):
        self.ip_address = ip_address
        self.hostname = hostname
        self.host_events = []  # Stores dictionaries for CSV rows
        self.pcap_writer = None
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True) # Ensure output dir exists

    def add_host_event(self, timestamp_obj: datetime.datetime, pid, ppid, uid, comm,
                       event_type, syscall, src_ip, dst_ip, src_port, dst_port, details):
        """Adds a host event to the internal list."""
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
        """Initializes the PCAP writer for this host."""
        if pcap_filename:
            full_path = os.path.join(self.output_dir, pcap_filename)
            self.pcap_writer = PcapWriter(full_path, append=True, sync=True)
            print(f"PCAP writer initialized for {self.hostname} at {full_path}")

    def add_packet_to_pcap(self, packet, timestamp: float | None = None):
        """Writes a packet to this host's PCAP file."""
        if self.pcap_writer:
            if timestamp is not None:
                packet.time = timestamp
            self.pcap_writer.write(packet)

    def close_pcap_writer(self):
        """Closes the PCAP writer if it's open."""
        if self.pcap_writer:
            self.pcap_writer.close()
            print(f"PCAP writer closed for {self.hostname}")
            self.pcap_writer = None # Avoid re-closing

    def write_events_to_csv(self, csv_filename: str | None):
        """Writes all collected host events to a CSV file."""
        if csv_filename and self.host_events:
            full_path = os.path.join(self.output_dir, csv_filename)
            print(f"Writing {len(self.host_events)} events for {self.hostname} to {full_path}...")
            with open(full_path, 'w', newline='') as csvfile:
                if not self.host_events: # Should not happen due to check above, but good practice
                    return
                # Use the keys from the first event dictionary as headers
                fieldnames = self.host_events[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.host_events)
            print(f"Finished writing events for {self.hostname} to {full_path}")


# Host Subclasses
class Attacker(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.http_sessions = {} # For managing HTTP state during exploitation
        self.http_client_port_counter = ATTACKER_HTTP_INIT_PORT # Separate port counter for exploit HTTP sessions


    def start_dvwa_exploitation(self, scheduler, clock, dvwa_server_host: WebServerDVWA,
                                router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                exploitation_start_dt: datetime.datetime):

        self.add_host_event(exploitation_start_dt, ATTACKER_PID_EXPLOIT, 1, 0, "exploit.py",
                            "process_exec", "", self.ip_address, "", "", "",
                            "Begin DVWA exploitation (SQLi, CmdInj)")

        # First, establish an HTTP session (SYN, SYN-ACK, ACK)
        self.http_client_port_counter += random.randint(1, 50) # Vary starting port slightly
        client_http_port = self.http_client_port_counter
        client_initial_seq = random.randint(0, 2**32 - 1)

        session_key = (dvwa_server_host.ip_address, HTTP_SERVER_PORT)
        self.http_sessions[session_key] = {
            'client_seq': client_initial_seq, # Initial sequence for SYN
            'server_ack': 0,                  # Server's ACK for our data, starts at 0
            'client_http_port': client_http_port,
            'process_pid': ATTACKER_PID_EXPLOIT,
            # Define sequence of malicious actions. Can be extended.
            'actions': ['sqli_1', 'cmd_inj_1'],
            'logged_in': False # Exploits might not need login, or might try to bypass
        }

        # Special type to trigger first exploit after HTTP setup
        # The actual exploit path/payload will be determined by send_next_exploit_request
        next_action_details = {'type': 'EXPLOIT_INIT_CONNECTION'}

        event_time = exploitation_start_dt # Start immediately
        scheduler.add_event(Event(event_time, 2, self.send_http_syn_for_exploit,
                                  f"Attacker SYN for DVWA Exploit to {dvwa_server_host.ip_address}",
                                  args=(clock, scheduler, dvwa_server_host, router_gateway_host,
                                        faucet_controller_host, client_http_port, client_initial_seq,
                                        next_action_details, session_key)))
        print(f"{clock.get_timestamp_str(exploitation_start_dt)}: Attacker {self.ip_address} (PID {ATTACKER_PID_EXPLOIT}) scheduled DVWA exploitation sequence.")

    def send_http_syn_for_exploit(self, clock, scheduler, target_server_host: WebServerDVWA,
                                  router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                  client_http_port: int, client_seq: int, next_action_details: dict, session_key: tuple):
        current_time = clock.get_time()
        syn_pkt = create_base_packet(clock, self.ip_address, client_http_port, target_server_host.ip_address,
                                     HTTP_SERVER_PORT, flags="S", seq=client_seq,
                                     eth_src=self.hostname, # Placeholder MAC
                                     eth_dst=router_gateway_host.mac_address_external_placeholder)

        packet_timestamp = current_time.timestamp()
        syn_pkt.time = packet_timestamp
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        router_gateway_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        # Target server will also log this packet when it receives it.
        # target_server_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)

        session = self.http_sessions.get(session_key)
        if session:
             session['client_seq'] = client_seq + 1 # SYN consumes a sequence number
             self.add_host_event(current_time, session['process_pid'], 1, 0, "exploit.py",
                                "network_connect", "connect", self.ip_address, target_server_host.ip_address,
                                client_http_port, HTTP_SERVER_PORT, f"HTTP SYN to {target_server_host.ip_address} for exploit session")

        event_time = current_time + datetime.timedelta(seconds=0.02) # RTT
        # Server uses its generic handle_http_syn, but needs Attacker's specific SYN-ACK handler
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_syn,
                                  f"DVWA handles Attacker HTTP SYN from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt,
                                        self.handle_http_syn_ack_for_exploit, next_action_details)))

    def handle_http_syn_ack_for_exploit(self, clock, scheduler, target_server_host: WebServerDVWA,
                                        router_gateway_host: 'RouterGateway', faucet_controller_host: Host,
                                        server_syn_ack_pkt: IP, next_action_details: dict):
        current_time = clock.get_time()
        client_http_port = server_syn_ack_pkt[TCP].dport
        server_ip = server_syn_ack_pkt[IP].src # Should be dvwa_server_host.ip_address

        session_key = (server_ip, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)
        if not session or session['client_http_port'] != client_http_port:
            print(f"Error: Attacker received unexpected SYN-ACK for exploit session from {server_ip}:{server_syn_ack_pkt[TCP].sport}")
            return

        # Attacker logs the SYN-ACK
        self.add_packet_to_pcap(server_syn_ack_pkt, timestamp=current_time.timestamp())

        session['server_ack'] = server_syn_ack_pkt[TCP].seq + 1 # Server's SYN-ACK also consumes 1 seq number

        ack_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                     eth_src=self.hostname, # Placeholder MAC
                                     eth_dst=router_gateway_host.mac_address_external_placeholder)

        packet_timestamp = current_time.timestamp()
        ack_pkt.time = packet_timestamp
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        router_gateway_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp) # Server sees the ACK

        # Connection established. Proceed with the first exploit action.
        event_time = current_time + datetime.timedelta(seconds=0.01)
        scheduler.add_event(Event(event_time, 2, self.send_next_exploit_request,
                                  "Attacker sends first exploit request",
                                  args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
        # print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} ACKed HTTP for exploit. Scheduled first exploit request.")

    def send_next_exploit_request(self, clock, scheduler, target_server_host: WebServerDVWA,
                                  router_gateway_host: 'RouterGateway', faucet_controller_host: Host, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session or not session['actions']:
            print(f"{clock.get_timestamp_str(clock.get_time())}: No more exploit actions for Attacker on session {session_key}.")
            # Optionally, initiate TCP FIN sequence here
            return

        action_key = session['actions'].pop(0)
        exploit_details = {} # This will store type, path, payload_str, description

        if action_key == 'sqli_1':
            # For GET requests, payload is part of the path.
            payload_url_encoded = SQLI_PAYLOADS[0].replace(" ", "%20").replace("'", "%27") # Basic URL encoding
            path = SQLI_TARGET_PATH.format(payload=payload_url_encoded)
            exploit_details = {'type': 'GET', 'path': path, 'description': 'SQL Injection Attempt (Users Table)'}
        elif action_key == 'cmd_inj_1':
            # For POST requests, payload is in the body.
            # Simple URL encoding for the command part.
            cmd_payload_encoded = CMD_INJ_PAYLOADS[0].replace(" ", "%20") # Example: "127.0.0.1;%20ls%20-la%20/tmp"
            post_body = f"{CMD_INJ_FIELD_NAME}={cmd_payload_encoded}&Submit=Submit"
            exploit_details = {'type': 'POST', 'path': CMD_INJ_TARGET_PATH, 'payload_str': post_body, 'description': 'Command Injection Attempt (ls /tmp)'}
        else:
            print(f"Unknown exploit action key: {action_key}")
            return

        self.send_http_exploit_payload(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, exploit_details, session_key)

    def send_http_exploit_payload(self, clock, scheduler, target_server_host: WebServerDVWA,
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
        payload_body_str = exploit_details.get('payload_str', "") # For POST requests

        http_request_line_and_headers = f"{method} {path} HTTP/1.1\r\nHost: {HOSTNAME_DVWA.rstrip('.')}\r\nUser-Agent: {HTTP_USER_AGENT} (Kali Attacker Exploit Tool)\r\nConnection: keep-alive\r\nAccept: text/html,application/xhtml+xml;q=0.9\r\n"
        if method == "POST":
            http_request_line_and_headers += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload_body_str.encode('utf-8'))}\r\n"

        full_http_request_payload = (http_request_line_and_headers + "\r\n" + payload_body_str).encode('utf-8')

        request_pkt = create_base_packet(clock, self.ip_address, client_http_port, target_server_host.ip_address,
                                         HTTP_SERVER_PORT, flags="PA", payload=full_http_request_payload,
                                         seq=session['client_seq'], ack=session['server_ack'],
                                         eth_src=self.hostname, # Placeholder MAC
                                         eth_dst=router_gateway_host.mac_address_external_placeholder)

        packet_timestamp = current_time.timestamp()
        request_pkt.time = packet_timestamp
        self.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        router_gateway_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp) # Target sees the request

        self.add_host_event(current_time, session['process_pid'], 1, 0, "exploit.py",
                            "network_data", "send", self.ip_address, target_server_host.ip_address,
                            client_http_port, HTTP_SERVER_PORT, f"Exploit HTTP {method}: {exploit_details['description']}")

        session['client_seq'] += len(full_http_request_payload)
        print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} sent exploit payload: {exploit_details['description']}")

        event_time = current_time + datetime.timedelta(seconds=0.05) # RTT + server processing
        # Server uses its generic handle_http_request
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_request,
                                  f"DVWA handles Attacker Exploit Req ({exploit_details['description'][:20]})",
                                  args=(clock, scheduler, self, faucet_controller_host, request_pkt)))


    def handle_http_response_for_exploit(self, clock, scheduler, target_server_host: WebServerDVWA,
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

        # Attacker logs the received server response
        self.add_packet_to_pcap(server_response_packet, timestamp=current_time.timestamp())

        # Send ACK for the received data
        payload_len = 0
        if Raw in server_response_packet:
            payload_len = len(server_response_packet[Raw].load)

        session['server_ack'] = server_response_packet[TCP].seq + payload_len

        ack_for_response_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                                  flags="A", seq=session['client_seq'], ack=session['server_ack'],
                                                  eth_src=self.hostname, # Placeholder MAC
                                                  eth_dst=router_gateway_host.mac_address_external_placeholder)

        packet_timestamp = current_time.timestamp()
        ack_for_response_pkt.time = packet_timestamp
        self.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        router_gateway_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp) # Server sees ACK

        # Optional: Log received payload summary
        # if Raw in server_response_packet:
        #     resp_payload_summary = server_response_packet[Raw].load.decode('utf-8', errors='ignore')[:70]
        #     self.add_host_event(current_time, session['process_pid'], 1, 0, "exploit.py", "network_data", "recv",
        #                        self.ip_address, server_ip, client_http_port, HTTP_SERVER_PORT,
        #                        f"Received HTTP response for exploit. Body: {resp_payload_summary}...")

        # Check if there are more exploit actions in the queue for this session
        if session['actions']:
            delay_seconds = random.uniform(0.2, 1.0) # Short delay before next exploit action
            event_time = current_time + datetime.timedelta(seconds=delay_seconds)
            scheduler.add_event(Event(event_time, 2, self.send_next_exploit_request,
                                      "Attacker sends next exploit request",
                                      args=(clock, scheduler, target_server_host, router_gateway_host, faucet_controller_host, session_key)))
        else:
            print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} finished all DVWA exploit actions for session {session_key}.")
            # TODO: Implement TCP FIN sequence to close connection gracefully
            # del self.http_sessions[session_key] # Clean up session

    def start_nmap_scan(self, scheduler, clock, target_ips: list, ports_to_scan: list,
                        router_gateway_host: Host, faucet_controller_host: Host,
                        all_hosts_map: dict, scan_start_dt: datetime.datetime):

        self.add_host_event(scan_start_dt, ATTACKER_PID_NMAP, 1, 0, "nmap",
                            "process_exec", "", self.ip_address, "", "", "",
                            f"Nmap -sS scan initiated against {', '.join(target_ips)} for {len(ports_to_scan)} ports each.")

        current_delay_offset = 0.0
        current_sport = ATTACKER_NMAP_INIT_SPORT

        for target_ip_str in target_ips:
            target_host_obj = all_hosts_map.get(target_ip_str)
            if not target_host_obj:
                print(f"Warning: Target host {target_ip_str} not found in all_hosts_map. Skipping Nmap for this target.")
                continue

            for port in ports_to_scan:
                event_time = scan_start_dt + datetime.timedelta(seconds=current_delay_offset)
                # Ensure all necessary arguments are passed correctly.
                # target_host_obj is the actual Host object for the target IP.
                action_args = (clock, scheduler, target_host_obj, port, current_sport,
                               router_gateway_host, faucet_controller_host)

                scheduler.add_event(Event(event_time, 3, self.send_nmap_syn_packet,
                                          f"Attacker Nmap SYN to {target_ip_str}:{port}",
                                          args=action_args))
                current_delay_offset += NMAP_SCAN_DELAY_PER_PACKET
                current_sport += 1
                if current_sport > 65530: # Wrap around source port if needed
                    current_sport = ATTACKER_NMAP_INIT_SPORT

        print(f"{clock.get_timestamp_str(scan_start_dt)}: Attacker {self.ip_address} (PID {ATTACKER_PID_NMAP}) scheduled {len(target_ips) * len(ports_to_scan)} Nmap -sS scan packets.")

    def send_nmap_syn_packet(self, clock, scheduler, target_host: Host, target_port: int,
                             src_port: int, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        target_ip = target_host.ip_address
        current_time = clock.get_time()
        # Nmap typically uses random sequence numbers for SYN packets
        client_initial_seq = random.randint(0, 2**32 - 1)

        # MAC addresses: Attacker -> Router's External MAC. Router then handles internal MACs.
        syn_pkt = create_base_packet(clock, self.ip_address, src_port, target_ip, target_port,
                                     flags="S", seq=client_initial_seq,
                                     eth_src=self.hostname, # Using hostname as placeholder for MAC
                                     eth_dst=router_gateway_host.mac_address_external_placeholder)

        packet_timestamp = current_time.timestamp()
        syn_pkt.time = packet_timestamp # Ensure packet time is set from clock

        # Attacker's view
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        # Router's view (transiting packet) - assuming router's pcap logs this
        router_gateway_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp) # direction="external_to_internal" could be added if method supports
        # Faucet's view
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        # Target's view (target receives this packet)
        # target_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp) # Target will log its response, not necessarily the incoming SYN from its own pcap writer in this model

        self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                            "network_packet", "sendto", self.ip_address, target_ip,
                            src_port, target_port, f"Nmap SYN to {target_ip}:{target_port}")

        # Schedule target host to handle this Nmap SYN packet
        event_time = current_time + datetime.timedelta(seconds=0.005) # Simulate RTT to target
        scheduler.add_event(Event(event_time, 1, target_host.handle_nmap_syn,
                                  f"Target {target_ip} handles Nmap SYN from {self.ip_address}:{src_port}",
                                  args=(clock, scheduler, syn_pkt, self, router_gateway_host, faucet_controller_host)))

    def handle_nmap_target_response(self, clock, scheduler, response_pkt: IP,
                                    router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        current_time = clock.get_time()
        # This is where attacker receives SYN-ACK (port open) or RST (port closed) from target
        # For -sS scan, if SYN-ACK is received, attacker sends RST.

        # Log received packet by attacker
        self.add_packet_to_pcap(response_pkt, timestamp=current_time.timestamp())
        # Faucet and router also see this response packet on its way back
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=current_time.timestamp())
        router_gateway_host.add_packet_to_pcap(response_pkt, timestamp=current_time.timestamp()) # direction="internal_to_external"

        if TCP in response_pkt and response_pkt[TCP].flags.SA: # SYN-ACK flags are SA (0x12)
            target_ip = response_pkt[IP].src
            target_port = response_pkt[TCP].sport # Target's source port (the scanned port)
            attacker_orig_sport = response_pkt[TCP].dport # Attacker's original source port for this scan

            # Attacker sends RST to complete the half-open scan for an open port
            # SEQ for RST should be the ACK number from the SYN-ACK from server
            rst_seq = response_pkt[TCP].ack
            rst_pkt = create_base_packet(clock, self.ip_address, attacker_orig_sport, target_ip, target_port,
                                         flags="R", seq=rst_seq,
                                         eth_src=self.hostname, # Placeholder MAC
                                         eth_dst=router_gateway_host.mac_address_external_placeholder)

            rst_pkt_timestamp = current_time.timestamp() # Can be same time or slightly after
            rst_pkt.time = rst_pkt_timestamp

            self.add_packet_to_pcap(rst_pkt, timestamp=rst_pkt_timestamp)
            router_gateway_host.add_packet_to_pcap(rst_pkt, timestamp=rst_pkt_timestamp)
            if faucet_controller_host:
                faucet_controller_host.add_packet_to_pcap(rst_pkt, timestamp=rst_pkt_timestamp)
            # Target might see this RST, add to its pcap if desired (target_host.add_packet_to_pcap(rst_pkt))

            self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                                "network_response", "recvfrom/sendto", self.ip_address, target_ip,
                                attacker_orig_sport, target_port,
                                f"Nmap: Received SYN-ACK from {target_ip}:{target_port} (OPEN). Sent RST.")
            # print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} received SYN-ACK from {target_ip}:{target_port} (OPEN). Sent RST.")

        elif TCP in response_pkt and response_pkt[TCP].flags.RA: # RST-ACK flags are RA (0x14) or just R (0x04)
            target_ip = response_pkt[IP].src
            target_port = response_pkt[TCP].sport # Target's source port (the scanned port)
            attacker_orig_sport = response_pkt[TCP].dport

            self.add_host_event(current_time, ATTACKER_PID_NMAP, 1, 0, "nmap",
                                "network_response", "recvfrom", self.ip_address, target_ip,
                                attacker_orig_sport, target_port,  # src_port/dst_port for the connection attempt
                                f"Nmap: Received RST/RST-ACK from {target_ip}:{target_port} (CLOSED).")
            # print(f"{clock.get_timestamp_str(current_time)}: Attacker {self.ip_address} received RST from {target_ip}:{target_port} (CLOSED).")

        # No further action needed from attacker for this specific port scan after RST or receiving RST.


class WebServerDVWA(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.active_streams = {}
        self.http_sessions = {}

    def handle_nmap_syn(self, clock, scheduler, nmap_syn_packet: IP,
                        attacker_host: Attacker, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        src_ip = nmap_syn_packet[IP].src    # Attacker's IP
        src_port = nmap_syn_packet[TCP].sport # Attacker's ephemeral source port
        dst_port = nmap_syn_packet[TCP].dport # Port being scanned on this host (self)
        current_time = clock.get_time()

        # Target logs the received SYN packet
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
                                              eth_src=router_gateway_host.mac_address_internal_placeholder, # From internal router MAC via target
                                              eth_dst=nmap_syn_packet[Ether].src) # To original querying MAC (attacker via router)
            log_message = f"Nmap SYN on OPEN port {dst_port} from {src_ip}:{src_port}. Sent SYN-ACK."
            event_desc = f"Target {self.ip_address} SYN-ACK for Nmap (port {dst_port} open)"
            # Host event for responding to scan on open port (optional, could be an IDS alert)
            # self.add_host_event(current_time, 0,0,0, "kernel", "network_response", "sendto", ...) # Example for IDS log
        else:
            # For a closed port, seq is often 0 and ack is the incoming SYN's seq + 1
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="RA", seq=0, ack=nmap_syn_packet[TCP].seq + 1, # RA for Reset-Ack
                                              eth_src=router_gateway_host.mac_address_internal_placeholder,
                                              eth_dst=nmap_syn_packet[Ether].src) # MAC of the packet that came in (Attacker via Router)
            log_message = f"Nmap SYN on CLOSED port {dst_port} from {src_ip}:{src_port}. Sent RST-ACK."
            event_desc = f"Target {self.ip_address} RST-ACK for Nmap (port {dst_port} closed)"

        response_pkt.time = current_time.timestamp() # Ensure time is set

        # Target sends response packet
        self.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        # Faucet sees response
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        # Router sees response (transiting internal to external)
        router_gateway_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        # Attacker will receive this (handled by attacker_host.handle_nmap_target_response)
        # attacker_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time) # Attacker logs it when it handles it

        # print(f"{clock.get_timestamp_str(current_time)}: Target {self.ip_address}: {log_message}") # Can be verbose

        # Schedule attacker to handle this response
        event_time = current_time + datetime.timedelta(seconds=0.005) # Simulate RTT for response to reach attacker
        scheduler.add_event(Event(event_time, 1, attacker_host.handle_nmap_target_response,
                                  event_desc,
                                  args=(clock, scheduler, response_pkt, router_gateway_host, faucet_controller_host)))

    def handle_http_syn(self, clock, scheduler, client_host, faucet_controller_host, client_syn_packet,
                        client_syn_ack_handler_method, # New parameter: method on client/attacker to call
                        next_client_action_details):
        client_ip = client_syn_packet[IP].src
        client_port = client_syn_packet[TCP].sport
        server_initial_seq = random.randint(0, 2**32 - 1)

        session_key = (client_ip, client_port)
        self.http_sessions[session_key] = {
            'server_seq': server_initial_seq + 1, # SYN consumes 1 seq number
            'client_ack': client_syn_packet[TCP].seq + 1,
            'logged_in': False,
            'server_tcp_stream_id': random.randint(1000,2000) # For log correlation if needed
        }

        syn_ack_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                         flags="SA", seq=server_initial_seq, ack=client_syn_packet[TCP].seq + 1)

        packet_time = clock.get_time()
        self.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        client_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())

        self.add_host_event(packet_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                            "network_connect", "accept", self.ip_address, client_ip,
                            HTTP_SERVER_PORT, client_port, f"HTTP SYN-ACK to {client_ip}:{client_port}")

        event_time = packet_time + datetime.timedelta(seconds=0.01) # RTT for SYN-ACK to reach client
        # Call the specific handler provided by the client/attacker
        scheduler.add_event(Event(event_time, 1, client_syn_ack_handler_method,
                                  f"Client/Attacker {client_ip} handles HTTP SYN-ACK from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_ack_pkt, next_client_action_details)))
        # print(f"{clock.get_timestamp_str(packet_time)}: DVWA ({self.ip_address}) sent HTTP SYN-ACK to {client_ip}:{client_port}. Callback: {client_syn_ack_handler_method.__name__}")


    def handle_http_request(self, clock, scheduler, client_host, faucet_controller_host, http_request_packet):
        client_ip = http_request_packet[IP].src
        client_port = http_request_packet[TCP].sport
        session_key = (client_ip, client_port)
        session = self.http_sessions.get(session_key)

        if not session:
            print(f"Error: No HTTP session found for {client_ip}:{client_port} at DVWA.")
            return

        # Assume http_request_packet[Raw].load contains the full HTTP request string
        raw_payload_bytes = http_request_packet[Raw].load if Raw in http_request_packet else b""
        try:
            http_payload_str = raw_payload_bytes.decode('utf-8', errors='ignore')
        except AttributeError:
             http_payload_str = ""

        # Default response
        response_body = "<html><head><title>Simulated DVWA</title></head><body><h1>Response</h1><p>Request processed.</p></body></html>"
        http_status = "200 OK"
        additional_headers = ""

        # Check for Command Injection attempt
        is_command_injection = False
        injected_command = None
        # Basic check for POST to the exec page and presence of shell characters / common commands
        if CMD_INJ_TARGET_PATH in http_payload_str and "POST" in http_payload_str:
            post_params = {}
            if "\r\n\r\n" in http_payload_str: # Ensure there's a body
                body = http_payload_str.split("\r\n\r\n", 1)[1]
                params = body.split('&')
                for param_pair in params:
                    if '=' in param_pair:
                        key, value = param_pair.split('=', 1)
                        # Simple decoding for spaces, more robust URL decoding might be needed for complex inputs
                        post_params[key.strip()] = value.replace('+', ' ').replace('%20', ' ').replace('%3B', ';').replace('%26', '&')

            if CMD_INJ_FIELD_NAME in post_params:
                field_value = post_params[CMD_INJ_FIELD_NAME]
                for test_cmd_base in CMD_INJ_PAYLOADS: # "127.0.0.1; ls -la /tmp"
                    # Check for the command part after ; or &&
                    if "; " in test_cmd_base:
                        cmd_part = test_cmd_base.split("; ", 1)[1]
                        if cmd_part in field_value and field_value.startswith(test_cmd_base.split("; ",1)[0]): # Ensure it starts with the benign part too
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
            current_time = clock.get_time() # Get current time for the host event
            self.add_host_event(current_time, DVWA_SHELL_PID, DVWA_APACHE_PID, DEFAULT_SERVER_UID,
                                "/bin/sh", "process_exec", "execve",
                                self.ip_address, client_ip, # SrcIP on server is self, DstIP is client for the event context
                                0, 0, # Ports not directly relevant for process exec log line
                                f"Command injection executed: /bin/sh -c '{injected_command}' by Apache UID {DEFAULT_SERVER_UID}")
            response_body = f"<html><body><pre>PING {post_params.get(CMD_INJ_FIELD_NAME,'').split(';')[0].split('&&')[0].strip()}\n...simulated output for injected command '{injected_command}'...</pre></body></html>"
            http_status = "200 OK" # Command execution might still return 200 OK with output
            print(f"{clock.get_timestamp_str(current_time)}: DVWA server ({self.ip_address}) detected and logged command injection: {injected_command}")

        # Login and other page logic (simplified, as command injection is the focus here)
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
        elif SQLI_TARGET_PATH.split("?")[0] in http_payload_str and "GET" in http_payload_str: # SQLi page
            # Simplified: just acknowledge the page, actual SQLi effect not simulated in DB
            response_body = "<html><body>SQL Injection Test Page. Your input was processed.</body></html>"


        content_length = len(response_body.encode('utf-8'))
        http_response_headers = f"HTTP/1.1 {http_status}\r\nServer: Apache/2.4.x (Simulated)\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Length: {content_length}\r\nConnection: keep-alive\r\n{additional_headers}\r\n"
        full_response = (http_response_headers + response_body).encode('utf-8')

        # Server sends ACK for received client data first
        client_data_len = len(raw_payload_bytes)
        server_ack_for_client_data = http_request_packet[TCP].seq + client_data_len

        ack_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                     flags="A", seq=session['server_seq'], ack=server_ack_for_client_data)

        current_time = clock.get_time()
        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        client_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)

        session['client_ack'] = server_ack_for_client_data # Update server's record of client's next expected ACK

        # Send HTTP Response data packet (scheduled slightly after ACK)
        response_event_time = current_time + datetime.timedelta(seconds=0.001) # Minimal delay

        # Storing packet to pass, as it's needed by client to determine next ACK value
        # This response_data_pkt is what client will ACK.
        response_data_pkt = create_base_packet(clock, self.ip_address, HTTP_SERVER_PORT, client_ip, client_port,
                                         flags="PA", payload=full_response,
                                         seq=session['server_seq'], ack=session['client_ack'])
        response_data_pkt.time = response_event_time.timestamp() # ensure correct time for this packet

        # Add to PCAPs (server, client, faucet)
        self.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)
        client_host.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_data_pkt, timestamp=response_data_pkt.time)

        self.add_host_event(response_event_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2",
                            "network_data", "send", self.ip_address, client_ip, HTTP_SERVER_PORT, client_port,
                            f"HTTP Response {http_status} for {http_payload_str[:50]}...")

        session['server_seq'] += len(full_response) # Update server's next SEQ

        # Client needs to ACK this response. Schedule client's processing of this response.
        # Determine which client handler to call based on client_host type
        response_ack_handler = None
        if isinstance(client_host, ClientNormal1):
            response_ack_handler = client_host.handle_http_response_ack
        elif isinstance(client_host, Attacker): # Attacker also needs to handle responses
            response_ack_handler = client_host.handle_http_response_for_exploit

        if response_ack_handler:
            client_ack_event_time = response_event_time + datetime.timedelta(seconds=0.01)
            scheduler.add_event(Event(client_ack_event_time, 2, response_ack_handler,
                                      f"Client/Attacker {client_ip} ACKs HTTP Resp from DVWA",
                                      args=(clock, scheduler, self, faucet_controller_host, response_data_pkt)))
        else:
            print(f"Warning: Could not determine HTTP response ACK handler for client type {type(client_host)}")
        # print(f"{clock.get_timestamp_str(response_event_time)}: DVWA ({self.ip_address}) sent HTTP response to {client_ip}:{client_port}.")


    def handle_streaming_syn(self, clock, scheduler, client_host, faucet_controller_host, client_syn_packet,
                             client_syn_ack_handler_method, # Added for streaming, might need unification
                             stream_duration_seconds): # stream_duration_seconds is specific to streaming
        client_ip = client_syn_packet[IP].src
        client_port = client_syn_packet[TCP].sport
        server_initial_seq = random.randint(0, 2**32 - 1)

        # Store session info
        self.active_streams[(client_ip, client_port)] = {
            'server_seq': server_initial_seq,
            'client_ack_of_server_seq': client_syn_packet[TCP].seq + 1
        }

        syn_ack_pkt = create_base_packet(clock, self.ip_address, STREAMING_SERVER_PORT, client_ip, client_port,
                                         flags="SA", seq=server_initial_seq, ack=client_syn_packet[TCP].seq + 1)

        # Add to relevant PCAPs
        packet_time = clock.get_time()
        self.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        client_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())
        if faucet_controller_host: # faucet_controller_host might be None in some test scenarios
            faucet_controller_host.add_packet_to_pcap(syn_ack_pkt, timestamp=packet_time.timestamp())

        self.add_host_event(packet_time, SIMULATED_WEBSERVER_PID, 1, DEFAULT_SERVER_UID, "apache2", # Example process
                            "network_connect", "accept", self.ip_address, client_ip,
                            STREAMING_SERVER_PORT, client_port,
                            f"TCP SYN-ACK to {client_ip}:{client_port} for stream")

        # Schedule client's ACK
        event_time = packet_time + datetime.timedelta(seconds=0.01) # Small delay for RTT
        # This callback is for streaming, ensure it's distinct from HTTP exploit/client handlers if they differ
        # For now, assuming client_syn_ack_handler_method is correctly passed for streaming client
        scheduler.add_event(Event(event_time, 1, client_syn_ack_handler_method, # client_host.handle_streaming_syn_ack,
                                  f"Client {client_ip} ACK stream SYN-ACK from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_ack_pkt, stream_duration_seconds)))
        # print(f"{clock.get_timestamp_str(packet_time)}: DVWA ({self.ip_address}) sent Streaming SYN-ACK to {client_ip}:{client_port}, scheduled client ACK.")


    def send_streaming_data_packet(self, clock, scheduler, client_host, faucet_controller_host, client_ip_port_tuple, stream_end_time):
        client_ip, client_port = client_ip_port_tuple
        current_time = clock.get_time()

        if current_time >= stream_end_time:
            # TODO: Implement TCP FIN sequence from server
            print(f"{clock.get_timestamp_str(current_time)}: Video stream data finished for {client_ip}:{client_port}. Initiating FIN (TODO).")
            if client_ip_port_tuple in self.active_streams:
                del self.active_streams[client_ip_port_tuple]
            return

        session = self.active_streams.get(client_ip_port_tuple)
        if not session:
            print(f"{clock.get_timestamp_str(current_time)}: Session for {client_ip}:{client_port} not found. Stopping stream.")
            return

        payload_size = random.randint(VIDEO_PACKET_SIZE_MIN, VIDEO_PACKET_SIZE_MAX)
        payload = os.urandom(payload_size)

        data_pkt = create_base_packet(clock, self.ip_address, STREAMING_SERVER_PORT, client_ip, client_port,
                                      flags="PA", payload=payload, seq=session['server_seq'], ack=session['client_ack_of_server_seq'])

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)
        client_host.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
             faucet_controller_host.add_packet_to_pcap(data_pkt, timestamp=packet_timestamp)

        # self.add_host_event(...) # Optional: log data packet send event on server

        session['server_seq'] += payload_size # Update server sequence number

        # Schedule next data packet
        next_event_time = current_time + datetime.timedelta(seconds=INTER_PACKET_DELAY_SECONDS)
        scheduler.add_event(Event(next_event_time, 2, self.send_streaming_data_packet,
                                  f"Server {self.ip_address} sends stream data to {client_ip}:{client_port}",
                                  args=(clock, scheduler, client_host, faucet_controller_host, client_ip_port_tuple, stream_end_time)))
        # print(f"{clock.get_timestamp_str(current_time)}: DVWA sent data packet to {client_ip}:{client_port}. Next scheduled.")


class VulnServerMetasploitable(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        # Potentially add other service-specific session tracking if needed, e.g. FTP, SSH sessions

    def handle_nmap_syn(self, clock, scheduler, nmap_syn_packet: IP,
                        attacker_host: Attacker, router_gateway_host: 'RouterGateway', faucet_controller_host: Host):
        # This method can be identical to WebServerDVWA.handle_nmap_syn if behavior is the same.
        # Or customized if Metasploitable responds differently (e.g. different OS fingerprint).
        # For now, using a shared logic by calling a generic handler or duplicating:
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
                                              eth_src=router_gateway_host.mac_address_internal_placeholder,
                                              eth_dst=nmap_syn_packet[Ether].src)
            log_message = f"Nmap SYN on OPEN port {dst_port} from {src_ip}:{src_port}. Sent SYN-ACK."
            event_desc = f"Target {self.ip_address} SYN-ACK for Nmap (port {dst_port} open)"
        else:
            response_pkt = create_base_packet(clock, self.ip_address, dst_port, src_ip, src_port,
                                              flags="RA", seq=0, ack=nmap_syn_packet[TCP].seq + 1,
                                              eth_src=router_gateway_host.mac_address_internal_placeholder,
                                              eth_dst=nmap_syn_packet[Ether].src)
            log_message = f"Nmap SYN on CLOSED port {dst_port} from {src_ip}:{src_port}. Sent RST-ACK."
            event_desc = f"Target {self.ip_address} RST-ACK for Nmap (port {dst_port} closed)"

        response_pkt.time = current_time.timestamp()
        self.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)
        router_gateway_host.add_packet_to_pcap(response_pkt, timestamp=response_pkt.time)

        # print(f"{clock.get_timestamp_str(current_time)}: Target {self.ip_address}: {log_message}")
        event_time = current_time + datetime.timedelta(seconds=0.005)
        scheduler.add_event(Event(event_time, 1, attacker_host.handle_nmap_target_response,
                                  event_desc,
                                  args=(clock, scheduler, response_pkt, router_gateway_host, faucet_controller_host)))


class ClientNormal1(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.http_client_port_counter = CLIENT1_HTTP_INIT_PORT
        self.http_pid_counter = SIMULATED_CLIENT_PID_START + 100 # Offset from streaming PID counter
        # Key for http_sessions: (target_hostname_queried, server_port_for_target)
        self.http_sessions = {}

    def start_web_browsing(self, scheduler, clock, target_server_hostname: str,
                           target_http_server_obj: WebServerDVWA, # Actual WebServerDVWA object
                           dns_server_host: Host, faucet_controller_host: Host,
                           browse_start_dt: datetime.datetime):

        self.http_pid_counter += 1
        process_pid = self.http_pid_counter

        self.add_host_event(browse_start_dt, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "process_exec", "", self.ip_address, "", "", "",
                            f"Start web browsing {target_server_hostname}")

        session_key = (target_server_hostname, HTTP_SERVER_PORT)
        self.http_sessions[session_key] = {
            'client_seq': 0, # Will be set before first SYN
            'server_ack': 0, # Will be set upon receiving SYN-ACK
            'dns_resolved_ip': None,
            'current_page_index': 0,
            'logged_in': False, # Specific to DVWA login state
            'process_pid': process_pid,
            'client_http_port': 0, # Will be set before first SYN
            'target_server_obj': target_http_server_obj # Store the target server object
        }

        # Initiate DNS lookup
        event = Event(browse_start_dt, 0, self.send_dns_query,
                      f"Client {self.ip_address} DNS Query for {target_server_hostname}",
                      args=(clock, scheduler, target_server_hostname, dns_server_host, faucet_controller_host, process_pid, target_http_server_obj))
        scheduler.add_event(event)
        print(f"{clock.get_timestamp_str(browse_start_dt)}: Client {self.ip_address} (PID {process_pid}) starting web browsing. First event: DNS query for {target_server_hostname}")

    def send_dns_query(self, clock, scheduler, target_hostname: str, dns_server_host: Host,
                       faucet_controller_host: Host, process_pid: int, target_http_server_obj: WebServerDVWA):
        dns_query_id = random.randint(1, 65535)
        # Use a unique client port for this DNS query
        client_dns_port = random.randint(40000, 49000) # Ephemeral port range for DNS by client

        # Ensure target_hostname ends with a dot for absolute query if not already
        fqdn_target_hostname = target_hostname if target_hostname.endswith('.') else target_hostname + '.'

        dns_req_pkt = Ether()/IP(dst=dns_server_host.ip_address, src=self.ip_address)/ \
                      UDP(sport=client_dns_port, dport=53)/ \
                      DNS(id=dns_query_id, rd=1, qd=DNSQR(qname=fqdn_target_hostname))

        current_time = clock.get_time()
        dns_req_pkt.time = current_time.timestamp()

        self.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time)
        dns_server_host.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time) # Router (DNS server) sees this
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(dns_req_pkt, timestamp=dns_req_pkt.time)

        self.add_host_event(current_time, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "sendto", self.ip_address, dns_server_host.ip_address,
                            client_dns_port, 53, f"DNS query for {fqdn_target_hostname}")

        # Schedule router (dns_server_host) to handle this query
        # Pass client instance (self) and the ultimate target server object for later use
        event_time = current_time + datetime.timedelta(seconds=0.005) # Simulate RTT to DNS server
        scheduler.add_event(Event(event_time, 1, dns_server_host.handle_dns_query,
                                  f"Router handles DNS Query from {self.ip_address} for {fqdn_target_hostname}",
                                  args=(clock, scheduler, dns_req_pkt, faucet_controller_host, self, target_http_server_obj)))
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} sent DNS query for {fqdn_target_hostname}. Scheduled router to handle.")

    def handle_dns_response(self, clock, scheduler, dns_response_packet: IP,
                            target_server_obj_after_dns: WebServerDVWA, # This is the DVWA server instance
                            faucet_controller_host: Host):
        current_time = clock.get_time()
        dns_payload = dns_response_packet.getlayer(DNS) # Use getlayer for safety
        resolved_ip = None

        if dns_payload and dns_payload.an and isinstance(dns_payload.an, DNSRR) and dns_payload.an.type == 1: # Type A
            resolved_ip = dns_payload.an.rdata
            # Scapy might decode rdata to string, ensure it is if needed, or keep as bytes if your setup expects that.
            if isinstance(resolved_ip, bytes):
                resolved_ip = resolved_ip.decode('utf-8')

        # Original hostname used for query is dns_payload.qd.qname
        original_hostname_bytes = dns_payload.qd.qname
        original_hostname = original_hostname_bytes.decode('utf-8') # Should be like "dvwa.internal.local."

        session_key = (original_hostname, HTTP_SERVER_PORT)
        session = self.http_sessions.get(session_key)

        if session and resolved_ip:
            session['dns_resolved_ip'] = resolved_ip
            self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                                "network_data", "recvfrom", self.ip_address, dns_response_packet[IP].src,
                                dns_response_packet[UDP].dport, dns_response_packet[UDP].sport, # src_port of resp is 53, dport is client's ephemeral
                                f"DNS response: {original_hostname} -> {resolved_ip}")
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address} got DNS response: {original_hostname} -> {resolved_ip}")

            # Now initiate HTTP connection to the resolved IP using target_server_obj_after_dns
            self.http_client_port_counter += random.randint(1, 5)
            client_http_port = self.http_client_port_counter
            session['client_http_port'] = client_http_port

            client_initial_seq = random.randint(0, 2**32 - 1)
            session['client_seq'] = client_initial_seq

            # First action after SYN/ACK will be GET for the first page in DVWA_PAGES (login page)
            next_action_details = {'type': 'GET', 'path': DVWA_PAGES[0]}

            event_time = current_time + datetime.timedelta(seconds=0.01) # Tiny delay before sending SYN
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
                                     flags="S", seq=client_seq)

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)

        self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "connect", self.ip_address, resolved_ip,
                            client_http_port, HTTP_SERVER_PORT, f"HTTP SYN to {resolved_ip} for {session_key[0]}")

        session['client_seq'] = client_seq + 1 # SYN consumes 1 seq number

        event_time = current_time + datetime.timedelta(seconds=0.02) # Simulate RTT for SYN to reach server
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_syn,
                                  f"Server {target_server_host.ip_address} handles HTTP SYN from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt, self.handle_http_syn_ack, next_action_details))) # Pass its own SYN-ACK handler
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_http_port} sent HTTP SYN to {resolved_ip}. Scheduled server handle_http_syn.")

    def handle_http_syn_ack(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host,
                            server_syn_ack_pkt: IP, next_action_details: dict):
        current_time = clock.get_time()
        client_http_port = server_syn_ack_pkt[TCP].dport # This client's ephemeral port for HTTP
        server_ip = server_syn_ack_pkt[IP].src # Should match target_server_host.ip_address

        # Find session based on target server hostname (which was the original query)
        # This assumes only one browsing session to a particular hostname at a time by this client
        session_key = (DNS_QUERY_NAME, HTTP_SERVER_PORT) # Assuming DNS_QUERY_NAME is the key
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: Client {self.ip_address} could not find HTTP session for {DNS_QUERY_NAME} on SYN-ACK receipt.")
            return
        if session['client_http_port'] != client_http_port: # Check if port matches the active session
            print(f"Error: Client {self.ip_address} received SYN-ACK on unexpected port {client_http_port}. Expected {session['client_http_port']}.")
            return

        # Client's next sequence number is the server's ACK. Server's ACK for client's SYN.
        session['server_ack'] = server_syn_ack_pkt[TCP].seq + 1 # Server's SYN-ACK also consumes 1 seq number

        ack_pkt = create_base_packet(clock, self.ip_address, client_http_port, server_ip, HTTP_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack'])

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)

        # Connection established. Proceed with the planned HTTP action (e.g., GET login page)
        event_time = current_time + datetime.timedelta(seconds=0.01) # Small delay before sending HTTP request
        scheduler.add_event(Event(event_time, 2, self.send_http_request,
                                  f"Client {self.ip_address} sends HTTP request for {next_action_details['path']}",
                                  args=(clock, scheduler, target_server_host, faucet_controller_host, next_action_details, session_key)))
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_http_port} ACKed HTTP SYN-ACK from {server_ip}. Scheduled send_http_request for {next_action_details['path']}.")

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
        method = action_details['type'] # "GET" or "POST"
        payload_body_str = ""
        if method == "POST":
            payload_body_str = action_details.get('payload', "")

        # Construct HTTP Request
        # Use DNS_QUERY_NAME (hostname) for Host header, not the resolved_ip
        http_request_headers = f"{method} {path} HTTP/1.1\r\nHost: {DNS_QUERY_NAME.rstrip('.')}\r\nUser-Agent: {HTTP_USER_AGENT}\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n"
        if session['logged_in'] and "PHPSESSID" not in http_request_headers: # Add cookie if logged in (simplified)
             http_request_headers += f"Cookie: PHPSESSID=simulatedsessionid_{random.randint(10000,99999)}; security=low\r\n" # Example cookie

        if method == "POST":
            http_request_headers += f"Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload_body_str.encode('utf-8'))}\r\n"

        full_http_request_str = http_request_headers + "\r\n" + payload_body_str

        request_pkt = create_base_packet(clock, self.ip_address, client_http_port, resolved_ip, HTTP_SERVER_PORT,
                                         flags="PA", payload=full_http_request_str.encode('utf-8'), # Payload must be bytes
                                         seq=session['client_seq'], ack=session['server_ack'])

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(request_pkt, timestamp=packet_timestamp)

        self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_data", "send", self.ip_address, resolved_ip,
                            client_http_port, HTTP_SERVER_PORT, f"HTTP {method} {path}")

        session['client_seq'] += len(full_http_request_str.encode('utf-8')) # Update client SEQ

        # Server will handle this request and send response
        event_time = current_time + datetime.timedelta(seconds=0.05) # Simulate RTT + server processing
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_http_request,
                                  f"Server {target_server_host.ip_address} handles HTTP request from {self.ip_address}",
                                  args=(clock, scheduler, self, faucet_controller_host, request_pkt)))
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_http_port} sent HTTP {method} {path}. Scheduled server handle_http_request.")

    def handle_http_response_ack(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, server_response_packet: IP):
        # This method is called when the client needs to ACK data received from the server (the HTTP response body)
        current_time = clock.get_time()
        session_key = (DNS_QUERY_NAME, HTTP_SERVER_PORT) # Assuming this is the active session key
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: Client {self.ip_address} could not find session for {DNS_QUERY_NAME} on HTTP response ACK.")
            return

        resolved_ip = session['dns_resolved_ip']
        client_http_port = session['client_http_port']

        # Client sends ACK for the data received from server
        # The server_response_packet is the packet carrying the HTTP data (e.g. HTML page)
        payload_len = 0
        if Raw in server_response_packet:
            payload_len = len(server_response_packet[Raw].load)

        # Client's ACK number should be server's SEQ number from data packet + length of data received
        session['server_ack'] = server_response_packet[TCP].seq + payload_len

        ack_for_response_pkt = create_base_packet(clock, self.ip_address, client_http_port, resolved_ip, HTTP_SERVER_PORT,
                                                  flags="A", seq=session['client_seq'], ack=session['server_ack'])

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_for_response_pkt, timestamp=packet_timestamp)

        # Update server's http_session's client_ack to this value if server needs to check it (not strictly needed for one-way data)
        # server_session_on_dvwa = target_server_host.http_sessions.get((self.ip_address, client_http_port))
        # if server_session_on_dvwa:
        #     server_session_on_dvwa['client_ack'] = session['server_ack']

        # Log that client received data (optional, can be verbose)
        # http_response_payload = server_response_packet[Raw].load.decode('utf-8', errors='ignore')[:100]
        # self.add_host_event(current_time, session['process_pid'], 1, DEFAULT_CLIENT_UID, "chrome.exe",
        #                     "network_data", "recv", self.ip_address, resolved_ip,
        #                     client_http_port, HTTP_SERVER_PORT, f"Received HTTP response data, now ACKing. Payload head: {http_response_payload}")
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_http_port} ACKed HTTP response data from {resolved_ip}.")

        # Determine next action (login, browse more pages, benign form submission)
        self.schedule_next_http_client_action(clock, scheduler, target_server_host, faucet_controller_host, session_key)


    def schedule_next_http_client_action(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, session_key: tuple):
        session = self.http_sessions.get(session_key)
        if not session:
            print(f"Error: No session for {session_key} to schedule next HTTP action.")
            return

        next_action = None
        # User "thinking time" or page load rendering time before next action
        delay_seconds = random.uniform(0.5, 2.5)

        if not session.get('logged_in_attempted', False): # Check if login was ATTEMPTED
            next_action = {'type': 'POST', 'path': '/dvwa/login.php', 'payload': DVWA_LOGIN_PAYLOAD}
            session['logged_in_attempted'] = True
            # The server's handle_http_request will set session['logged_in'] = True on DVWA if successful
            # Here, client just assumes it will try to login. The server response will confirm.
        elif session.get('logged_in', False) and session['current_page_index'] < len(DVWA_PAGES):
            page_path = DVWA_PAGES[session['current_page_index']]
            # Avoid re-requesting login.php if we are already logged in and it's the first page.
            if page_path == "/dvwa/login.php" and session['current_page_index'] == 0:
                 session['current_page_index'] +=1 # Skip it and try next page
                 if session['current_page_index'] < len(DVWA_PAGES):
                     page_path = DVWA_PAGES[session['current_page_index']]
                 else: # Only login page in list, then do form
                    next_action = {'type': 'POST', 'path': DVWA_BENIGN_FORM_TARGET, 'payload': DVWA_BENIGN_FORM_PAYLOAD}
                    session['current_page_index'] += 1 # Mark as done with pages and form
                    scheduler.add_event(Event(clock.get_time() + datetime.timedelta(seconds=delay_seconds), 2, self.send_http_request,
                                              f"Client {self.ip_address} POST benign form to {target_server_host.hostname}",
                                              args=(clock, scheduler, target_server_host, faucet_controller_host, next_action, session_key)))
                    return

            if session['current_page_index'] < len(DVWA_PAGES): # Re-check if we skipped login
                next_action = {'type': 'GET', 'path': page_path}
                session['current_page_index'] += 1
        elif session.get('logged_in', False) and session['current_page_index'] == len(DVWA_PAGES): # Done with pages, try benign form
            next_action = {'type': 'POST', 'path': DVWA_BENIGN_FORM_TARGET, 'payload': DVWA_BENIGN_FORM_PAYLOAD}
            session['current_page_index'] += 1 # Mark as done with form
        else: # All browsing actions done or failed to log in and no other pages to try
            if not session.get('logged_in', False) and session.get('logged_in_attempted', False):
                print(f"{clock.get_timestamp_str(clock.get_time())}: Client {self.ip_address} failed to log into DVWA or no further actions after login attempt. Ending session.")
            else:
                print(f"{clock.get_timestamp_str(clock.get_time())}: Client {self.ip_address} finished browsing DVWA or no pages left. Ending session.")
            # TODO: Implement TCP FIN sequence from client to close connection
            # del self.http_sessions[session_key] # Clean up session
            return

        if next_action:
            event_time = clock.get_time() + datetime.timedelta(seconds=delay_seconds)
            description = f"Client {self.ip_address} {next_action['type']} {next_action['path']} to {target_server_host.hostname}"
            scheduler.add_event(Event(event_time, 2, self.send_http_request, description,
                                      args=(clock, scheduler, target_server_host, faucet_controller_host, next_action, session_key)))
            # print(f"{clock.get_timestamp_str(clock.get_time())}: Scheduled next HTTP action: {description} at {clock.get_timestamp_str(event_time)}")


class ClientNormal2(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.current_streaming_port = STREAMING_CLIENT_INIT_PORT
        self.client_pid_counter = SIMULATED_CLIENT_PID_START
        self.active_streams = {} # Key: (server_ip, server_port), Value: {client_seq, server_ack_of_client_seq}

    def start_video_stream(self, scheduler, clock, target_server_host: WebServerDVWA, faucet_controller_host: Host, stream_start_dt: datetime.datetime, stream_duration_seconds: int):
        self.current_streaming_port += random.randint(1, 10) # Increment to vary client port
        client_port = self.current_streaming_port
        self.client_pid_counter += 1
        process_pid = self.client_pid_counter

        self.add_host_event(stream_start_dt, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe", # Example process
                            "process_exec", "", self.ip_address, "", "", "",
                            f"Start video stream to {target_server_host.ip_address}:{STREAMING_SERVER_PORT}")

        client_initial_seq = random.randint(0, 2**32 - 1)
        # Store client's perspective of the stream state
        self.active_streams[(target_server_host.ip_address, STREAMING_SERVER_PORT)] = {
            'client_seq': client_initial_seq,
            'server_ack_of_client_seq': 0 # Server's ACK for client's data (not used much in one-way stream)
        }

        event = Event(stream_start_dt, 0, self.send_streaming_syn,
                      f"Client {self.ip_address}:{client_port} SYN for stream to {target_server_host.ip_address}",
                      args=(clock, scheduler, target_server_host, faucet_controller_host, client_port, client_initial_seq, process_pid, stream_duration_seconds))
        scheduler.add_event(event)
        print(f"{clock.get_timestamp_str(stream_start_dt)}: Client {self.ip_address}:{client_port} (PID: {process_pid}) scheduled video stream to {target_server_host.ip_address}. Duration: {stream_duration_seconds}s.")

    def send_streaming_syn(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, client_port: int, client_seq: int, process_pid: int, stream_duration_seconds: int):
        current_time = clock.get_time() # Should be == stream_start_dt from previous event if scheduled correctly
        syn_pkt = create_base_packet(clock, self.ip_address, client_port, target_server_host.ip_address,
                                     STREAMING_SERVER_PORT, flags="S", seq=client_seq)

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(syn_pkt, timestamp=packet_timestamp)

        self.add_host_event(current_time, process_pid, 1, DEFAULT_CLIENT_UID, "chrome.exe",
                            "network_connect", "connect", self.ip_address, target_server_host.ip_address,
                            client_port, STREAMING_SERVER_PORT, "TCP SYN sent for video stream")

        # Schedule server's response (handle_streaming_syn)
        # This simulates the packet traveling and server processing it
        event_time = current_time + datetime.timedelta(seconds=0.02) # Simulate RTT/processing delay
        scheduler.add_event(Event(event_time, 1, target_server_host.handle_streaming_syn, # Server's SYN handler for streaming
                                  f"Server {target_server_host.ip_address} handles stream SYN from {self.ip_address}:{client_port}",
                                  args=(clock, scheduler, self, faucet_controller_host, syn_pkt, self.handle_streaming_syn_ack, stream_duration_seconds))) # Pass its own SYN-ACK handler
        # print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_port} sent streaming SYN to {target_server_host.ip_address}. Scheduled server handle_syn.")

    def handle_streaming_syn_ack(self, clock, scheduler, target_server_host: WebServerDVWA, faucet_controller_host: Host, server_syn_ack_pkt: IP, stream_duration_seconds: int):
        current_time = clock.get_time()
        client_port = server_syn_ack_pkt[TCP].dport # This client's port
        server_ip = server_syn_ack_pkt[IP].src

        session = self.active_streams.get((server_ip, STREAMING_SERVER_PORT))
        if not session:
            print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_port} received SYN-ACK from {server_ip} but no active session found. Ignoring.")
            return

        # Update client sequence based on server's ACK, and set what client will ACK from server
        session['client_seq'] = server_syn_ack_pkt[TCP].ack
        session['server_ack_of_client_seq'] = server_syn_ack_pkt[TCP].seq + 1

        ack_pkt = create_base_packet(clock, self.ip_address, client_port, server_ip, STREAMING_SERVER_PORT,
                                     flags="A", seq=session['client_seq'], ack=session['server_ack_of_client_seq'])

        packet_timestamp = current_time.timestamp()
        self.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        target_server_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)
        if faucet_controller_host:
            faucet_controller_host.add_packet_to_pcap(ack_pkt, timestamp=packet_timestamp)

        # Client host event for established connection (optional)
        # self.add_host_event(...)

        # Connection established. Server can now start sending data.
        # Update server's knowledge of client's ACK for its SYN-ACK (implicitly done by server receiving this ACK)
        # And schedule the first data packet from the server.
        client_ip_port_tuple = (self.ip_address, client_port) # For server to identify stream

        # Server's active_streams entry needs to be updated with the client's ACK for the server's sequence.
        # This happens when the server "receives" this ACK packet.
        # For simulation, we can directly update the server's state or schedule an event for it.
        # Here, we directly update the server's state for simplicity before scheduling its data send.
        server_session = target_server_host.active_streams.get(client_ip_port_tuple)
        if server_session:
            server_session['client_ack_of_server_seq'] = session['server_ack_of_client_seq']
        else:
            # This would be an inconsistency if the server didn't have the stream active after sending SYN-ACK
            print(f"WARNING: {clock.get_timestamp_str(current_time)}: Server {target_server_host.ip_address} has no active stream for {client_ip_port_tuple} upon client ACK.")


        stream_end_time = current_time + datetime.timedelta(seconds=stream_duration_seconds)

        event_time = current_time + datetime.timedelta(seconds=INTER_PACKET_DELAY_SECONDS) # Server sends first data packet shortly after ACK
        scheduler.add_event(Event(event_time, 2, target_server_host.send_streaming_data_packet,
                                  f"Server {server_ip} starts stream data to {self.ip_address}:{client_port}",
                                  args=(clock, scheduler, self, faucet_controller_host, client_ip_port_tuple, stream_end_time)))
        print(f"{clock.get_timestamp_str(current_time)}: Client {self.ip_address}:{client_port} ACKed stream with {server_ip}. Scheduled server's first data packet.")
    # Client typically just sends ACKs for data packets. For simplicity, these ACKs are not explicitly simulated here.
    # A full TCP stack simulation would involve client scheduling ACK events upon receiving data.


class FaucetController(Host):
    def __init__(self, ip_address, hostname, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)

class RouterGateway(Host):
    def __init__(self, ip_address, hostname, external_ip_address, output_dir="output"):
        super().__init__(ip_address, hostname, output_dir)
        self.external_ip_address = external_ip_address
        self.mac_address_internal_placeholder = f"00:00:00:AA:BB:{random.randint(10,99):02X}" # Router's internal MAC
        self.mac_address_external_placeholder = f"00:00:00:DD:EE:{random.randint(10,99):02X}" # Router's external MAC
        # self.dns_cache = {} # Simple DNS cache if acting as a caching resolver
        # self.arp_cache_external = {} # IP -> MAC for external network
        # self.arp_cache_internal = {} # IP -> MAC for internal network

    # Modified add_packet_to_pcap to handle direction if needed for more complex routing logic later.
    # For now, it just writes to the router's main pcap file.
    # The global gateway_transit_pcap_writer is used for packets truly transiting.
    # However, the Nmap logic seems to call router_gateway_host.add_packet_to_pcap for transit.
    # This means "router_self_traffic.pcap" will contain these. This is acceptable.
    def add_packet_to_pcap(self, packet, timestamp: float | None = None, direction: str | None = None):
        """Writes a packet to this host's PCAP file. Direction can be used for context."""
        if self.pcap_writer:
            # Ensure packet time is set, Scapy PcapWriter uses pkt.time
            if timestamp is not None:
                packet.time = timestamp
            elif not hasattr(packet, 'time') or packet.time is None:
                 # Fallback if not set by create_base_packet or caller; ideally should always be set.
                packet.time = datetime.datetime.now().timestamp()

            # Log direction if provided (optional, for router's own analysis or richer logs)
            # if direction:
            #     print(f"DEBUG: Router {self.hostname} logging packet {packet.summary()} direction {direction}")
            self.pcap_writer.write(packet)


    def handle_dns_query(self, clock, scheduler, query_packet: IP,
                         faucet_controller_host: Host, client_host_who_queried: ClientNormal1,
                         target_http_server_obj: WebServerDVWA): # target_http_server_obj is DVWA server instance
        current_time = clock.get_time()
        dns_request_layer = query_packet.getlayer(DNS)
        if not dns_request_layer or not dns_request_layer.qd: # Ensure it's a DNS query with a question
            print(f"{clock.get_timestamp_str(current_time)}: Router received non-DNS query or malformed DNS query. Dropping.")
            return

        qname_bytes = dns_request_layer.qd.qname
        qname_str = qname_bytes.decode('utf-8')

        client_ip = query_packet[IP].src
        client_udp_sport = query_packet[UDP].sport # Client's source port for this DNS query

        response_ip_str = None
        # Basic DNS resolution logic (replace with cache lookup or forwarding if more advanced)
        if qname_str == DNS_QUERY_NAME: # DNS_QUERY_NAME should be "dvwa.internal.local."
            response_ip_str = VICTIM_WEBSRV_DVWA_IP
        # Add more records if needed:
        # elif qname_str == "another.internal.local.":
        #    response_ip_str = "10.0.0.X"

        if response_ip_str:
            # Construct DNS response packet
            # Ether src/dst are swapped from query_packet
            # IP src is router, dst is client
            # UDP src is 53 (DNS port), dport is client's original sport
            # DNS id matches query, qr=1 (response), aa=1 (authoritative for this direct resolution)
            # qd is copied from query, an is the answer record
            dns_response_pkt = Ether(dst=query_packet[Ether].src, src=query_packet[Ether].dst)/ \
                               IP(dst=client_ip, src=self.ip_address)/ \
                               UDP(dport=client_udp_sport, sport=53)/ \
                               DNS(id=dns_request_layer.id, qr=1, aa=1, qd=dns_request_layer.qd, \
                                   an=DNSRR(rrname=qname_bytes, type='A', rdata=response_ip_str, ttl=600)) # ttl in seconds

            dns_response_pkt.time = current_time.timestamp()

            self.add_packet_to_pcap(dns_response_pkt, timestamp=dns_response_pkt.time)
            # The client_host_who_queried will also record this packet from its perspective when it "receives" it.
            # So, no need for client_host_who_queried.add_packet_to_pcap(dns_response_pkt) here.
            if faucet_controller_host:
                faucet_controller_host.add_packet_to_pcap(dns_response_pkt, timestamp=dns_response_pkt.time)

            self.add_host_event(current_time, 0, 0, 0, "dnsmasq", # Example router DNS process
                                "network_data", "sendto", self.ip_address, client_ip,
                                53, client_udp_sport,
                                f"DNS response for {qname_str} -> {response_ip_str}")

            # Schedule client to handle this response
            event_time = current_time + datetime.timedelta(seconds=0.005) # RTT for response to reach client
            scheduler.add_event(Event(event_time, 1, client_host_who_queried.handle_dns_response,
                                      f"Client {client_host_who_queried.ip_address} handles DNS Response for {qname_str}",
                                      args=(clock, scheduler, dns_response_pkt, target_http_server_obj, faucet_controller_host)))
            # print(f"{clock.get_timestamp_str(current_time)}: Router ({self.ip_address}) sent DNS response for {qname_str} to {client_ip}. Scheduled client handle_dns_response.")
        else:
            # TODO: Handle NXDOMAIN (Non-Existent Domain) response
            print(f"{clock.get_timestamp_str(current_time)}: Router ({self.ip_address}) has no DNS record for {qname_str}. NXDOMAIN not implemented.")
            self.add_host_event(current_time, 0, 0, 0, "dnsmasq",
                                "dns_resolution_fail", "", self.ip_address, client_ip,
                                53, client_udp_sport,
                                f"No DNS record for {qname_str}")


class MasterClock:
    """Manages the simulation time."""
    def __init__(self, start_time=None):
        """
        Initializes the master clock.
        Args:
            start_time (datetime.datetime, optional): The initial time for the simulation.
                                                     Defaults to datetime.datetime.now().
        """
        self.current_time = start_time if start_time else datetime.datetime.now()

    def get_time(self) -> datetime.datetime:
        """Returns the current simulation time."""
        return self.current_time

    def advance_time(self, new_time: datetime.datetime):
        """
        Advances the simulation clock to a new_time.
        Args:
            new_time (datetime.datetime): The time to advance to.
        Raises:
            ValueError: If new_time is in the past.
        """
        if new_time < self.current_time:
            raise ValueError("Cannot advance time to the past.")
        self.current_time = new_time

    def get_timestamp_str(self, dt_obj: datetime.datetime = None) -> str:
        """
        Returns a datetime object as a string for CSV logs.
        Uses current simulation time if dt_obj is None.
        """
        if dt_obj is None:
            dt_obj = self.current_time
        return dt_obj.strftime('%Y-%m-%d %H:%M:%S.%f')


class Event:
    """Represents an event in the simulation."""
    def __init__(self, timestamp: datetime.datetime, priority: int, action, description: str, args: tuple = None):
        """
        Initializes an Event.
        Args:
            timestamp (datetime.datetime): The time at which the event occurs.
            priority (int): The priority of the event (lower value means higher priority).
            action (callable): The function to call when the event is processed.
            description (str): A human-readable description of the event.
            args (tuple, optional): Arguments to pass to the action callable.
        """
        self.timestamp = timestamp
        self.priority = priority
        self.action = action
        self.description = description
        self.args = args if args is not None else () # Ensure args is always a tuple

    def __lt__(self, other):
        """Compares two events for ordering in the priority queue."""
        if self.timestamp == other.timestamp:
            return self.priority < other.priority
        return self.timestamp < other.timestamp


class EventScheduler:
    """Manages and schedules events using a min-heap."""
    def __init__(self):
        """Initializes an empty event list (min-heap)."""
        self._events = []

    def add_event(self, event: Event):
        """
        Adds an event to the scheduler.
        Args:
            event (Event): The event to add.
        """
        heapq.heappush(self._events, event)

    def get_next_event(self) -> Event | None:
        """
        Retrieves and removes the next event (earliest timestamp, highest priority)
        from the scheduler.
        Returns:
            Event | None: The next event, or None if the scheduler is empty.
        """
        if not self.is_empty():
            return heapq.heappop(self._events)
        return None

    def is_empty(self) -> bool:
        """Checks if the event scheduler is empty."""
        return not self._events


def create_output_directory(dir_name="output"):
    """
    Creates the output directory if it doesn't already exist.
    Args:
        dir_name (str, optional): The name of the directory to create.
                                  Defaults to "output".
    """
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

    # For printing specific event times using the clock's formatter
    # Example: print(master_clock.get_timestamp_str(specific_datetime_object))

    print(f"Simulation setup complete. Start time: {master_clock.get_timestamp_str()}. Duration: {args.duration} minutes.")

    # Initialize Hosts
    attacker = Attacker(ATTACKER_EXT_KALI_IP, HOSTNAME_ATTACKER_KALI, OUTPUT_DIR)
    dvwa_server = WebServerDVWA(VICTIM_WEBSRV_DVWA_IP, VICTIM_WEBSRV_DVWA_HOSTNAME, OUTPUT_DIR)
    metasploitable_server = VulnServerMetasploitable(VICTIM_VULNSRV_METASPLOITABLE_IP, HOSTNAME_METASPLOITABLE, OUTPUT_DIR)
    client1 = ClientNormal1(CLIENT_NORMAL_1_IP, HOSTNAME_CLIENT_NORMAL_1, OUTPUT_DIR)
    client2 = ClientNormal2(CLIENT_NORMAL_2_IP, HOSTNAME_CLIENT_NORMAL_2, OUTPUT_DIR)
    faucet_controller = FaucetController(FAUCET_CONTROLLER_VM_IP, HOSTNAME_FAUCET_CONTROLLER, OUTPUT_DIR)
    router_gateway = RouterGateway(ROUTER_INTERNAL_IP, HOSTNAME_ROUTER_GATEWAY, ROUTER_EXTERNAL_IP, OUTPUT_DIR)

    print("Host instances created.")

    # Initialize PCAP writers for individual hosts
    attacker.init_pcap_writer("attacker_traffic.pcap")
    dvwa_server.init_pcap_writer("dvwa_server_traffic.pcap")
    metasploitable_server.init_pcap_writer("metasploitable_server_traffic.pcap")
    client1.init_pcap_writer("client1_traffic.pcap")
    client2.init_pcap_writer("client2_traffic.pcap")
    faucet_controller.init_pcap_writer("faucet_controller_traffic.pcap")
    # For gateway, we might want to log traffic from its perspective (internal/external interfaces)
    # Using the host's writer for its own traffic, and a separate one for transit traffic.
    router_gateway.init_pcap_writer("router_self_traffic.pcap") # Traffic originating/destined to router IP

    # Global/central PCAP writer for traffic passing through the gateway
    gateway_transit_pcap_path = os.path.join(OUTPUT_DIR, "gateway_transit_traffic.pcap")
    gateway_transit_pcap_writer = PcapWriter(gateway_transit_pcap_path, append=True, sync=True)
    print(f"Gateway transit PCAP writer initialized at {gateway_transit_pcap_path}")

    # Example of scheduling video streaming activity
    sim_start_time = master_clock.get_time() # Capture the actual start time of the simulation clock

    # --- Schedule ClientNormal2 Video Streaming ---
    if isinstance(client2, ClientNormal2) and isinstance(dvwa_server, WebServerDVWA) and isinstance(faucet_controller, FaucetController):
        video_stream_start_delay_seconds = 5
        video_stream_event_time = sim_start_time + datetime.timedelta(seconds=video_stream_start_delay_seconds)
        VIDEO_STREAM_ACTIVE_DURATION_SECONDS = 30
        client2.start_video_stream(event_scheduler, master_clock, dvwa_server, faucet_controller,
                                   video_stream_event_time, VIDEO_STREAM_ACTIVE_DURATION_SECONDS)
    else:
        print(f"WARN: Types mismatch for video stream scheduling: client2={type(client2)}, dvwa_server={type(dvwa_server)}, faucet={type(faucet_controller)}")

    # --- Schedule ClientNormal1 Web Browsing ---
    if isinstance(client1, ClientNormal1) and isinstance(dvwa_server, WebServerDVWA) and \
       isinstance(router_gateway, RouterGateway) and isinstance(faucet_controller, FaucetController):
        web_browse_start_delay_seconds = 2
        web_browse_event_time = sim_start_time + datetime.timedelta(seconds=web_browse_start_delay_seconds)
        client1.start_web_browsing(event_scheduler, master_clock, DNS_QUERY_NAME, dvwa_server,
                                   router_gateway, faucet_controller, web_browse_event_time)
    else:
        print(f"WARN: Types mismatch for web browsing scheduling: client1={type(client1)}, dvwa_server={type(dvwa_server)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")

    # Initialize ALL_HOSTS map (must be done after all hosts are instantiated for Nmap and Exploitation)
    ALL_HOSTS = { host.ip_address: host for host in [attacker, dvwa_server, metasploitable_server, client1, client2, faucet_controller, router_gateway] if host}

    # --- Schedule Attacker Nmap Scan ---
    if isinstance(attacker, Attacker) and isinstance(router_gateway, RouterGateway) and \
       isinstance(faucet_controller, FaucetController):
        nmap_scan_start_delay_seconds = 10
        nmap_scan_event_time = sim_start_time + datetime.timedelta(seconds=nmap_scan_start_delay_seconds)
        attacker.start_nmap_scan(event_scheduler, master_clock, NMAP_TARGET_IPS,
                                NMAP_TARGET_PORTS_COMMON, router_gateway,
                                faucet_controller, ALL_HOSTS, nmap_scan_event_time)
    else:
        print(f"WARN: Types mismatch for Nmap scan scheduling: attacker={type(attacker)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")

    # --- Schedule Attacker DVWA Exploitation ---
    if isinstance(attacker, Attacker) and isinstance(dvwa_server, WebServerDVWA) and \
       isinstance(router_gateway, RouterGateway) and isinstance(faucet_controller, FaucetController):
        exploitation_start_delay_seconds = 20 # Start after Nmap might have found open ports
        exploitation_event_time = sim_start_time + datetime.timedelta(seconds=exploitation_start_delay_seconds)
        attacker.start_dvwa_exploitation(event_scheduler, master_clock, dvwa_server,
                                        router_gateway, faucet_controller, exploitation_event_time)
    else:
        print(f"WARN: Types mismatch for DVWA exploitation scheduling: attacker={type(attacker)}, dvwa_server={type(dvwa_server)}, router={type(router_gateway)}, faucet={type(faucet_controller)}")


    # Main simulation loop
    #    a. Advance master_clock to event.timestamp
    #    b. Execute event.action(*event.args)
    #    c. Log event processing
    # 3. If no more events or simulation time exceeded, break loop.

    # For now, we'll just process a few events if any were added (like the video stream start)
    # This is a more complete version of the simplified loop used before.
    print("\n--- Starting Main Simulation Loop ---")
    processed_event_count = 0
    # simulation_end_time is already calculated from sim_start_time + args.duration

    # Initialize a global list of hosts for easier lookup if needed by event actions
    # This is a simple approach; a more robust system might use a dedicated Simulation class
    # that owns the hosts, clock, and scheduler.
    ALL_HOSTS = {
        attacker.ip_address: attacker,
        dvwa_server.ip_address: dvwa_server,
        metasploitable_server.ip_address: metasploitable_server,
        client1.ip_address: client1,
        client2.ip_address: client2,
        faucet_controller.ip_address: faucet_controller,
        router_gateway.ip_address: router_gateway
        # Add other hosts if any by their primary IP
    }
    # Make ALL_HOSTS accessible if needed, e.g. by passing a simulation context object to methods
    # For now, methods that need other hosts usually get them passed as arguments.

    while not event_scheduler.is_empty():
        next_event = event_scheduler.get_next_event()
        if next_event is None: # Should not happen if is_empty() is false, but defensive
            break

        # Check if event is beyond the total simulation duration
        if next_event.timestamp > simulation_end_time:
            print(f"Event '{next_event.description}' at {master_clock.get_timestamp_str(next_event.timestamp)} is beyond simulation end time ({master_clock.get_timestamp_str(simulation_end_time)}). Stopping.")
            # event_scheduler.add_event(next_event) # Optionally put back if it might be used by a longer sim
            break # Stop processing further events

        # Ensure events are processed in chronological order
        if next_event.timestamp < master_clock.get_time():
            print(f"Warning: Event '{next_event.description}' timestamp {master_clock.get_timestamp_str(next_event.timestamp)} is in the past compared to current clock {master_clock.get_timestamp_str()}. Potential scheduling issue. Skipping.")
            # This can happen if events are not strictly ordered or if clock advancement is inconsistent.
            # However, with heapq, next_event.timestamp should always be >= master_clock.get_time() if clock is only advanced to event times.
            continue

        master_clock.advance_time(next_event.timestamp)

        # Reduced verbosity for common events like data transfer, can be enabled for debugging
        if "stream data" not in next_event.description and "ACKs HTTP Response" not in next_event.description : # Example filter
             print(f"[{master_clock.get_timestamp_str()}] Processing Event ({next_event.priority}): {next_event.description}")

        try:
            next_event.action(*next_event.args) # Execute the event's action with its arguments
            processed_event_count += 1
        except Exception as e:
            print(f"ERROR executing event action for '{next_event.description}' at {master_clock.get_timestamp_str()}: {e}")
            import traceback
            traceback.print_exc()
            # Depending on severity, you might want to break the simulation or log and continue
            # For this generator, we'll log and continue.

        # Optional: Add a small sleep for very fast simulations if output is too quick to read,
        # but generally not needed for data generation.
        # time.sleep(0.0001)

    if event_scheduler.is_empty():
        print(f"--- Event scheduler became empty at simulation time: {master_clock.get_timestamp_str()} ---")

    print(f"--- Main Simulation Loop Finished. Processed {processed_event_count} events. ---")
    print(f"Final Simulation Time: {master_clock.get_timestamp_str()}")


    # Cleanup phase (already in a good structure)
    # try: ... finally: is good practice if the loop itself could raise unhandled exceptions
    # that would prevent cleanup. Here, exceptions within event actions are caught.
    print("\nStarting cleanup phase...")
    # Write CSV event logs
    if 'attacker' in locals(): attacker.write_events_to_csv("attacker_events.csv")
    if 'dvwa_server' in locals(): dvwa_server.write_events_to_csv("dvwa_server_events.csv")
    if 'metasploitable_server' in locals(): metasploitable_server.write_events_to_csv("metasploitable_server_events.csv")
    if 'client1' in locals(): client1.write_events_to_csv("client1_events.csv")
    if 'client2' in locals(): client2.write_events_to_csv("client2_events.csv")
    if 'faucet_controller' in locals(): faucet_controller.write_events_to_csv("faucet_controller_events.csv")
    if 'router_gateway' in locals(): router_gateway.write_events_to_csv("router_gateway_events.csv")

    # Close all PCAP writers
    if 'attacker' in locals(): attacker.close_pcap_writer()
    if 'dvwa_server' in locals(): dvwa_server.close_pcap_writer()
    if 'metasploitable_server' in locals(): metasploitable_server.close_pcap_writer()
    if 'client1' in locals(): client1.close_pcap_writer()
    if 'client2' in locals(): client2.close_pcap_writer()
    if 'faucet_controller' in locals(): faucet_controller.close_pcap_writer()
    if 'router_gateway' in locals(): router_gateway.close_pcap_writer()

    if 'gateway_transit_pcap_writer' in locals() and gateway_transit_pcap_writer:
        # Check if it's already closed by any chance, though PcapWriter handles this.
        if hasattr(gateway_transit_pcap_writer, 'closed') and not gateway_transit_pcap_writer.closed:
             gateway_transit_pcap_writer.close()
        print("Gateway transit PCAP writer closed.")

    print("Cleanup complete. Simulation finished.")
