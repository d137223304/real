import os
import argparse
import pandas as pd
import csv # Added for csv.QUOTE_ALL
from datetime import datetime, timedelta # timedelta might be needed for timestamp tolerance
from scapy.all import rdpcap, TCP, UDP, IP, ICMP # Add specific layers as needed
# For memory efficient reading of large pcaps, PcapReader can be an alternative
# from scapy.all import PcapReader


# Placeholder for constants that will be needed for labeling rules
# These should match the values used in master_data_generator.py
ATTACKER_EXT_KALI_IP = "192.168.100.50"
VICTIM_WEBSRV_DVWA_IP = "10.0.0.101"
VICTIM_VULNSRV_METASPLOITABLE_IP = "10.0.0.102"
CLIENT_NORMAL_1_IP = "10.0.0.201"
CLIENT_NORMAL_2_IP = "10.0.0.202"

# Define a small tolerance for timestamp correlation (e.g., 0.5 seconds)
TIMESTAMP_TOLERANCE = timedelta(seconds=0.5)


# Expected columns for an empty host events DataFrame
EXPECTED_HOST_EVENT_COLUMNS = [
    "Timestamp", "PID", "PPID", "UID", "Comm", "EventType",
    "Syscall", "SrcIP", "DstIP", "SrcPort", "DstPort", "Details"
]


def load_and_consolidate_host_events(input_dir_path):
    """
    Loads and consolidates all host event CSV files from the input directory.
    """
    all_events_dfs = []
    try:
        files_in_dir = os.listdir(input_dir_path)
    except FileNotFoundError:
        print(f"Error: Input directory for host events not found: {input_dir_path}")
        return pd.DataFrame(columns=EXPECTED_HOST_EVENT_COLUMNS)

    for filename in files_in_dir:
        if filename.endswith("_events.csv"):
            full_file_path = os.path.join(input_dir_path, filename)
            print(f"Processing host event file: {filename}")
            try:
                df = pd.read_csv(full_file_path)
                if df.empty:
                    print(f"Warning: Host event file {filename} is empty.")
                    continue

                # Crucial: Convert Timestamp column
                df['Timestamp'] = pd.to_datetime(df['Timestamp'])

                # Add a column to identify the source host from the filename
                source_host_name = filename.replace("_events.csv", "")
                df['SourceHostEventFile'] = source_host_name

                all_events_dfs.append(df)
            except pd.errors.EmptyDataError:
                print(f"Warning: Host event file {filename} is empty or contains no data.")
            except KeyError as e:
                print(f"Warning: Missing expected column {e} in {filename}. Skipping this file.")
            except ValueError as e:
                print(f"Warning: Error converting timestamp in {filename}: {e}. Skipping this file.")
            except Exception as e:
                print(f"Error processing file {filename}: {e}")

    if not all_events_dfs:
        print("Warning: No host event CSV files found or processed.")
        return pd.DataFrame(columns=EXPECTED_HOST_EVENT_COLUMNS + ['SourceHostEventFile'])

    try:
        master_df = pd.concat(all_events_dfs, ignore_index=True)
        master_df.sort_values(by='Timestamp', inplace=True)
        print(f"Successfully loaded and consolidated {len(master_df)} host events from {len(all_events_dfs)} CSV files.")
        return master_df
    except Exception as e:
        print(f"Error during final concatenation or sort of host events: {e}")
        return pd.DataFrame(columns=EXPECTED_HOST_EVENT_COLUMNS + ['SourceHostEventFile'])


# --- Network Flow Reconstruction ---

UDP_FLOW_TIMEOUT = timedelta(seconds=60)
ICMP_FLOW_TIMEOUT = timedelta(seconds=30)
# TCP flows are typically ended by FIN/RST, but a very long timeout could be a fallback.
# For now, relying on FIN/RST for TCP.

EXPECTED_FLOW_COLUMNS = [
    "FlowID", "Timestamp_Start", "Timestamp_End", "Duration", "Protocol",
    "SrcIP", "DstIP", "SrcPort", "DstPort", "TotalPackets", "TotalBytes", "PcapFile", "InitialFlags", "ClosingFlags"
]

def _get_flow_key(packet, pkt_time):
    """Helper to create a unique key for a flow."""
    if IP not in packet:
        return None, None

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol_name = None
    src_port, dst_port = None, None

    if TCP in packet:
        protocol_name = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol_name = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif ICMP in packet:
        protocol_name = 'ICMP'
        src_port = packet[ICMP].type # Using type/code for ICMP "ports"
        dst_port = packet[ICMP].code
        # For echo request/reply, id is important for matching
        if packet[ICMP].type in [0, 8]: # Echo reply or request
             # Include ICMP ID in one of the "port" fields for key uniqueness
             # This is a simplification for flow keying.
             if hasattr(packet[ICMP], 'id'):
                 dst_port = f"{packet[ICMP].code}_{packet[ICMP].id}"
    else:
        return None, None # Not a supported protocol for flow reconstruction

    # Ensure consistent ordering for the key (e.g., lower IP/port first)
    # This makes (A,B) and (B,A) part of the same flow if desired,
    # but for directional flows, we keep them distinct.
    # For this implementation, we treat (A,B) and (B,A) as distinct flows.
    return (src_ip, dst_ip, src_port, dst_port, protocol_name), protocol_name


def _finalize_flow(flow_data, end_time, closing_flags=None):
    """Helper to finalize a flow entry."""
    flow_data['Timestamp_End'] = end_time
    start_time = flow_data['Timestamp_Start']
    # Ensure both are datetime objects before subtraction
    if isinstance(start_time, datetime) and isinstance(end_time, datetime):
        flow_data['Duration'] = (end_time - start_time).total_seconds()
    else:
        flow_data['Duration'] = -1 # Indicate error or missing data
    if closing_flags:
        flow_data['ClosingFlags'] = closing_flags
    return flow_data

def _finalize_timed_out_flows(active_flows, current_time, timeout_delta, all_flows_data, protocol_name_filter):
    """Helper to check and finalize timed-out UDP/ICMP flows."""
    timed_out_keys = []
    for key, flow_data in active_flows.items():
        # Check protocol matches if a filter is provided (e.g. don't timeout TCP using UDP logic)
        if protocol_name_filter and key[4] != protocol_name_filter:
            continue
        if current_time - flow_data['Timestamp_End'] > timeout_delta:
            all_flows_data.append(_finalize_flow(flow_data, flow_data['Timestamp_End'])) # End time is last packet's time
            timed_out_keys.append(key)
    for key in timed_out_keys:
        del active_flows[key]

def reconstruct_flows_from_pcaps(input_dir_path):
    """
    Reconstructs network flows from all PCAP files in the input directory.
    """
    all_flows_data = []
    flow_id_counter = 0

    try:
        pcap_files = [f for f in os.listdir(input_dir_path) if f.endswith(".pcap")]
    except FileNotFoundError:
        print(f"Error: Input directory for PCAPs not found: {input_dir_path}")
        return pd.DataFrame(columns=EXPECTED_FLOW_COLUMNS)

    if not pcap_files:
        print("No PCAP files found in the input directory.")
        return pd.DataFrame(columns=EXPECTED_FLOW_COLUMNS)

    active_flows = {} # Combined dict for TCP, UDP, ICMP for simplicity of timeout iteration

    for pcap_filename in pcap_files:
        full_pcap_path = os.path.join(input_dir_path, pcap_filename)
        print(f"\nProcessing PCAP file: {pcap_filename}")

        try:
            packets = rdpcap(full_pcap_path)
            # Scapy's rdpcap loads packets in order, but an explicit sort is safer if files could be malformed/merged.
            # For performance on known good captures, this sort might be skipped.
            packets.sort(key=lambda p: p.time)
        except Exception as e:
            print(f"Error reading or sorting PCAP file {pcap_filename}: {e}")
            continue

        for packet_idx, packet in enumerate(packets):
            try:
                pkt_time = datetime.fromtimestamp(float(packet.time))
                flow_key_tuple, protocol_name = _get_flow_key(packet, pkt_time)

                if not flow_key_tuple:
                    continue # Packet not suitable for flow tracking (e.g. not IP, or not TCP/UDP/ICMP)

                packet_len = len(packet)

                if protocol_name == 'TCP':
                    flags = packet[TCP].flags
                    if flags.S: # SYN packet
                        if flow_key_tuple not in active_flows:
                            flow_id_counter += 1
                            active_flows[flow_key_tuple] = {
                                "FlowID": flow_id_counter, "Timestamp_Start": pkt_time, "Timestamp_End": pkt_time,
                                "Protocol": 'TCP', "SrcIP": flow_key_tuple[0], "DstIP": flow_key_tuple[1],
                                "SrcPort": flow_key_tuple[2], "DstPort": flow_key_tuple[3],
                                "TotalPackets": 1, "TotalBytes": packet_len, "PcapFile": pcap_filename,
                                "InitialFlags": str(flags), "ClosingFlags": ""
                            }
                        else: # SYN for an existing flow (e.g. retransmission, or more complex scenario)
                            active_flows[flow_key_tuple]['TotalPackets'] += 1
                            active_flows[flow_key_tuple]['TotalBytes'] += packet_len
                            active_flows[flow_key_tuple]['Timestamp_End'] = pkt_time
                            # Potentially update InitialFlags if this SYN is different or more complete
                    elif flow_key_tuple in active_flows:
                        active_flows[flow_key_tuple]['TotalPackets'] += 1
                        active_flows[flow_key_tuple]['TotalBytes'] += packet_len
                        active_flows[flow_key_tuple]['Timestamp_End'] = pkt_time
                        if flags.F or flags.R: # FIN or RST packet
                            all_flows_data.append(_finalize_flow(active_flows[flow_key_tuple], pkt_time, str(flags)))
                            del active_flows[flow_key_tuple]
                    # Else: TCP packet for a flow we didn't see a SYN for. For now, ignore.
                    # Could optionally create a flow if policy dictates.

                elif protocol_name in ['UDP', 'ICMP']:
                    timeout = UDP_FLOW_TIMEOUT if protocol_name == 'UDP' else ICMP_FLOW_TIMEOUT
                    if flow_key_tuple not in active_flows:
                        flow_id_counter += 1
                        active_flows[flow_key_tuple] = {
                            "FlowID": flow_id_counter, "Timestamp_Start": pkt_time, "Timestamp_End": pkt_time,
                            "Protocol": protocol_name, "SrcIP": flow_key_tuple[0], "DstIP": flow_key_tuple[1],
                            "SrcPort": flow_key_tuple[2], "DstPort": flow_key_tuple[3],
                            "TotalPackets": 1, "TotalBytes": packet_len, "PcapFile": pcap_filename,
                            "InitialFlags": "", "ClosingFlags": "" # Less relevant for UDP/ICMP in this simple model
                        }
                    else:
                        active_flows[flow_key_tuple]['TotalPackets'] += 1
                        active_flows[flow_key_tuple]['TotalBytes'] += packet_len
                        active_flows[flow_key_tuple]['Timestamp_End'] = pkt_time

                    # Periodically check for timeouts for UDP/ICMP flows
                    # This check can be done less frequently (e.g. every N packets or T seconds) for performance
                    # For simplicity here, check after each relevant packet.
                    _finalize_timed_out_flows(active_flows, pkt_time, timeout, all_flows_data, protocol_name)

            except AttributeError as ae:
                # This can happen if a packet is malformed or doesn't have expected layers/fields
                # print(f"Skipping packet due to AttributeError: {ae} in {pcap_filename}")
                continue # Skip to next packet
            except Exception as ex:
                print(f"Unexpected error processing packet {packet_idx} in {pcap_filename}: {ex}")
                continue


        # After processing all packets in the current PCAP, finalize remaining active flows for this PCAP
        # Note: This simple model assumes flows don't span PCAP files.
        # For TCP, this will mostly be flows that didn't see FIN/RST.
        # For UDP/ICMP, this finalizes flows not yet timed out.
        print(f"End of PCAP {pcap_filename}. Finalizing {len(active_flows)} active flows...")
        active_flow_keys_for_this_pcap = [k for k,v in active_flows.items() if v['PcapFile'] == pcap_filename]

        for key in list(active_flow_keys_for_this_pcap): # list() to avoid issues with dict changing size
            if key in active_flows: # Check if not already finalized by timeout check within loop
                flow_data = active_flows[key]
                # Use the Timestamp_End of the flow itself (i.e., time of its last packet)
                all_flows_data.append(_finalize_flow(flow_data, flow_data['Timestamp_End']))
                del active_flows[key]
        print(f"Finalized flows for {pcap_filename}. Total flows collected so far: {len(all_flows_data)}")

    # After all PCAP files are processed, one final check for any remaining flows in active_flows
    # (though the per-file finalization should handle most)
    if active_flows:
        print(f"Finalizing {len(active_flows)} remaining flows after all PCAPs processed...")
        for key in list(active_flows.keys()):
            flow_data = active_flows[key]
            all_flows_data.append(_finalize_flow(flow_data, flow_data['Timestamp_End']))
            del active_flows[key]

    if not all_flows_data:
        print("Warning: No network flows reconstructed from any PCAP file.")
        return pd.DataFrame(columns=EXPECTED_FLOW_COLUMNS)

    flows_df = pd.DataFrame(all_flows_data)
    if not flows_df.empty:
        flows_df.sort_values(by='Timestamp_Start', inplace=True)

    print(f"\nSuccessfully reconstructed {len(flows_df)} network flows from all PCAP files.")
    return flows_df

# --- Correlation of Flows with Host Events ---

def correlate_flows_with_events(flows_df, master_host_events_df):
    """
    Correlates network flows with host events (specifically 'network_connect').
    """
    if flows_df.empty:
        print("Warning: Flows DataFrame is empty. Cannot correlate.")
        return flows_df
    if master_host_events_df.empty:
        print("Warning: Master Host Events DataFrame is empty. Cannot correlate.")
        return flows_df

    print("Starting correlation of flows with host events...")

    # Initialize new columns in flows_df
    flows_df['Correlated_PID'] = pd.NA
    flows_df['Correlated_PPID'] = pd.NA
    flows_df['Correlated_UID'] = pd.NA
    flows_df['Correlated_Comm'] = pd.NA
    flows_df['Correlated_HostEventTimestamp'] = pd.NaT

    # Prepare Host Events for Efficient Searching
    connect_events_df = master_host_events_df[master_host_events_df['EventType'] == 'network_connect'].copy() # Use .copy() to avoid SettingWithCopyWarning

    if connect_events_df.empty:
        print("No 'network_connect' events found in host events. Correlation will be limited.")
        return flows_df

    # Ensure Timestamp columns are datetime objects
    # flows_df['Timestamp_Start'] should already be datetime from reconstruct_flows_from_pcaps
    # connect_events_df['Timestamp'] should already be datetime from load_and_consolidate_host_events
    if not pd.api.types.is_datetime64_any_dtype(flows_df['Timestamp_Start']):
        flows_df['Timestamp_Start'] = pd.to_datetime(flows_df['Timestamp_Start']) # Assuming it's unix timestamp if not datetime
    if not pd.api.types.is_datetime64_any_dtype(connect_events_df['Timestamp']):
        connect_events_df['Timestamp'] = pd.to_datetime(connect_events_df['Timestamp'])

    # Ensure port columns are numeric and handle potential errors
    # DstPort in host events can sometimes be NaN or malformed if not captured correctly.
    connect_events_df['DstPort'] = pd.to_numeric(connect_events_df['DstPort'], errors='coerce').astype('Int64') # Use Int64 to allow pd.NA
    # Flows DstPort should generally be okay from Scapy, but ensure it's also Int64 for comparison
    flows_df['DstPort'] = flows_df['DstPort'].astype('Int64')


    # Sort connect_events_df by Timestamp for potentially faster searching if we were to use searchsorted (more complex)
    # For now, direct filtering is used.
    connect_events_df.sort_values(by='Timestamp', inplace=True)

    correlated_count = 0

    # Iterate Through Flows for Correlation
    for flow in flows_df.itertuples(): # Use itertuples() for better performance
        flow_index = flow.Index
        flow_start_time = flow.Timestamp_Start
        flow_src_ip = flow.SrcIP
        flow_dst_ip = flow.DstIP
        flow_dst_port = flow.DstPort
        # flow_protocol = flow.Protocol # Not used in current host event schema for matching

        # Define time window
        min_time = flow_start_time - TIMESTAMP_TOLERANCE
        max_time = flow_start_time + TIMESTAMP_TOLERANCE

        # Filter candidate_events
        # Step 1: Time window
        candidate_events_time_window = connect_events_df[
            (connect_events_df['Timestamp'] >= min_time) &
            (connect_events_df['Timestamp'] <= max_time)
        ]

        if candidate_events_time_window.empty:
            continue

        # Step 2: Match on IPs and Destination Port
        # Host events SrcIP is the host's IP, DstIP is the remote IP for an outbound connection.
        # So, flow.SrcIP (client) should match event.SrcIP (client making connect call)
        # And flow.DstIP (server) should match event.DstIP (server being connected to)
        # And flow.DstPort should match event.DstPort

        # Handle cases where DstPort might be pd.NA after conversion
        if pd.isna(flow_dst_port):
            final_candidate_events = candidate_events_time_window[
                (candidate_events_time_window['SrcIP'] == flow_src_ip) &
                (candidate_events_time_window['DstIP'] == flow_dst_ip) &
                (candidate_events_time_window['DstPort'].isna()) # Match NaN DstPort
            ]
        else:
            final_candidate_events = candidate_events_time_window[
                (candidate_events_time_window['SrcIP'] == flow_src_ip) &
                (candidate_events_time_window['DstIP'] == flow_dst_ip) &
                (candidate_events_time_window['DstPort'] == flow_dst_port)
            ]

        if final_candidate_events.empty:
            continue

        # Find Best Match: Prioritize events at or before the flow start time
        pre_events = final_candidate_events[final_candidate_events['Timestamp'] <= flow_start_time]

        best_match_event = None
        if not pre_events.empty:
            # Sort by Timestamp descending, take the first one (closest before or at flow_start_time)
            # (flow_start_time - event.Timestamp) should be minimized and non-negative
            pre_events = pre_events.copy() # Avoid SettingWithCopyWarning
            pre_events['time_diff'] = flow_start_time - pre_events['Timestamp']
            best_match_event = pre_events.sort_values(by='time_diff').iloc[0]
        else:
            # Optional: if no events at or before, consider events slightly after (within tolerance)
            # Sort by Timestamp ascending, take the first one (closest after flow_start_time)
            # final_candidate_events = final_candidate_events.copy() # Avoid SettingWithCopyWarning
            # final_candidate_events['time_diff'] = final_candidate_events['Timestamp'] - flow_start_time
            # best_match_event = final_candidate_events.sort_values(by='time_diff').iloc[0]
            pass # For now, only consider events at or before

        if best_match_event is not None:
            flows_df.loc[flow_index, 'Correlated_PID'] = best_match_event.PID
            flows_df.loc[flow_index, 'Correlated_PPID'] = best_match_event.PPID
            flows_df.loc[flow_index, 'Correlated_UID'] = best_match_event.UID
            flows_df.loc[flow_index, 'Correlated_Comm'] = best_match_event.Comm
            flows_df.loc[flow_index, 'Correlated_HostEventTimestamp'] = best_match_event.Timestamp
            correlated_count +=1

        if (flow_index + 1) % 10000 == 0: # Print progress every 10000 flows
            print(f"Processed {flow_index + 1}/{len(flows_df)} flows for event correlation. Found {correlated_count} correlations so far.")

    print(f"Correlation of flows with host events complete. {correlated_count} flows were correlated with a host event.")
    return flows_df

# --- Ground Truth Labeling ---

def get_label_for_flow(flow_row):
    """
    Determines a ground truth label for a single network flow based on its properties
    and correlated host event information.
    """
    comm = flow_row.Correlated_Comm
    src_ip = flow_row.SrcIP
    dst_ip = flow_row.DstIP
    dst_port = flow_row.DstPort # This should be Int64 from previous steps, allowing pd.NA
    src_port = flow_row.SrcPort # Ensure this is accessed for rules needing it
    # pcap_file = flow_row.PcapFile # Available for context if needed

    label = "unknown" # Default label

    if pd.notna(comm):
        comm_lower = str(comm).lower()
        if "nmap" in comm_lower:
            # Nmap scans are typically from the attacker
            if src_ip == ATTACKER_EXT_KALI_IP and (dst_ip == VICTIM_WEBSRV_DVWA_IP or dst_ip == VICTIM_VULNSRV_METASPLOITABLE_IP):
                label = "malicious_reconnaissance_nmap"
        elif "sqlmap" in comm_lower: # sqlmap is an explicit tool name
            if src_ip == ATTACKER_EXT_KALI_IP and dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 80:
                label = "malicious_exploit_sql_injection"
        elif "python" in comm_lower: # General python script
            # This rule is broad for SQLi. If specific exploit scripts are known, they'd be better.
            # Assuming python from attacker to DVWA's web port might be an exploit attempt.
            if src_ip == ATTACKER_EXT_KALI_IP and dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 80:
                label = "malicious_exploit_sql_injection" # Or could be generic "malicious_exploit_script"
        elif "curl" in comm_lower:
            # Curl from attacker to DVWA web port could be command injection probing or execution
            if src_ip == ATTACKER_EXT_KALI_IP and dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 80:
                label = "malicious_exploit_cmd_injection"
        elif "nc" in comm_lower or "netcat" in comm_lower:
            # This rule for lateral movement is very specific to the scenario.
            # It assumes 'nc' is used by DVWA to connect to Metasploitable's FTP (vsftpd backdoor port 21).
            # This implies an initial compromise of DVWA that then uses 'nc'.
            # The correlated 'Comm' would be 'nc' running on DVWA_IP.
            if src_ip == VICTIM_WEBSRV_DVWA_IP and dst_ip == VICTIM_VULNSRV_METASPLOITABLE_IP and dst_port == 21: # Port 21 for vsftpd
                label = "malicious_lateral_movement_ftp_vsftpd_backdoor"
            # Netcat from attacker could be various things (reverse shell, bind shell connection, data transfer)
            elif src_ip == ATTACKER_EXT_KALI_IP:
                 label = "malicious_shell_access_netcat" # Or generic "malicious_tool_netcat"
            # Netcat TO attacker could be a reverse shell connecting back
            elif dst_ip == ATTACKER_EXT_KALI_IP:
                 label = "malicious_shell_access_netcat_reverse"

        elif "chrome.exe" in comm_lower or "firefox.exe" in comm_lower: # Assuming these are from windows clients
             if src_ip == CLIENT_NORMAL_1_IP or src_ip == CLIENT_NORMAL_2_IP:
                # Specific rule for CLIENT_NORMAL_2_IP streaming from VICTIM_WEBSRV_DVWA_IP on port 443
                if src_ip == CLIENT_NORMAL_2_IP and dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 443:
                    label = "benign_streaming"
                # General browsing from clients to DVWA web server
                elif dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 80:
                    label = "benign_browsing_dvwa"
                # Other browsing could be to external sites, still benign in this context
                else:
                    label = "benign_browsing_other"
        # Example for meterpreter - would need 'Comm' name if correlated on victim
        # elif "meterpreter_process_name" in comm_lower and (src_ip == VICTIM_WEBSRV_DVWA_IP or src_ip == VICTIM_VULNSRV_METASPLOITABLE_IP):
        #    if dst_ip == ATTACKER_EXT_KALI_IP: # Connecting back to Kali
        #        label = "malicious_c2_meterpreter"

    # Fallback/Benign identification if no specific malicious indicators from 'Comm'
    # These rules apply if 'label' is still "unknown"
    if label == "unknown":
        # Traffic from known clients not specifically identified by a browser 'Comm'
        if src_ip == CLIENT_NORMAL_1_IP or src_ip == CLIENT_NORMAL_2_IP:
            # If CLIENT_NORMAL_2 is streaming (client sends request to server's 443, or server sends data from its 443)
            if src_ip == CLIENT_NORMAL_2_IP and dst_ip == VICTIM_WEBSRV_DVWA_IP and dst_port == 443:
                 label = "benign_streaming" # Client initiating or interacting with streaming server
            else:
                 label = "benign_client_traffic"
        # Traffic from DVWA server that isn't lateral movement or to a client for streaming
        elif src_ip == VICTIM_WEBSRV_DVWA_IP:
            # Server sending to CLIENT_NORMAL_2 from server's port 443 (streaming data)
            if dst_ip == CLIENT_NORMAL_2_IP and src_port == 443: # Check server's source port
                 label = "benign_streaming"
            elif dst_ip == CLIENT_NORMAL_1_IP or dst_ip == CLIENT_NORMAL_2_IP : # e.g. HTTP responses to benign browsing from server's port 80
                if src_port == 80 and (dst_port is not None and dst_port > 1024): # Check server is sending from port 80
                    label = "benign_browsing_dvwa_response"
                else:
                    label = "benign_dvwa_server_traffic" # Other DVWA egress
            else: # DVWA to other non-client IPs
                label = "benign_dvwa_server_traffic"

        elif src_ip == VICTIM_VULNSRV_METASPLOITABLE_IP:
            label = "benign_metasploitable_server_traffic" # General Metasploitable egress

        # Traffic explicitly to/from attacker not caught by a 'Comm' rule
        elif src_ip == ATTACKER_EXT_KALI_IP or dst_ip == ATTACKER_EXT_KALI_IP:
            label = "malicious_unspecified_attacker_traffic"


    # If still unknown, it might be internal traffic not involving clients or specific servers, or unclassified external
    # For example, router to internal hosts for DNS if not captured by other rules.
    # Or if Correlated_Comm was NaN.

    return label


def load_host_events_csv(csv_filepath):
    """
    Loads host events from a CSV file into a pandas DataFrame.
    Converts 'Timestamp' to datetime objects.
    """
    if not os.path.exists(csv_filepath):
        print(f"Warning: CSV file not found: {csv_filepath}")
        return pd.DataFrame() # Return empty DataFrame

    try:
        events_df = pd.read_csv(csv_filepath)
        # Convert Timestamp column to datetime objects
        events_df['Timestamp'] = pd.to_datetime(events_df['Timestamp'])
        # Sort by timestamp just in case they are not already
        events_df.sort_values(by='Timestamp', inplace=True)
        print(f"Successfully loaded {len(events_df)} events from {csv_filepath}")
        return events_df
    except Exception as e:
        print(f"Error loading or processing CSV file {csv_filepath}: {e}")
        return pd.DataFrame()


def load_pcap_data(pcap_filepath):
    """
    Loads network packets from a PCAP file into a pandas DataFrame.
    Extracts key information from TCP, UDP, and IP layers.
    """
    packets_data = []
    if not os.path.exists(pcap_filepath):
        print(f"Warning: PCAP file not found: {pcap_filepath}")
        return pd.DataFrame()

    try:
        # Using rdpcap to load all packets into memory; for very large files, PcapReader is better
        packets = rdpcap(pcap_filepath)
        for packet in packets:
            pkt_time = datetime.fromtimestamp(float(packet.time))
            src_ip, dst_ip, src_port, dst_port, proto = None, None, None, None, None
            pkt_len = len(packet)

            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
            elif Ether in packet: # Handle non-IP packets like ARP if necessary, basic info for now
                src_ip = packet[Ether].src # MAC Address
                dst_ip = packet[Ether].dst # MAC Address
                proto = packet[Ether].type

            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                proto = 'TCP' # More specific than IP proto number
            elif UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                proto = 'UDP' # More specific
            elif ICMP in packet:
                proto = 'ICMP'
                # ICMP doesn't have ports in the same way, but type/code can be stored if needed
                # src_port = packet[ICMP].type
                # dst_port = packet[ICMP].code

            packets_data.append({
                'Timestamp': pkt_time,
                'SrcIP': src_ip,
                'DstIP': dst_ip,
                'SrcPort': src_port,
                'DstPort': dst_port,
                'Protocol': proto,
                'Length': pkt_len,
                'RawPacket': packet # Keep the raw packet for deeper inspection if needed later
            })

        df = pd.DataFrame(packets_data)
        if not df.empty:
            df.sort_values(by='Timestamp', inplace=True)
        print(f"Successfully loaded {len(df)} packets from {pcap_filepath}")
        return df
    except Exception as e:
        print(f"Error loading or processing PCAP file {pcap_filepath}: {e}")
        return pd.DataFrame()


def correlate_events_and_packets(host_events_df, pcap_df, host_ip):
    """
    Correlates host events with network packets and applies basic labels.

    Args:
        host_events_df (pd.DataFrame): DataFrame of host events.
        pcap_df (pd.DataFrame): DataFrame of network packets.
        host_ip (str): The IP address of the host whose events are being processed.
                       Used to determine direction of traffic for labeling.

    Returns:
        pd.DataFrame: A DataFrame of correlated data with a new 'Label' column.
                      This could be a modified version of pcap_df or host_events_df,
                      or a new DataFrame depending on the desired output.
                      For now, let's aim to label packets.
    """
    if host_events_df.empty and pcap_df.empty:
        print("Both host events and pcap data are empty. No correlation possible.")
        return pd.DataFrame()

    # Add a 'Label' column to the pcap_df, initialized to 'Benign'
    labeled_pcap_df = pcap_df.copy()
    labeled_pcap_df['Label'] = 'Benign'
    labeled_pcap_df['Reason'] = '' # To store why a packet was labeled
    labeled_pcap_df['CorrelatedHostEventTimestamp'] = pd.NaT
    labeled_pcap_df['CorrelatedHostEventDetails'] = ''


    # Example 1: Label packets based on known malicious IPs
    # Packets TO the attacker from the host_ip (potentially C2 communication or data exfil)
    labeled_pcap_df.loc[
        (labeled_pcap_df['SrcIP'] == host_ip) & (labeled_pcap_df['DstIP'] == ATTACKER_EXT_KALI_IP),
        ['Label', 'Reason']
    ] = ['Malicious', 'Outbound to Known Attacker IP']

    # Packets FROM the attacker to the host_ip (potentially attack traffic, C2 commands)
    labeled_pcap_df.loc[
        (labeled_pcap_df['SrcIP'] == ATTACKER_EXT_KALI_IP) & (labeled_pcap_df['DstIP'] == host_ip),
        ['Label', 'Reason']
    ] = ['Malicious', 'Inbound from Known Attacker IP']

    # Example 2: Correlate host events with packets
    # This is a simplified example. Real correlation can be much more complex.
    # It might involve matching on PID, connection tuples (IPs, ports), and time windows.
    if not host_events_df.empty:
        for index, event in host_events_df.iterrows():
            event_time = event['Timestamp']
            event_src_ip = event['SrcIP']
            event_dst_ip = event['DstIP']
            event_src_port = event['SrcPort']
            event_dst_port = event['DstPort']
            event_details = f"Type:{event['EventType']}_Syscall:{event['Syscall']}_Comm:{event['Comm']}_PID:{event['PID']}_Details:{event['Details']}"

            # Define a time window for correlation
            time_window_start = event_time - TIMESTAMP_TOLERANCE
            time_window_end = event_time + TIMESTAMP_TOLERANCE

            # Find packets within this time window and matching connection info (if available)
            # This is a basic correlation logic. More sophisticated matching might be needed.
            # For example, 'network_connect' or 'network_data' events are good candidates.

            potential_matches = labeled_pcap_df[
                (labeled_pcap_df['Timestamp'] >= time_window_start) &
                (labeled_pcap_df['Timestamp'] <= time_window_end)
            ]

            correlated_this_event = False
            for pkt_idx, packet in potential_matches.iterrows():
                # Condition 1: Host event indicates outbound traffic from host_ip
                # and packet matches this (host_ip is src)
                cond1 = (event_src_ip == host_ip and packet['SrcIP'] == host_ip and
                           (pd.isna(event_dst_ip) or event_dst_ip == packet['DstIP']) and # Allow event DstIP to be NaN
                           (pd.isna(event_src_port) or event_src_port == packet['SrcPort']) and
                           (pd.isna(event_dst_port) or event_dst_port == packet['DstPort']))

                # Condition 2: Host event indicates inbound traffic to host_ip
                # and packet matches this (host_ip is dst)
                cond2 = (event_dst_ip == host_ip and packet['DstIP'] == host_ip and
                           (pd.isna(event_src_ip) or event_src_ip == packet['SrcIP']) and # Allow event SrcIP to be NaN
                           (pd.isna(event_src_port) or event_src_port == packet['SrcPort']) and
                           (pd.isna(event_dst_port) or event_dst_port == packet['DstPort']))

                # Condition 3: Event has no IP/port info, but is related to a process that might be doing network activity
                # We might label based on event type if it's suspicious, e.g., 'cmd_injection_executed'
                # This is a more general correlation, less precise.
                # For now, let's focus on events that have some network indicators.

                if cond1 or cond2:
                    # If the event itself is suspicious, label the packet
                    if "exploit_sent" in event['EventType'] or \
                       "cmd_injection_executed" in event['EventType'] or \
                       "sqli_attempt_detected" in event['EventType'] or \
                       "nmap_scan_result" in event['EventType']: # Assuming nmap from attacker is malicious contextually

                        # Prioritize keeping an existing 'Malicious' label if one of these events confirms it
                        if labeled_pcap_df.loc[pkt_idx, 'Label'] != 'Malicious':
                             labeled_pcap_df.loc[pkt_idx, 'Label'] = 'Suspicious-Correlated'

                        current_reason = labeled_pcap_df.loc[pkt_idx, 'Reason']
                        new_reason_part = f"CorrelatedHostEvent({event['EventType']})"
                        if new_reason_part not in current_reason: # Avoid duplicate reasons
                            labeled_pcap_df.loc[pkt_idx, 'Reason'] += ("; " if current_reason else "") + new_reason_part

                        labeled_pcap_df.loc[pkt_idx, 'CorrelatedHostEventTimestamp'] = event_time
                        labeled_pcap_df.loc[pkt_idx, 'CorrelatedHostEventDetails'] = event_details
                        correlated_this_event = True

            if correlated_this_event:
                 print(f"Correlated host event at {event_time} ({event['EventType']}) with one or more packets.")

    # Further refinement: if a packet is part of a known malicious flow (e.g. to/from ATTACKER_EXT_KALI_IP)
    # and it also correlates with a suspicious host event, make sure the label reflects that.
    # The current logic gives precedence to 'Malicious' from IP check.
    # If 'Suspicious-Correlated' is set, and it's also to/from Kali, it will already be 'Malicious'.

    print(f"Correlation and basic labeling complete. Found {len(labeled_pcap_df[labeled_pcap_df['Label'] != 'Benign'])} non-benign packets.")
    print(f"Correlation and basic labeling complete. Found {len(labeled_pcap_df[labeled_pcap_df['Label'] != 'Benign'])} non-benign packets.")
    return labeled_pcap_df


def main(input_dir_path, output_file_path):
    """
    Main function to orchestrate the data loading, correlation, and labeling.
    """
    print(f"Starting data correlation and labeling process...")
    print(f"Input directory: {input_dir_path}")
    print(f"Output file: {output_file_path}")

    # Create the directory for the output file if it doesn't exist at the beginning
    # Ensure output_dir_for_file is not an empty string (e.g. if output_file_path is just a filename in CWD)
    output_dir_for_file = os.path.dirname(output_file_path)
    if output_dir_for_file and not os.path.exists(output_dir_for_file):
        os.makedirs(output_dir_for_file, exist_ok=True)
        print(f"Ensured output directory for file exists: {output_dir_for_file}")

    if not os.path.exists(input_dir_path):
        print(f"Error: Input directory {input_dir_path} does not exist. Exiting.")
        return

    # Step 1: Load and consolidate host events
    print("\nLoading and consolidating host events...")
    master_host_events_df = load_and_consolidate_host_events(input_dir_path)
    if master_host_events_df is None or master_host_events_df.empty:
        print("Warning: No host events loaded. Correlation and some labeling rules might be limited.")
        # Initialize empty df with expected columns if it's None, to prevent errors later
        if master_host_events_df is None: # Should be an empty DF from the function, but double check
             master_host_events_df = pd.DataFrame(columns=EXPECTED_HOST_EVENT_COLUMNS + ['SourceHostEventFile'])
    else:
        print(f"Consolidated host events DataFrame shape: {master_host_events_df.shape}")

    # Step 2: Reconstruct network flows
    print("\nReconstructing network flows from PCAPs...")
    flows_df = reconstruct_flows_from_pcaps(input_dir_path)
    if flows_df is None or flows_df.empty:
        print("Warning: No network flows reconstructed. Most further processing will be skipped.")
        # Ensure flows_df is an empty DataFrame with columns if None, for consistency for final output step.
        if flows_df is None: # Should be an empty DF from the function, but double check
            flows_df = pd.DataFrame(columns=EXPECTED_FLOW_COLUMNS)
    else:
        print(f"Reconstructed flows DataFrame shape: {flows_df.shape}")

    # Step 3: Correlate flows with host events
    if not flows_df.empty and not master_host_events_df.empty:
        print("\nCorrelating network flows with host events...")
        flows_df = correlate_flows_with_events(flows_df, master_host_events_df)
        print("Correlation complete.")
    elif flows_df.empty:
        print("\nSkipping flow-event correlation as no network flows were reconstructed.")
    else: # host events must be empty
        print("\nSkipping flow-event correlation as no (or empty) host events were loaded.")

    # Step 4: Ground truth labeling
    if not flows_df.empty:
        print("\nApplying ground truth labels to flows...")
        # Ensure 'Correlated_Comm' and 'SrcPort' columns exist if they were not created due to empty inputs to prior steps
        if 'Correlated_Comm' not in flows_df.columns:
            flows_df['Correlated_Comm'] = pd.NA
        if 'SrcPort' not in flows_df.columns: # Vital for labeling
            print("Warning: 'SrcPort' column missing in flows_df before labeling. Adding with NA. Labeling accuracy may be affected.")
            flows_df['SrcPort'] = pd.NA # Or an appropriate default like 0 if that makes more sense for get_label_for_flow

        flows_df['Label'] = flows_df.apply(get_label_for_flow, axis=1)
        print("Labeling complete.")
        print("\nLabel distribution:")
        print(flows_df['Label'].value_counts(dropna=False)) # dropna=False to see count of 'unknown' or any NaNs
    else:
        print("\nSkipping ground truth labeling as no flows were available.")

    # Step 7: Final Output
    # This block will handle flows_df even if it's empty (e.g. no pcaps found or no flows reconstructed)
    # In such a case, it will write an empty CSV with headers.
    print(f"\nPreparing final dataset for output to: {output_file_path}")
    final_columns_order = [
        'FlowID', 'Timestamp_Start', 'Timestamp_End', 'Duration', 'Protocol',
        'SrcIP', 'DstIP', 'SrcPort', 'DstPort', 'TotalPackets', 'TotalBytes', 'PcapFile',
        'Correlated_PID', 'Correlated_PPID', 'Correlated_UID', 'Correlated_Comm',
        'Correlated_HostEventTimestamp', 'Label'
    ]

    # Ensure all final columns exist in flows_df, adding any missing ones with NA.
    # This is important if flows_df is empty or some optional columns were not created.
    for col in final_columns_order:
        if col not in flows_df.columns:
            print(f"Warning: Final output column '{col}' not found in flows_df. Adding as NA.")
            flows_df[col] = pd.NA # Assign NA to the whole column if it's missing

    # Select and reorder columns for the final output.
    # If flows_df is empty, output_df will be an empty DataFrame with these columns.
    output_df = flows_df[final_columns_order]

    try:
        print(f"Writing final dataset to: {output_file_path}")
        output_df.to_csv(output_file_path, index=False, quoting=csv.QUOTE_ALL)
        if not output_df.empty:
            print(f"Successfully wrote final dataset with {len(output_df)} flows.")
        else:
            print(f"Wrote an empty dataset (headers only) as no flows were processed or reconstructed: {output_file_path}")
    except Exception as e:
        print(f"Error writing final dataset to CSV {output_file_path}: {e}")

    print("\nAll processing finished.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Correlate host events with PCAP data and label network packets.")
    parser.add_argument("--input_dir", "-i", required=True, help="Path to the directory containing input PCAP and CSV files.")
    parser.add_argument("--output_file", "-o", default="final_correlated_labeled_dataset.csv", help="Path for the final output CSV dataset.")

    args = parser.parse_args()
    main(args.input_dir, args.output_file)
