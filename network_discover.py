import pandas as pd
from netmiko import ConnectHandler
from getpass import getpass
from graphviz import Digraph
import os
import re

def normalize_hostname(hostname):
    return hostname.split('.')[0] if hostname else ''

def get_vendor_from_platform(platform):
    if platform:
        return platform.split()[0]
    return ''

def get_device_type(capabilities, platform):
    caps = (capabilities or '').lower()
    plat = (platform or '').lower()
    if 'switch' in caps or 'switch' in plat:
        return 'Switch'
    if 'router' in caps or 'router' in plat:
        return 'Router'
    return 'Unknown'

def parse_arp_table(arp_output):
    arp_entries = []
    for line in arp_output.splitlines():
        if line.strip().startswith('Protocol') or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 6:
            arp_entries.append({
                'protocol': parts[0],
                'arp_ip': parts[1],
                'age': parts[2],
                'mac_address': parts[3],
                'type': parts[4],
                'interface': parts[5]
            })
    return arp_entries

def parse_mac_table(mac_output):
    mac_entries = []
    # Typical header: VLAN    MAC Address       Type        Ports
    for line in mac_output.splitlines():
        if line.strip().startswith('VLAN') or not line.strip():
            continue
        parts = re.split(r'\s+', line.strip())
        if len(parts) >= 4:
            mac_entries.append({
                'vlan': parts[0],
                'mac_address': parts[1],
                'type': parts[2],
                'port': parts[3]
            })
    return mac_entries

# --- User Input ---
print("Network Auto-Discovery Tool\n---------------------------")
seed_ip = input("Enter the seed device IP address: ")
username = input("Enter username: ")
password = getpass("Enter password: ")
enable_secret = getpass("Enter enable (privileged exec) password (press Enter if same as login): ")
if not enable_secret:
    enable_secret = password

def prompt_credentials(ip, hostname=None):
    print(f"\nEnter credentials for {hostname or ip} ({ip}):")
    user = input("  Username: ")
    pwd = getpass("  Password: ")
    secret = getpass("  Enable password (press Enter if same as login): ")
    if not secret:
        secret = pwd
    return user, pwd, secret

def discover_network(seed_ip, username, password, enable_secret, known_devices=None, known_links=None, scanned_devices=None, credentials_cache=None, device_arp_mac_rows=None):
    if known_devices is None:
        known_devices = {}
    if known_links is None:
        known_links = []
    if scanned_devices is None:
        scanned_devices = set()
    if credentials_cache is None:
        credentials_cache = {}
    if device_arp_mac_rows is None:
        device_arp_mac_rows = []
    scan_queue = [(seed_ip, username, password, enable_secret)]
    while scan_queue:
        current_ip, user, pwd, secret = scan_queue.pop(0)
        if current_ip in scanned_devices:
            continue
        print(f"\n--- Scanning device: {current_ip} ---")
        device_details = {
            "device_type": "cisco_ios",
            "host": current_ip,
            "username": user,
            "password": pwd,
            "secret": secret,
        }
        try:
            with ConnectHandler(**device_details) as net_connect:
                net_connect.enable()
                version_info = net_connect.send_command("show version", use_textfsm=True)[0]
                hostname = normalize_hostname(version_info.get('hostname', current_ip))
                model = version_info.get('hardware', [''])[0]
                mgmt_ip = current_ip
                scanned_devices.add(mgmt_ip)  # Mark as scanned before processing neighbors
                platform = version_info.get('hardware', [''])[0]
                capabilities = ''
                device_type = 'Unknown'
                vendor = get_vendor_from_platform(platform)
                # Try to get device_type and vendor from CDP neighbor if available
                neighbors = net_connect.send_command("show cdp neighbors detail", use_textfsm=True)
                print("Raw neighbors data:", neighbors)  # Debug print
                if neighbors:
                    for neighbor in neighbors:
                        if neighbor.get('mgmt_address') == mgmt_ip:
                            capabilities = neighbor.get('capabilities', '')
                            platform = neighbor.get('platform', platform)
                            device_type = get_device_type(capabilities, platform)
                            vendor = get_vendor_from_platform(platform)
                            break
                else:
                    device_type = get_device_type('', platform)
                # Add device row
                device_arp_mac_rows.append({
                    'row_type': 'device',
                    'ip': mgmt_ip,
                    'hostname': hostname,
                    'model': model,
                    'username': user,
                    'device_type': device_type,
                    'vendor': vendor,
                    'protocol': '', 'arp_ip': '', 'age': '', 'mac_address': '', 'type': '', 'interface': '',
                    'vlan': '', 'port': ''
                })
                # --- ARP Table ---
                arp_output = net_connect.send_command("show arp")
                arp_entries = parse_arp_table(arp_output)
                for arp in arp_entries:
                    intf = arp['interface']
                    # Initialize all fields
                    intf_status = line_protocol = speed = duplex = intf_description = input_errors = output_errors = ''
                    admin_status = mac_addr = mtu = last_input = last_output = packets_in = packets_out = bytes_in = bytes_out = ''
                    vlan = port_type = native_vlan = allowed_vlans = stp_role = stp_state = stp_root = stp_cost = stp_priority = ''
                    poe_status = poe_power = poe_current = poe_voltage = ''
                    cdp_neighbor = cdp_neighbor_port = cdp_neighbor_platform = cdp_neighbor_ip = cdp_neighbor_desc = ''
                    try:
                        intf_output = net_connect.send_command(f"show interfaces {intf}")
                        # Status and protocol
                        m = re.search(rf"{re.escape(intf)} is (\w+), line protocol is (\w+)", intf_output)
                        if m:
                            intf_status, line_protocol = m.group(1), m.group(2)
                        # Speed and duplex
                        m = re.search(r'(\d+)Mb/s, (\w+)-duplex', intf_output)
                        if m:
                            speed, duplex = m.group(1), m.group(2)
                        # Description
                        m = re.search(r'Description: (.*)', intf_output)
                        if m:
                            intf_description = m.group(1).strip()
                        # MAC address
                        m = re.search(r'address is ([0-9a-fA-F.]+)', intf_output)
                        if m:
                            mac_addr = m.group(1)
                        # MTU
                        m = re.search(r'MTU (\d+) bytes', intf_output)
                        if m:
                            mtu = m.group(1)
                        # Input/output errors
                        m = re.search(r'(\d+) input errors', intf_output)
                        if m:
                            input_errors = m.group(1)
                        m = re.search(r'(\d+) output errors', intf_output)
                        if m:
                            output_errors = m.group(1)
                        # Last input/output
                        m = re.search(r'Last input (.*), output (.*), output hang', intf_output)
                        if m:
                            last_input, last_output = m.group(1).strip(), m.group(2).strip()
                        # Packets/bytes in/out
                        m = re.search(r'(\d+) packets input, (\d+) bytes', intf_output)
                        if m:
                            packets_in, bytes_in = m.group(1), m.group(2)
                        m = re.search(r'(\d+) packets output, (\d+) bytes', intf_output)
                        if m:
                            packets_out, bytes_out = m.group(1), m.group(2)
                        # Admin status
                        if 'administratively down' in intf_output:
                            admin_status = 'down'
                        else:
                            admin_status = 'up'
                    except Exception:
                        pass
                    # Switchport info
                    try:
                        sw_output = net_connect.send_command(f"show interfaces {intf} switchport")
                        m = re.search(r'Administrative Mode: (\w+)', sw_output)
                        if m:
                            port_type = m.group(1)
                        m = re.search(r'Access Mode VLAN: (\d+)', sw_output)
                        if m:
                            vlan = m.group(1)
                        m = re.search(r'Native VLAN: (\d+)', sw_output)
                        if m:
                            native_vlan = m.group(1)
                        m = re.search(r'Trunking Native Mode VLAN: (\d+)', sw_output)
                        if m:
                            native_vlan = m.group(1)
                        m = re.search(r'Trunking VLANs Enabled: ([\d, ]+)', sw_output)
                        if m:
                            allowed_vlans = m.group(1)
                    except Exception:
                        pass
                    # Spanning-tree info
                    try:
                        stp_output = net_connect.send_command(f"show spanning-tree interface {intf} detail")
                        m = re.search(r'Port role: (\w+)', stp_output)
                        if m:
                            stp_role = m.group(1)
                        m = re.search(r'Port state: (\w+)', stp_output)
                        if m:
                            stp_state = m.group(1)
                        m = re.search(r'Port is root: (\w+)', stp_output)
                        if m:
                            stp_root = m.group(1)
                        m = re.search(r'Port path cost (\d+)', stp_output)
                        if m:
                            stp_cost = m.group(1)
                        m = re.search(r'Port priority (\d+)', stp_output)
                        if m:
                            stp_priority = m.group(1)
                    except Exception:
                        pass
                    # PoE info
                    try:
                        poe_output = net_connect.send_command(f"show power inline {intf}")
                        m = re.search(r'([Uu]p|[Dd]own)\s+(\d+\.\d+)\s+(\d+)\s+(\d+)', poe_output)
                        if m:
                            poe_status, poe_power, poe_current, poe_voltage = m.groups()
                    except Exception:
                        pass
                    # CDP neighbor info for this port
                    try:
                        cdp_output = net_connect.send_command(f"show cdp neighbors {intf} detail", use_textfsm=True)
                        if cdp_output and isinstance(cdp_output, list) and len(cdp_output) > 0:
                            cdp = cdp_output[0]
                            cdp_neighbor = cdp.get('neighbor_name', '')
                            cdp_neighbor_port = cdp.get('neighbor_interface', '')
                            cdp_neighbor_platform = cdp.get('platform', '')
                            cdp_neighbor_ip = cdp.get('mgmt_address', '')
                            cdp_neighbor_desc = cdp.get('neighbor_description', '')
                    except Exception:
                        pass
                    device_arp_mac_rows.append({
                        'row_type': 'arp',
                        'source': 'ARP',
                        'ip': '', 'hostname': '', 'model': '', 'username': '', 'device_type': '', 'vendor': '',
                        'protocol': arp['protocol'],
                        'arp_ip': arp['arp_ip'],
                        'age': arp['age'],
                        'mac_address': arp['mac_address'],
                        'type': arp['type'],
                        'interface': arp['interface'],
                        'vlan': vlan, 'port': '',
                        'intf_status': intf_status,
                        'line_protocol': line_protocol,
                        'speed': speed,
                        'duplex': duplex,
                        'intf_description': intf_description,
                        'input_errors': input_errors,
                        'output_errors': output_errors,
                        'admin_status': admin_status,
                        'mac_addr': mac_addr,
                        'mtu': mtu,
                        'last_input': last_input,
                        'last_output': last_output,
                        'packets_in': packets_in,
                        'packets_out': packets_out,
                        'bytes_in': bytes_in,
                        'bytes_out': bytes_out,
                        'port_type': port_type,
                        'native_vlan': native_vlan,
                        'allowed_vlans': allowed_vlans,
                        'stp_role': stp_role,
                        'stp_state': stp_state,
                        'stp_root': stp_root,
                        'stp_cost': stp_cost,
                        'stp_priority': stp_priority,
                        'poe_status': poe_status,
                        'poe_power': poe_power,
                        'poe_current': poe_current,
                        'poe_voltage': poe_voltage,
                        'cdp_neighbor': cdp_neighbor,
                        'cdp_neighbor_port': cdp_neighbor_port,
                        'cdp_neighbor_platform': cdp_neighbor_platform,
                        'cdp_neighbor_ip': cdp_neighbor_ip,
                        'cdp_neighbor_desc': cdp_neighbor_desc
                    })
                # --- MAC Address Table (for switches) ---
                if device_type == 'Switch':
                    mac_output = net_connect.send_command("show mac address-table")
                    mac_entries = parse_mac_table(mac_output)
                    for mac in mac_entries:
                        device_arp_mac_rows.append({
                            'row_type': 'mac',
                            'ip': '', 'hostname': '', 'model': '', 'username': '', 'device_type': '', 'vendor': '',
                            'protocol': '', 'arp_ip': '', 'age': '',
                            'mac_address': mac['mac_address'],
                            'type': mac['type'],
                            'interface': '',
                            'vlan': mac['vlan'],
                            'port': mac['port']
                        })
                # --- CDP Neighbors and Links ---
                for neighbor in neighbors:
                    neighbor_ip = neighbor.get('mgmt_address')
                    neighbor_name = normalize_hostname(neighbor.get('neighbor_name', neighbor_ip))
                    neighbor_model = neighbor.get('platform', '')
                    neighbor_caps = neighbor.get('capabilities', '')
                    neighbor_type = get_device_type(neighbor_caps, neighbor_model)
                    neighbor_vendor = get_vendor_from_platform(neighbor_model)
                    # Add neighbor to known_devices if not already present
                    if neighbor_ip and neighbor_ip not in known_devices:
                        known_devices[neighbor_ip] = {'ip': neighbor_ip, 'hostname': neighbor_name, 'model': neighbor_model, 'username': None, 'device_type': neighbor_type, 'vendor': neighbor_vendor}
                    # Add link info
                    link_info = {
                        'source_host': hostname,
                        'source_ip': mgmt_ip,
                        'source_port': neighbor.get('local_interface', ''),
                        'target_host': neighbor_name,
                        'target_ip': neighbor_ip,
                        'target_port': neighbor.get('neighbor_interface', '')
                    }
                    known_links.append(link_info)
                    # If neighbor not scanned, prompt for credentials and add to queue
                    if neighbor_ip and neighbor_ip not in scanned_devices and all(neighbor_ip != queued[0] for queued in scan_queue):
                        print(f"  -> Discovered new neighbor: {neighbor_name} at {neighbor_ip}")
                        if neighbor_ip in credentials_cache:
                            n_user, n_pwd, n_secret = credentials_cache[neighbor_ip]
                        else:
                            n_user, n_pwd, n_secret = prompt_credentials(neighbor_ip, neighbor_name)
                            credentials_cache[neighbor_ip] = (n_user, n_pwd, n_secret)
                        scan_queue.append((neighbor_ip, n_user, n_pwd, n_secret))
        except Exception as e:
            print(f"Could not connect to or process {current_ip}. Error: {e}")
            scanned_devices.add(current_ip)
    return known_devices, known_links, device_arp_mac_rows

# --- Run Discovery ---
devices_dict, links_list, device_arp_mac_rows = discover_network(seed_ip, username, password, enable_secret)

print("\n--- DISCOVERY COMPLETE ---")
df_devices = pd.DataFrame(device_arp_mac_rows)
df_links = pd.DataFrame(links_list)

print("\n--- Discovered Devices, ARP, and MAC Table Entries ---")
print(df_devices)
print("\n--- Discovered Network Links ---")
print(df_links)

# --- Save to Excel ---
with pd.ExcelWriter('network_inventory.xlsx') as writer:
    df_devices.to_excel(writer, sheet_name='Devices', index=False)
    df_links.to_excel(writer, sheet_name='Links', index=False)
print("\nInventory saved to network_inventory.xlsx")

# --- Generate Network Map ---
def generate_network_map(df_links):
    dot = Digraph(comment='Network Map', strict=True)
    dot.attr('node', shape='box', style='rounded')
    dot.attr(label='Network Diagram', fontsize='20')
    dot.attr(rankdir='TB')
    all_hosts = set(df_links['source_host']).union(set(df_links['target_host']))
    for host in all_hosts:
        dot.node(str(host))
    for _, row in df_links.iterrows():
        dot.edge(str(row['source_host']), str(row['target_host']), 
                 label=f"{row['source_port']} -> {row['target_port']}")
    output_filename = 'network_map'
    dot.render(output_filename, format='png', view=False)
    print(f"Network map saved as {output_filename}.png")

if not df_links.empty:
    generate_network_map(df_links)
else:
    print("No links found, skipping network map generation.") 