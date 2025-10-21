import os
import time
import subprocess
import re
import base64
import json
import socket
import ipaddress
import requests
from urllib.parse import urlparse, parse_qs, quote, unquote
import dns.resolver
import dns.exception

# --- Configuration & Colors ---
class Colors:
    """Class to hold ANSI color codes."""
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    END = "\033[0m" 
    
# --- Output Directory Configuration ---
# Uses a relative path (will create 'MAHAZONA CHECKER_Results' folder where the script is run)
OUTPUT_DIR = "MAHAZONA CHECKER_Results" 

# Define file paths using the new output directory
WORKING_HOSTS_FILE = os.path.join(OUTPUT_DIR, "working_hosts.txt")
CIDR_RESULTS_FILE = os.path.join(OUTPUT_DIR, "cidr_scan_results.txt")

TELE2_SPEED_TEST_URL = "/10MB.zip" # Curl target for speed simulation

# --- Core Helper Functions ---
def clear_screen():
    """Clears the terminal screen (works for Linux/Mac 'clear' and Windows 'cls')."""
    os.system('cls' if os.name == 'nt' else 'clear')

def ensure_output_directory():
    """Checks if the output directory exists and creates it if not."""
    try:
        if not os.path.exists(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR)
            print(f"{Colors.GREEN}Created output directory: {OUTPUT_DIR}{Colors.END}")
    except OSError as e:
        print(f"{Colors.RED}ERROR: Failed to create output directory {OUTPUT_DIR}. Results may not save correctly. ({e}){Colors.END}")

def display_header(title="MAHAZONA HOST CHECKER (V1.0 - Generic)"):
    """
    Displays the stylized header. 
    Version set to V1.0 as requested. 
    (This function definition fixes the NameError: name 'display_header' is not defined)
    """
    clear_screen()
    print(f"{Colors.YELLOW}============================================================{Colors.END}") 
    print(f"               {Colors.RED}M{Colors.CYAN}AHAZONA HOST CHECKER (V1.0){Colors.END}") # V1.0 as requested
    print(f"{Colors.YELLOW}============================================================{Colors.END}") 
    print(f"{' ' * 10}{Colors.WHITE}A TOOL BY = @Virus_tw {Colors.END}")
    print(f"{Colors.CYAN}-" * 60 + Colors.END)

def resolve_ip(hostname):
    """
    Resolves a hostname to an IP address using external DNS servers (8.8.8.8, 1.1.1.1).
    This logic bypasses the Termux '/etc/resolv.conf' network issue.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1'] # Use external DNS servers
        answers = resolver.resolve(hostname, 'A', search=True)
        return answers[0].address, None
    except dns.exception.Timeout:
        return None, "DNS resolution timed out."
    except dns.resolver.NXDOMAIN:
        return None, f"Could not resolve IP for {hostname}. DNS error (NXDOMAIN)."
    except Exception as e:
        # If the underlying network is broken, the separate fix steps (rm /etc/resolv.conf + ln -s) are still required, 
        # but this logic prevents the Python script from relying on Termux's potentially broken default DNS file.
        return None, f"Error resolving IP: {e}. Check DNS configuration."

def parse_config_url(config_url, port_override, security_override, network_override):
    """Parses VLESS and VMESS config URLs, applying method overrides."""
    try:
        # --- VMESS Parsing ---
        if config_url.lower().startswith('vmess://'):
            base64_data = config_url[len('vmess://'):]
            try:
                decoded_json = base64.b64decode(base64_data).decode('utf-8')
            except Exception:
                missing_padding = len(base64_data) % 4
                if missing_padding:
                    base64_data += '=' * (4 - missing_padding)
                decoded_json = base64.b64decode(base64_data).decode('utf-8')

            vmess_config = json.loads(decoded_json)
            host = vmess_config.get('add')
            user_id = vmess_config.get('id')
            
            port = str(port_override)
            security = security_override
            network = network_override
            
            original_sni = vmess_config.get('sni', '')
            reverse_host_header = vmess_config.get('host', '') 
            alias = vmess_config.get('ps', f"{host}:{port}")

            return {
                'protocol': 'vmess', 'user_id': user_id, 'host': host, 'port': port,
                'security': security, 'network': network, 'original_sni': original_sni, 
                'reverse_host_header': reverse_host_header, 'alias': alias,
                'original_config_dict': vmess_config
            }, None

        # --- VLESS Parsing ---
        parsed_url = urlparse(config_url)
        if parsed_url.scheme != 'vless':
            return None, "Invalid protocol. Must be 'vless://' or 'vmess://'."

        user_id = parsed_url.username 
        netloc_parts_split_at_user = parsed_url.netloc.split('@', 1)
        host_and_port_str = netloc_parts_split_at_user[1] if len(netloc_parts_split_at_user) > 1 else netloc_parts_split_at_user[0]
        host, _ = (host_and_port_str.split(':') if ':' in host_and_port_str else (host_and_port_str, '443'))

        query_params = parse_qs(parsed_url.query)
        reverse_host_header = query_params.get('host', [''])[0] 

        port = str(port_override)
        security = security_override
        network = network_override
        original_sni = query_params.get('sni', [''])[0]

        return {
            'protocol': 'vless', 'user_id': user_id, 'host': host, 'port': port,
            'security': security, 'network': network, 'original_sni': original_sni,
            'reverse_host_header': reverse_host_header,
            'query_params': query_params
        }, None
    except json.JSONDecodeError:
        return None, "Invalid VMESS link: JSON decoding failed."
    except Exception as e:
        return None, f"Error parsing config: {e}. Ensure it's a valid VLESS/VMESS URL."

def test_speed_simulated_http(target_host_or_ip, port, actual_host_header=None, security_protocol='none', timeout=15):
    """Simulates a download speed using curl."""
    
    protocol = "https" if security_protocol.lower() == 'tls' or str(port) in ('443', '2096', '8443') else "http"
    url_to_connect = f"{protocol}://{target_host_or_ip}:{port}{TELE2_SPEED_TEST_URL}"
    
    host_header_option = ['-H', f'Host: {actual_host_header}'] if actual_host_header else []
    
    try:
        # Get IP using the DNS-fixed resolve_ip function
        ip_addr = resolve_ip(target_host_or_ip)[0] 
        if not ip_addr:
             return None, "Could not resolve IP for curl."

        command = [
            'curl', '-s', '-L', '-o', '/dev/null', 
            # Use --resolve to force curl to use the IP address we just resolved, bypassing system DNS issues
            '--resolve', f'{target_host_or_ip}:{port}:{ip_addr}', 
            '-w', '%{speed_download}',
            '--connect-timeout', str(timeout),
            '--max-time', str(timeout + 5), 
        ]
        command.extend(host_header_option)
        
        if protocol == 'https':
             command.append('-k') # -k for insecure connection (to ignore self-signed certs)
             
        command.append(url_to_connect)

        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 10, check=False) 
        download_speed_bps = process.stdout.strip()
        
        if download_speed_bps:
            try:
                speed = float(download_speed_bps)
                if speed > 0:
                    return speed, None
                else:
                    return 0, "VLESS/VMESS Protocol Active" # VLESS/VMESS often intercepts traffic, resulting in 0 speed or a curl failure
            except ValueError:
                return None, f"Curl Error: {process.stderr.strip()}"
                
        return None, "Curl output empty/failed."
    except Exception as e:
        return None, f"Error during simulated speed test: {e}"

def run_tcp_test(host_or_ip, port, timeout=5):
    """Checks if a TCP port is open."""
    try:
        ip_addr = host_or_ip
        if not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$|^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$", host_or_ip):
            # Resolve if it's a domain name, using the DNS-fixed resolve_ip function
            ip_addr, resolve_error = resolve_ip(host_or_ip)
            if resolve_error or not ip_addr:
                return False, f"TCP resolution error: {resolve_error}"
                
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start_time = time.time()
        s.connect((ip_addr, int(port)))
        end_time = time.time()
        s.close()
        latency_ms = (end_time - start_time) * 1000
        return True, f"Port {port} open ({latency_ms:.2f} ms connect time)"
    except socket.timeout:
        return False, f"Port {port} connection timed out after {timeout}s."
    except socket.error as e:
        return False, f"Port {port} refused connection or is unreachable ({e})."
    except Exception as e:
        return False, f"Error during TCP test: {e}"

def format_speed(bits_per_second):
    """Formats speed from bps into human-readable units (Mbps/Kbps)."""
    if bits_per_second is None or bits_per_second <= 0:
        return "N/A"
    bits_per_second = float(bits_per_second)
    if bits_per_second >= 1_000_000_000:
        return f"{bits_per_second / 1_000_000_000:.2f} Gbps"
    elif bits_per_second >= 1_000_000:
        return f"{bits_per_second / 1_000_000:.2f} Mbps"
    elif bits_per_second >= 1_000:
        return f"{bits_per_second / 1_000:.2f} Kbps"
    else:
        return f"{bits_per_second:.2f} bps"

def generate_new_config_url(base_config_data, new_sni, target_host_from_config, new_port, new_security, new_network, new_host_header=None):
    """Generates a new config URL based on modified parameters."""
    protocol = base_config_data['protocol']
    
    if protocol == 'vmess':
        vmess_dict = base_config_data.get('original_config_dict', {}).copy()
        vmess_dict['add'] = target_host_from_config
        vmess_dict['port'] = int(new_port)
        vmess_dict['net'] = new_network 
            
        final_sni = new_sni if new_security == 'tls' else ''
        vmess_dict['sni'] = final_sni if final_sni else ""
        
        if new_security == 'tls':
            vmess_dict['tls'] = 'tls'
        elif 'tls' in vmess_dict:
            del vmess_dict['tls']
        
        final_host_header = new_host_header if new_host_header else base_config_data.get('reverse_host_header', '')
        if final_host_header:
            vmess_dict['host'] = final_host_header
        elif 'host' in vmess_dict:
            del vmess_dict['host']

        alias_security = 'TLS' if new_security == 'tls' else 'NoTLS'
        alias_host = f"Host={final_host_header.replace('.', '_')}" if final_host_header else ''
        alias_sni = f"SNI={final_sni.replace('.', '_')}" if final_sni else ''
        new_alias = f"Mode={new_network.upper()}_{new_port}_{alias_security}_{alias_sni}_{alias_host}"
        vmess_dict['ps'] = new_alias

        json_str = json.dumps(vmess_dict, ensure_ascii=False)
        encoded_data = base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
        return f"vmess://{encoded_data}"
    
    elif protocol == 'vless':
        scheme = base_config_data['protocol']
        user_id = base_config_data['user_id']
        current_host = target_host_from_config 
        port = new_port
        full_host_port = f"{current_host}:{port}"

        query_parts = []
        
        for param, values in base_config_data['query_params'].items():
            if param.lower() in ('sni', 'host', 'security', 'type', 'network'): continue
            if isinstance(values, list):
                for value in values:
                    query_parts.append(f"{param}={quote(value, safe='')}")
            else:
                query_parts.append(f"{param}={quote(values, safe='')}")

        query_parts.append(f"security={new_security}")
        query_parts.append(f"type={new_network}")
        
        final_sni = new_sni if new_security == 'tls' else ''
        if final_sni:
            query_parts.append(f"sni={quote(final_sni, safe='')}")
        
        final_host_header = new_host_header if new_host_header else base_config_data.get('reverse_host_header', '')
        if final_host_header:
            query_parts.append(f"host={quote(final_host_header, safe='')}")
            
        query_string = "&".join(query_parts)
        
        alias_security = 'TLS' if new_security == 'tls' else 'NoTLS'
        alias_host = f"Host={final_host_header.replace('.', '_')}" if final_host_header else ''
        alias_sni = f"SNI={final_sni.replace('.', '_')}" if final_sni else ''
        new_alias = f"Mode={new_network.upper()}_{new_port}_{alias_security}_{alias_sni}_{alias_host}"
        fragment_string = quote(new_alias, safe='')

        query_segment = f"?{query_string}" if query_string else ""
        fragment_segment = f"#{fragment_string}"

        new_config_url = f"{scheme}://{user_id}@{full_host_port}{query_segment}{fragment_segment}"
        return new_config_url
        
    return None

def save_working_host(entry_type, connect_target, header_tested, tcp_status, speed_bps, config_url=None):
    """Saves a working host/SNI/IP to the working_hosts.txt file."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    speed_formatted = format_speed(speed_bps)

    ensure_output_directory() 
    try:
        with open(WORKING_HOSTS_FILE, "a") as f:
            f.write(f"[{timestamp}] Type: {entry_type}\n")
            f.write(f"  Connect Target (URL Host): {connect_target}\n")
            f.write(f"  Header Tested: {header_tested}\n")
            f.write(f"  TCP Status: {tcp_status}\n")
            f.write(f"  Simulated Speed: {speed_formatted}\n")
            if config_url:
                f.write(f"  Config URL: {config_url}\n")
            f.write("-" * 30 + "\n")
        print(f"  {Colors.GREEN} [✓] Saved to {WORKING_HOSTS_FILE}{Colors.END}")
    except IOError as e:
        print(f"{Colors.RED} [X] Error saving to file (Check permissions for {OUTPUT_DIR}): {e}{Colors.END}")

def perform_test_run(config_data, connect_target, header_to_test, test_name, port, security, network, host_header_for_config):
    """Performs the TCP/Speed test for one specific header."""
    
    curl_host_header = header_to_test 
    
    print(f"  {Colors.YELLOW}  Header for CURL Test:{Colors.END} {curl_host_header}")
    
    # 1. TCP Connect Test
    tcp_ok, tcp_result = run_tcp_test(connect_target, port)

    if not tcp_ok:
        print(f"  {Colors.RED}  TCP Connect:{Colors.END} {tcp_result}")
        return

    print(f"  {Colors.GREEN}  TCP Connect:{Colors.END} {tcp_result}")
    
    # 2. Simulated Speed Test
    print(f"  {Colors.MAGENTA}  Simulating Speed Test (Expecting 'VLESS/VMESS Protocol Active' for success)...{Colors.END}")
    simulated_speed, speed_error = test_speed_simulated_http(
        target_host_or_ip=connect_target, 
        port=port,
        actual_host_header=curl_host_header, 
        security_protocol=security
    )
    
    # 3. Config Generation & Save (SAVE IF TCP WAS OK)
    
    if "SNI Test" in test_name:
        final_config_sni = header_to_test if security == 'tls' else ''
        final_config_host = config_data.get('reverse_host_header', '') 
        header_to_log = f"SNI={header_to_test}"
    else: 
        final_config_sni = config_data.get('original_sni', '') if security == 'tls' else ''
        final_config_host = host_header_for_config
        header_to_log = f"Reverse Host={host_header_for_config}"
        
    new_config_url = generate_new_config_url(
        base_config_data=config_data,
        new_sni=final_config_sni,
        target_host_from_config=connect_target,
        new_port=port,
        new_security=security,
        new_network=network,
        new_host_header=final_config_host
    )

    if simulated_speed is not None and simulated_speed >= 0:
        speed_display = format_speed(simulated_speed) 
        print(f"  {Colors.YELLOW}  Simulated Speed:{Colors.END} {speed_display} ({speed_error})")
        
        print(f"  {Colors.GREEN}  Conclusion: TCP success indicates this is a LIKELY WORKING HOST.{Colors.END}")

        save_working_host( 
            entry_type=f"{test_name} (TCP OK)", 
            connect_target=connect_target,
            header_tested=header_to_log,
            tcp_status="Open", 
            speed_bps=simulated_speed, 
            config_url=new_config_url
        )
    else:
        print(f"  {Colors.RED}  Simulated Speed:{Colors.END} N/A (Failed: {speed_error})")


def scan_host_with_methods(base_config_data, custom_headers, test_settings):
    """Iterates through custom headers and runs the specific test method for SNI and Reverse Host Header."""
    connect_target = base_config_data['host']
    port, security, network = test_settings['port'], test_settings['security'], test_settings['network']
    
    print(f"\n{Colors.MAGENTA}--- Running Test: {test_settings['name']} ---{Colors.END}")
    print(f"  {Colors.CYAN}Target:{Colors.END} {connect_target}:{port} | {network.upper()} over {security.upper()}")
    
    if security == 'tls':
        total_tests = len(custom_headers) * 2 
    else:
        total_tests = len(custom_headers) 

    test_counter = 0

    for custom_header in custom_headers:
        
        connection_header_for_reverse_test = base_config_data.get('original_sni', base_config_data['host'])
        
        # 1. Test using the custom header as **SNI** (For TLS modes)
        if security == 'tls':
            test_counter += 1
            test_name = f"SNI Test ({test_settings['name']})"
            print(f"\n{Colors.BLUE}[Test {test_counter}/{total_tests}] Method: SNI Mode | SNI Header: {custom_header}{Colors.END}")
            
            perform_test_run(
                config_data=base_config_data,
                connect_target=connect_target,
                header_to_test=custom_header, 
                test_name=test_name,
                port=port,
                security=security,
                network=network,
                host_header_for_config='' 
            )
            
        # 2. Test using the custom header as **Reverse Host Header** (For all modes)
        test_counter += 1
        
        test_name = f"Reverse Host Test ({test_settings['name']})"
        print(f"\n{Colors.BLUE}[Test {test_counter}/{total_tests}] Method: Reverse Host Mode | Host Header: {custom_header}{Colors.END}")
        
        perform_test_run(
            config_data=base_config_data,
            connect_target=connect_target,
            header_to_test=connection_header_for_reverse_test,
            test_name=test_name,
            port=port,
            security=security,
            network=network,
            host_header_for_config=custom_header 
        )

def get_test_selection():
    """Displays the VLESS/VMESS test selection menu and returns the chosen settings."""
    while True:
        display_header("Select VLESS/VMESS Test Method")
        print(f"{Colors.YELLOW}Choose a test method (Enter the number):{Colors.END}")
        
        methods = {
            1: {"name": "Port 80 - WebSocket (No TLS)", "port": "80", "security": "none", "network": "ws"},
            2: {"name": "Port 8080 - WebSocket (No TLS)", "port": "8080", "security": "none", "network": "ws"},
            3: {"name": "Port 443 - TCP (TLS)", "port": "443", "security": "tls", "network": "tcp"},
            4: {"name": "Port 443 - WebSocket (TLS)", "port": "443", "security": "tls", "network": "ws"},
            5: {"name": "Port 2096 - WebSocket (TLS)", "port": "2096", "security": "tls", "network": "ws"},
            6: {"name": "Port 8443 - WebSocket (TLS)", "port": "8443", "security": "tls", "network": "ws"},
        }
        
        for num, setting in methods.items():
            print(f"{Colors.GREEN}[{num}]{Colors.END} {setting['name']}")

        print(f"{Colors.RED}[0]{Colors.END} Back to Main Menu")

        choice = input(f"{Colors.GREEN}>> {Colors.END}").strip()
        
        if choice == '0':
            return None
        
        try:
            choice_num = int(choice)
            if choice_num in methods:
                return methods[choice_num]
            else:
                print(f"{Colors.RED}Invalid choice. Please enter a number from the list.{Colors.END}")
                time.sleep(1.5)
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.END}")
            time.sleep(1.5)

def get_custom_headers():
    """Prompts the user for a list of custom headers (SNI/Host Header)."""
    all_headers = []

    print(f"{Colors.CYAN}-" * 60 + Colors.END)
    print(f"{Colors.YELLOW}Do you want to load Headers from a file (one per line)? (yes/no) [no]:{Colors.END}")
    load_file = input(f"{Colors.GREEN}>> {Colors.END}").strip().lower()

    if load_file in ('yes', 'y'):
        print(f"{Colors.CYAN}Enter the path to your Header file (e.g., host_list.txt):{Colors.END}")
        file_path = input(f"{Colors.GREEN}>> {Colors.END}").strip()
        
        try:
            print(f"NOTE: For Termux, the path must be accessible (e.g., /sdcard/Download/your_file.txt)")
            with open(file_path, 'r') as f:
                file_hosts = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
            all_headers.extend(file_hosts)
            print(f"{Colors.GREEN}Loaded {len(file_hosts)} headers from file.{Colors.END}")
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File '{file_path}' not found. Skipping file load.{Colors.END}") # Handles the 'Google.txt' not found error
        except Exception as e:
            print(f"{Colors.RED}Error reading file: {e}. Skipping file load.{Colors.END}")

    print(f"{Colors.CYAN}-" * 60 + Colors.END)
    print(f"{Colors.CYAN}Enter any additional custom SNI/Host Headers (one by one). Type 'done' when finished:{Colors.END}")
    while True:
        header_input = input(f"{Colors.GREEN}SNI/Host (or 'done'):{Colors.END} ").strip()
        if header_input.lower() == 'done':
            break
        if header_input and header_input not in all_headers:
            all_headers.append(header_input)
    
    if not all_headers:
        print(f"{Colors.RED}\nNo headers were provided. Skipping header tests.{Colors.END}")
        return None
        
    return all_headers

def original_vless_vmess_main():
    """Main logic for the VLESS/VMESS Host Checker mode."""
    test_settings = get_test_selection()
    if not test_settings:
        return

    display_header(f"Config for {test_settings['name']}")
    print(f"{Colors.CYAN}Enter the VLESS or VMESS config URL for this method ({test_settings['name']}):{Colors.END}")
    original_config_url = input(f"{Colors.GREEN}>> {Colors.END}").strip()

    config_data, error = parse_config_url(
        original_config_url, 
        test_settings['port'], 
        test_settings['security'], 
        test_settings['network']
    )

    if error:
        print(f"{Colors.RED}Error: {error}{Colors.END}")
        input(f"{Colors.YELLOW}Press Enter to return to main menu...{Colors.END}")
        return

    custom_headers = get_custom_headers()
    if not custom_headers:
        return
    
    display_header()
    print(f"{Colors.GREEN}Configuration Summary:{Colors.END}")
    print(f"  {Colors.CYAN}Protocol:{Colors.END} {config_data['protocol'].upper()}")
    print(f"  {Colors.CYAN}Connect Host:{Colors.END} {config_data['host']} (Target IP/Domain)") 
    print(f"  {Colors.CYAN}Test Mode:{Colors.END} {test_settings['name']}")
    print(f"  {Colors.CYAN}Headers to test:{Colors.END} {len(custom_headers)}")
    print(f"{Colors.CYAN}-" * 60 + Colors.END)

    print(f"{Colors.YELLOW}NOTE: TCP success is the TRUE indicator. Speed of 0 (or N/A) is expected for VLESS/VMESS.{Colors.END}")
    scan_host_with_methods(config_data, custom_headers, test_settings)

    print(f"{Colors.CYAN}-" * 60 + Colors.END)
    print(f"{Colors.GREEN}All VLESS/VMESS tests complete! Results saved to {WORKING_HOSTS_FILE}!{Colors.END}")
    input(f"{Colors.MAGENTA}Press Enter to return to main menu...{Colors.END}")


# --- CIDR Scan Mode ---

def mode_cidr_range_scan():
    """Mode to scan all IPs in a CIDR range for an open port."""
    display_header("CIDR Range Scan Mode")
    print(f"{Colors.CYAN}Enter the CIDR range (e.g., 192.168.1.0/24):{Colors.END}")
    cidr_range = input(f"{Colors.GREEN}>> {Colors.END}").strip()
    
    print(f"{Colors.CYAN}Enter the port to scan (e.g., 443):{Colors.END}")
    port_to_scan = input(f"{Colors.GREEN}>> {Colors.END}").strip()

    try:
        network = ipaddress.ip_network(cidr_range, strict=False)
        port = int(port_to_scan)
    except ValueError as e:
        print(f"{Colors.RED}Invalid input: {e}{Colors.END}")
        time.sleep(2)
        return

    print(f"\n{Colors.YELLOW}Starting scan of {network.num_addresses} IPs in {cidr_range} on port {port}...{Colors.END}")
    print(f"Results will be saved to {CIDR_RESULTS_FILE}")
    
    start_time = time.time()
    open_ips = 0

    ensure_output_directory() 
    try:
        with open(CIDR_RESULTS_FILE, "w") as f:
            f.write(f"CIDR Scan Results for {cidr_range}:{port}\n" + "-"*40 + "\n")
            
            ip_list = list(network.hosts()) 
            total_ips = len(ip_list)

            for i, ip in enumerate(ip_list):
                ip_str = str(ip)
                
                tcp_ok, tcp_result = run_tcp_test(ip_str, port)

                if tcp_ok:
                    open_ips += 1
                    status = f"{Colors.GREEN}OPEN{Colors.END}"
                    log_line = f"[OPEN] {ip_str}:{port} | {tcp_result}\n"
                    f.write(log_line.replace(Colors.GREEN, "").replace(Colors.END, "")) 
                else:
                    status = f"{Colors.RED}CLOSED{Colors.END}"
                
                # Print progress to the console
                print(f"[{i+1}/{total_ips}] {ip_str} -> {status}", end='\r')
                
        end_time = time.time()
        print("\n" + "="*60)
        print(f"{Colors.GREEN}Scan Finished!{Colors.END}")
        print(f"Total IPs checked: {total_ips}")
        print(f"Time taken: {end_time - start_time:.2f} seconds")
        print(f"Open IPs found: {open_ips}")
        input(f"{Colors.MAGENTA}Press Enter to return to main menu...{Colors.END}")

    except Exception as e:
        print(f"{Colors.RED}\nAn error occurred during scan: {e}{Colors.END}")
        input(f"{Colors.MAGENTA}Press Enter to return to main menu...{Colors.END}")


# --- Main Logic ---

def main_menu_selection():
    """Displays the main menu and returns the selected mode."""
    while True:
        display_header("Select Operating Mode")
        print(f"{Colors.YELLOW}Choose a mode (Enter the number):{Colors.END}")
        
        modes = {
            1: {"name": "VLESS/VMESS Host Check (TCP/SNI/Host Header Test)"},
            2: {"name": "CIDR Range Scan (IP Port Check)"},
        }
        
        for num, mode in modes.items():
            print(f"{Colors.GREEN}[{num}]{Colors.END} {mode['name']}")

        print(f"{Colors.RED}[0]{Colors.END} Exit")

        choice = input(f"{Colors.GREEN}>> {Colors.END}").strip()
        
        if choice == '0':
            return 0
        
        try:
            choice_num = int(choice)
            if choice_num in modes:
                return choice_num
            else:
                print(f"{Colors.RED}Invalid choice. Please enter a number from the list.{Colors.END}")
                time.sleep(1.5)
        except ValueError:
            print(f"{Colors.RED}Invalid input. Please enter a number.{Colors.END}")
            time.sleep(1.5)

def main():
    ensure_output_directory() 

    while True:
        mode_choice = main_menu_selection()
        
        if mode_choice == 0:
            print(f"{Colors.YELLOW}Exiting tool.{Colors.END}")
            break
        elif mode_choice == 1:
            original_vless_vmess_main()
        elif mode_choice == 2:
            mode_cidr_range_scan()
            
if __name__ == "__main__":
    try:
        # Prevents request library from printing warnings about insecure requests
        if 'requests' in locals() or 'requests' in globals():
            requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass 
        
    main()
