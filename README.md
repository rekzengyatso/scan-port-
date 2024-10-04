# scan-port-
import nmap

# Initialize the Nmap PortScanner
nm = nmap.PortScanner()

# Define the target IP address and port range
target_ip = '192.168.1.1'  # Replace with the actual IP address of the Windows 2016 server
port_range = '21-443'

# Run the scan
nm.scan(target_ip, port_range)

# Print the scan results
for host in nm.all_hosts():
    print(f'Host: {host} ({nm[host].hostname()})')
    print(f'State: {nm[host].state()}')
    for proto in nm[host].all_protocols():
        print(f'Protocol: {proto}')
        lport = nm[host][proto].keys()
        for port in sorted(lport):
            print(f'Port: {port}\tState: {nm[host][proto][port]["state"]}')
