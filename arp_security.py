import scapy.all as scapy

def mac(ipadd):
    """
    Returns the MAC address of `ip`, if it is unable to find it
    for some reason, throws `IndexError`
    """
    arp_request = scapy.ARP(pdst=ipadd)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = scapy.srp(arp_req_br, timeout=5, verbose=False)[0]
    return list_1[0][1].hwsrc

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    # if the packet is an ARP packet & if it is an ARP reply
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            # get the real MAC address of the sender
            originalmac = mac(packet[scapy.ARP].psrc)
            # get the MAC address from the packet sent to us
            responsemac = packet[scapy.ARP].hwsrc
            # if they're different, definitely there is an attack
            if originalmac != responsemac:
                print("[*] ALERT!! You are under attack, the ARP table is being poisoned.!")
        except IndexError:
            # unable to find the real mac
            pass

sniff("eth0")