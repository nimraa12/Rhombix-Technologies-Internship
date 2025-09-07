from scapy.all import sniff

def show_packet(packet):
    print(packet.summary())

print("Sniffing started... Press CTRL+C to stop.")
sniff(prn=show_packet, count=20)
print("Sniffing finished.")
