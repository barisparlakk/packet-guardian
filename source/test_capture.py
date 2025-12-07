from scapy.all import sniff
def packet_callback(packet):
    print(f"Captured packet: {packet.summary()}")

# Try to capture 5 packets. 

try:
    print("Testing packet capture (requires sudo)...")
    sniff(count=5, prn=packet_callback)
    print("Success!!")
except Exception as e:
    print(f"Error: {e}")
    
