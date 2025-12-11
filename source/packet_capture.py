"""

Packet Capture Module
Captures network packets and extracts basic information

"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime
import csv
import os


class PacketCapture:
    def __init__(self, interface="en0", output_file="captured_packets.csv"):
        """
        Initialize packet capture module
        
        Args:
            interface: Network interface to capture from (default: en0)
            output_file: CSV file to store captured packets
        """
        self.interface = interface
        self.output_file = output_file
        self.packets_data = []
        self.packet_count = 0

        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        os.makedirs(data_dir, exist_ok=True)
        self.data_dir = data_dir
        
        
        
    def parse_packet(self, packet):
        """
        Parse packet and extract relevant information
        
        Args:
            packet: Scapy packet object
            
        Returns:
            dict: Packet information
        """
        packet_info = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'protocol': 'Unknown',
            'src_ip': None,
            'dst_ip': None,
            'src_port': None,
            'dst_port': None,
            'packet_size': len(packet),
            'flags': None,
            'ttl': None,
            'payload_size': 0
        }
        
        # Extract IP layer information
        if IP in packet:
            packet_info['src_ip'] = packet[IP].src
            packet_info['dst_ip'] = packet[IP].dst
            packet_info['ttl'] = packet[IP].ttl
            
            # Determine protocol
            if TCP in packet:
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = packet[TCP].sport
                packet_info['dst_port'] = packet[TCP].dport
                packet_info['flags'] = str(packet[TCP].flags)
                
            elif UDP in packet:
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = packet[UDP].sport
                packet_info['dst_port'] = packet[UDP].dport
                
            elif ICMP in packet:
                packet_info['protocol'] = 'ICMP'
                packet_info['src_port'] = packet[ICMP].type
                packet_info['dst_port'] = packet[ICMP].code
        
        # Calculate payload size
        if Raw in packet:
            packet_info['payload_size'] = len(packet[Raw].load)
            
        return packet_info
    
    def packet_callback(self, packet):
        """
        Callback function for each captured packet
        
        Args:
            packet: Scapy packet object
        """
        self.packet_count += 1
        packet_info = self.parse_packet(packet)
        self.packets_data.append(packet_info)
        
        # Print packet summary
        print(f"[{self.packet_count}] {packet_info['timestamp']} | "
              f"{packet_info['protocol']:8} | "
              f"{packet_info['src_ip']:15} -> {packet_info['dst_ip']:15} | "
              f"Size: {packet_info['packet_size']:5} bytes")
    
    def start_capture(self, count=100, timeout=60, filter_exp=None):
        """
        Start capturing packets
        
        Args:
            count: Number of packets to capture (0 = infinite)
            timeout: Timeout in seconds
            filter_exp: BPF filter expression (e.g., "tcp port 80")
        """
        print(f"\n{'='*80}")
        print(f"Starting packet capture on interface: {self.interface}")
        print(f"Capturing {count if count > 0 else 'unlimited'} packets...")
        if filter_exp:
            print(f"Filter: {filter_exp}")
        print(f"{'='*80}\n")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.packet_callback,
                count=count,
                timeout=timeout,
                filter=filter_exp,
                store=False
            )
        except KeyboardInterrupt:
            print("\n\nCapture stopped by user (Ctrl+C)")
        except Exception as e:
            print(f"\nError during capture: {e}")
        finally:
            self.save_to_csv()
    
    def save_to_csv(self):
        """
        Save captured packets to CSV file
        """
        if not self.packets_data:
            print("\nNo packets captured.")
            return
        
        filepath = os.path.join(self.data_dir, self.output_file)
        
        try:
            with open(filepath, 'w', newline='') as csvfile:
                fieldnames = self.packets_data[0].keys()
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                writer.writerows(self.packets_data)
            
            print(f"\n{'='*80}")
            print(f"✓ Captured {self.packet_count} packets")
            print(f"✓ Data saved to: {filepath}")
            print(f"{'='*80}\n")
        except Exception as e:
            print(f"\nError saving to CSV: {e}")
    
    def get_statistics(self):
        """
        Get basic statistics about captured packets
        
        Returns:
            dict: Statistics
        """
        if not self.packets_data:
            return {}
        
        protocols = {}
        total_size = 0
        
        for packet in self.packets_data:
            protocol = packet['protocol']
            protocols[protocol] = protocols.get(protocol, 0) + 1
            total_size += packet['packet_size']
        
        return {
            'total_packets': self.packet_count,
            'protocol_distribution': protocols,
            'total_bytes': total_size,
            'average_packet_size': total_size / self.packet_count if self.packet_count > 0 else 0
        }
    
    def print_statistics(self):
        """
        Print capture statistics
        """
        stats = self.get_statistics()
        
        if not stats:
            print("No statistics available.")
            return
        
        print(f"\n{'='*80}")
        print("CAPTURE STATISTICS")
        print(f"{'='*80}")
        print(f"Total Packets: {stats['total_packets']}")
        print(f"Total Bytes: {stats['total_bytes']:,} bytes")
        print(f"Average Packet Size: {stats['average_packet_size']:.2f} bytes")
        print(f"\nProtocol Distribution:")
        for protocol, count in stats['protocol_distribution'].items():
            percentage = (count / stats['total_packets']) * 100
            print(f"  {protocol:10} : {count:5} packets ({percentage:5.2f}%)")
        print(f"{'='*80}\n")


# Example usage
if __name__ == "__main__":
    # Create packet capture instance
    capturer = PacketCapture(interface="en0", output_file="captured_packets.csv")
    
    # Start capturing 50 packets (or stop with Ctrl+C)
    # You can add filters like: filter_exp="tcp port 80 or tcp port 443" #will add this feature too.

    capturer.start_capture(count=1000, timeout=None) #my default timeout is 30, Changing it to 250 for more complicated tests.
    #instead we can specify what we can capture. 
    # capturer.start_capture(count=50, filter_exp="tcp port 80 or tcp port 443") #this will only capture http/https
    # capturer.start_capture(count=100, filter_exp="tcp") #this will only capture tcp
    # capturer.start_capture(count=0, timeout=120) #with this, you can capture indefinitely, pressing ctrl+c will stop the process.

    
    # Print statistics
    capturer.print_statistics()