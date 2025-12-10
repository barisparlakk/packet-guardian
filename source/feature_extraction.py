"""
Feature Extraction Module
Extracts traffic features for anomaly detection
"""

import pandas as pd
import numpy as np
from datetime import datetime
from collections import Counter
import os


class FeatureExtractor:
    def __init__(self, csv_file="captured_packets.csv"):
        """
        Initialize feature extractor
        
        Args:
            csv_file: Path to captured packets CSV file
        """
        self.csv_file = csv_file
        self.df = None
        self.features = None
        
    def load_data(self):
        """
        Load packet data from CSV file
        """
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        filepath = os.path.join(data_dir, self.csv_file)
        
        try:
            self.df = pd.read_csv(filepath)
            print(f"✓ Loaded {len(self.df)} packets from {filepath}")
            
            # Convert timestamp to datetime
            self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
            
            return True
        except Exception as e:
            print(f"Error loading data: {e}")
            return False
    
    def calculate_packet_rate(self, time_window=1.0):
        """
        Calculate packets per second
        
        Args:
            time_window: Time window in seconds
            
        Returns:
            float: Packets per second
        """
        if self.df is None or len(self.df) == 0:
            return 0
        
        time_diff = (self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds()
        
        if time_diff == 0:
            return len(self.df)
        
        return len(self.df) / time_diff
    
    def get_protocol_distribution(self):
        """
        Get distribution of protocols
        
        Returns:
            dict: Protocol counts and percentages
        """
        if self.df is None:
            return {}
        
        protocol_counts = self.df['protocol'].value_counts()
        total = len(self.df)
        
        distribution = {}
        for protocol, count in protocol_counts.items():
            distribution[protocol] = {
                'count': int(count),
                'percentage': (count / total) * 100
            }
        
        return distribution
    
    def detect_port_scan(self, threshold=10):
        """
        Detect potential port scanning activity
        
        Args:
            threshold: Number of unique ports accessed from same source
            
        Returns:
            list: Suspicious source IPs and their activity
        """
        if self.df is None:
            return []
        
        # Group by source IP and count unique destination ports
        port_scan_suspects = []
        
        for src_ip in self.df['src_ip'].unique():
            if pd.isna(src_ip):
                continue
            
            src_data = self.df[self.df['src_ip'] == src_ip]
            unique_dst_ports = src_data['dst_port'].nunique()
            unique_dst_ips = src_data['dst_ip'].nunique()
            
            if unique_dst_ports >= threshold:
                port_scan_suspects.append({
                    'src_ip': src_ip,
                    'unique_ports_accessed': int(unique_dst_ports),
                    'unique_destinations': int(unique_dst_ips),
                    'total_packets': len(src_data),
                    'protocols': src_data['protocol'].unique().tolist()
                })
        
        return sorted(port_scan_suspects, key=lambda x: x['unique_ports_accessed'], reverse=True)
    
    def analyze_tcp_flags(self):
        """
        Analyze TCP flag patterns
        
        Returns:
            dict: TCP flag statistics
        """
        if self.df is None:
            return {}
        
        tcp_data = self.df[self.df['protocol'] == 'TCP']
        
        if len(tcp_data) == 0:
            return {'message': 'No TCP packets found'}
        
        flag_counts = tcp_data['flags'].value_counts()
        
        flag_stats = {}
        for flag, count in flag_counts.items():
            if pd.notna(flag):
                flag_stats[str(flag)] = int(count)
        
        # Detect SYN flood (many SYN packets)
        syn_packets = tcp_data[tcp_data['flags'].str.contains('S', na=False)]
        syn_flood_risk = len(syn_packets) > (len(tcp_data) * 0.5)
        
        return {
            'flag_distribution': flag_stats,
            'total_tcp_packets': len(tcp_data),
            'syn_packets': len(syn_packets),
            'syn_flood_risk': syn_flood_risk
        }
    
    def calculate_packet_size_stats(self):
        """
        Calculate packet size statistics
        
        Returns:
            dict: Size statistics
        """
        if self.df is None:
            return {}
        
        return {
            'mean_size': float(self.df['packet_size'].mean()),
            'median_size': float(self.df['packet_size'].median()),
            'std_size': float(self.df['packet_size'].std()),
            'min_size': int(self.df['packet_size'].min()),
            'max_size': int(self.df['packet_size'].max()),
            'total_bytes': int(self.df['packet_size'].sum())
        }
    
    def detect_high_rate_bursts(self, window_size=5, threshold=10):
        """
        Detect high-rate traffic bursts
        
        Args:
            window_size: Time window in seconds
            threshold: Packets per second threshold
            
        Returns:
            list: Detected bursts
        """
        if self.df is None or len(self.df) < 2:
            return []
        
        bursts = []
        
        # Sort by timestamp
        df_sorted = self.df.sort_values('timestamp')
        
        for i in range(len(df_sorted) - 1):
            time_diff = (df_sorted.iloc[i + 1]['timestamp'] - df_sorted.iloc[i]['timestamp']).total_seconds()
            
            if time_diff > 0 and time_diff < 0.1:  # Very fast packets (< 0.1 sec)
                bursts.append({
                    'time': df_sorted.iloc[i]['timestamp'].strftime('%Y-%m-%d %H:%M:%S.%f'),
                    'packets_in_burst': 2,
                    'time_diff': time_diff
                })
        
        return bursts[:10]  # Return first 10 bursts
    
    def get_top_talkers(self, top_n=5):
        """
        Get most active source and destination IPs
        
        Args:
            top_n: Number of top talkers to return
            
        Returns:
            dict: Top source and destination IPs
        """
        if self.df is None:
            return {}
        
        top_src = self.df['src_ip'].value_counts().head(top_n)
        top_dst = self.df['dst_ip'].value_counts().head(top_n)
        
        return {
            'top_sources': {ip: int(count) for ip, count in top_src.items()},
            'top_destinations': {ip: int(count) for ip, count in top_dst.items()}
        }
    
    def extract_ml_features(self):
        """
        Extract features for machine learning model
        
        Returns:
            pandas.DataFrame: Feature matrix
        """
        if self.df is None:
            return None
        
        # Group packets by source IP to create flow-based features
        features_list = []
        
        for src_ip in self.df['src_ip'].unique():
            if pd.isna(src_ip):
                continue
            
            src_data = self.df[self.df['src_ip'] == src_ip]
            
            feature_vector = {
                'src_ip': src_ip,
                'packet_count': len(src_data),
                'unique_dst_ips': src_data['dst_ip'].nunique(),
                'unique_dst_ports': src_data['dst_port'].nunique(),
                'avg_packet_size': src_data['packet_size'].mean(),
                'std_packet_size': src_data['packet_size'].std(),
                'total_bytes': src_data['packet_size'].sum(),
                'tcp_count': len(src_data[src_data['protocol'] == 'TCP']),
                'udp_count': len(src_data[src_data['protocol'] == 'UDP']),
                'icmp_count': len(src_data[src_data['protocol'] == 'ICMP']),
                'avg_ttl': src_data['ttl'].mean(),
                'unique_protocols': src_data['protocol'].nunique()
            }
            
            # Calculate packet rate for this source
            if len(src_data) > 1:
                time_span = (src_data['timestamp'].max() - src_data['timestamp'].min()).total_seconds()
                feature_vector['packet_rate'] = len(src_data) / time_span if time_span > 0 else len(src_data)
            else:
                feature_vector['packet_rate'] = 1
            
            features_list.append(feature_vector)
        
        self.features = pd.DataFrame(features_list)
        return self.features
    
    def save_features(self, output_file="extracted_features.csv"):
        """
        Save extracted features to CSV
        
        Args:
            output_file: Output filename
        """
        if self.features is None:
            print("No features to save. Run extract_ml_features() first.")
            return
        
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        filepath = os.path.join(data_dir, output_file)
        
        try:
            self.features.to_csv(filepath, index=False)
            print(f"✓ Features saved to {filepath}")
        except Exception as e:
            print(f"Error saving features: {e}")
    
    def generate_report(self):
        """
        Generate comprehensive traffic analysis report
        """
        if self.df is None:
            print("No data loaded.")
            return
        
        print("\n" + "="*80)
        print("TRAFFIC ANALYSIS REPORT")
        print("="*80)
        
        # Basic stats
        print(f"\n📊 BASIC STATISTICS")
        print(f"   Total Packets: {len(self.df)}")
        print(f"   Packet Rate: {self.calculate_packet_rate():.2f} packets/second")
        print(f"   Capture Duration: {(self.df['timestamp'].max() - self.df['timestamp'].min()).total_seconds():.2f} seconds")
        
        # Protocol distribution
        print(f"\n🔌 PROTOCOL DISTRIBUTION")
        proto_dist = self.get_protocol_distribution()
        for protocol, stats in proto_dist.items():
            print(f"   {protocol:10} : {stats['count']:4} packets ({stats['percentage']:.1f}%)")
        
        # Packet size stats
        print(f"\n📦 PACKET SIZE STATISTICS")
        size_stats = self.calculate_packet_size_stats()
        print(f"   Mean Size: {size_stats['mean_size']:.2f} bytes")
        print(f"   Min Size: {size_stats['min_size']} bytes")
        print(f"   Max Size: {size_stats['max_size']} bytes")
        print(f"   Total Traffic: {size_stats['total_bytes']:,} bytes")
        
        # Top talkers
        print(f"\n💬 TOP TALKERS")
        top_talkers = self.get_top_talkers(top_n=3)
        print(f"   Top Source IPs:")
        for ip, count in top_talkers['top_sources'].items():
            print(f"      {ip:20} : {count} packets")
        print(f"   Top Destination IPs:")
        for ip, count in top_talkers['top_destinations'].items():
            print(f"      {ip:20} : {count} packets")
        
        # Port scan detection
        print(f"\n🔍 PORT SCAN DETECTION")
        port_scans = self.detect_port_scan(threshold=5)
        if port_scans:
            print(f"   ⚠️  {len(port_scans)} suspicious source(s) detected:")
            for suspect in port_scans[:3]:
                print(f"      {suspect['src_ip']:20} : {suspect['unique_ports_accessed']} unique ports accessed")
        else:
            print(f"   ✓ No suspicious port scanning detected")
        
        # TCP flags
        print(f"\n🚩 TCP FLAG ANALYSIS")
        tcp_flags = self.analyze_tcp_flags()
        if 'flag_distribution' in tcp_flags:
            for flag, count in list(tcp_flags['flag_distribution'].items())[:5]:
                print(f"   {flag:10} : {count} packets")
            if tcp_flags['syn_flood_risk']:
                print(f"   ⚠️  Possible SYN flood detected!")
        
        # High-rate bursts
        print(f"\n⚡ HIGH-RATE BURST DETECTION")
        bursts = self.detect_high_rate_bursts()
        if bursts:
            print(f"   ⚠️  {len(bursts)} high-rate burst(s) detected")
        else:
            print(f"   ✓ No high-rate bursts detected")
        
        print("\n" + "="*80 + "\n")


# Example usage
if __name__ == "__main__":
    # Create feature extractor
    extractor = FeatureExtractor("captured_packets.csv")
    
    # Load and analyze data
    if extractor.load_data():
        # Generate analysis report
        extractor.generate_report()
        
        # Extract ML features
        print("Extracting features for machine learning...")
        features = extractor.extract_ml_features()
        
        if features is not None:
            print(f"\n✓ Extracted {len(features)} feature vectors")
            print(f"✓ Feature dimensions: {features.shape[1] - 1} features per flow")
            
            # Display sample features
            print("\nSample feature vectors:")
            print(features.head())
            
            # Save features
            extractor.save_features()
        else:
            print("Failed to extract features.")