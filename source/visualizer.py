"""

Visualization Module
Creates charts and graphs for network traffic analysis

"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
from datetime import datetime


class TrafficVisualizer:
    def __init__(self):
        """
        Initialize visualizer
        """
        self.data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        self.output_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "visualizations")
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Set style
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
        
    def load_data(self, packets_file="captured_packets.csv", 
                  features_file="extracted_features.csv",
                  results_file="anomaly_results.csv"):
        """
        Load all data files
        
        Returns:
            tuple: (packets_df, features_df, results_df)
        """
        try:
            packets_df = pd.read_csv(os.path.join(self.data_dir, packets_file))
            packets_df['timestamp'] = pd.to_datetime(packets_df['timestamp'])
            print(f"✓ Loaded {len(packets_df)} packets")
        except Exception as e:
            print(f"Warning: Could not load packets: {e}")
            packets_df = None
        
        try:
            features_df = pd.read_csv(os.path.join(self.data_dir, features_file))
            print(f"✓ Loaded {len(features_df)} feature vectors")
        except Exception as e:
            print(f"Warning: Could not load features: {e}")
            features_df = None
        
        try:
            results_df = pd.read_csv(os.path.join(self.data_dir, results_file))
            print(f"✓ Loaded {len(results_df)} detection results")
        except Exception as e:
            print(f"Warning: Could not load results: {e}")
            results_df = None
        
        return packets_df, features_df, results_df
    
    def plot_protocol_distribution(self, packets_df):
        """
        Create pie chart of protocol distribution
        """
        if packets_df is None:
            return
        
        plt.figure(figsize=(10, 8))
        
        protocol_counts = packets_df['protocol'].value_counts()
        colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8']
        
        plt.pie(protocol_counts.values, 
                labels=protocol_counts.index,
                autopct='%1.1f%%',
                colors=colors,
                startangle=90,
                explode=[0.05] * len(protocol_counts))
        
        plt.title('Protocol Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.axis('equal')
        
        filepath = os.path.join(self.output_dir, 'protocol_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_packet_size_histogram(self, packets_df):
        """
        Create histogram of packet sizes
        """
        if packets_df is None:
            return
        
        plt.figure(figsize=(12, 6))
        
        plt.hist(packets_df['packet_size'], bins=50, color='#4ECDC4', 
                edgecolor='black', alpha=0.7)
        
        plt.axvline(packets_df['packet_size'].mean(), color='red', 
                   linestyle='--', linewidth=2, label=f'Mean: {packets_df["packet_size"].mean():.0f} bytes')
        plt.axvline(packets_df['packet_size'].median(), color='orange', 
                   linestyle='--', linewidth=2, label=f'Median: {packets_df["packet_size"].median():.0f} bytes')
        
        plt.xlabel('Packet Size (bytes)', fontsize=12, fontweight='bold')
        plt.ylabel('Frequency', fontsize=12, fontweight='bold')
        plt.title('Packet Size Distribution', fontsize=16, fontweight='bold', pad=20)
        plt.legend(fontsize=10)
        plt.grid(True, alpha=0.3)
        
        filepath = os.path.join(self.output_dir, 'packet_size_histogram.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_traffic_timeline(self, packets_df):
        """
        Create timeline of traffic activity
        """
        if packets_df is None or len(packets_df) < 2:
            return
        
        plt.figure(figsize=(14, 6))
        
        # Resample to 1-second intervals
        packets_df = packets_df.sort_values('timestamp')
        packets_df.set_index('timestamp', inplace=True)
        
        # Count packets per second
        packets_per_second = packets_df.resample('1S').size()
        
        plt.plot(packets_per_second.index, packets_per_second.values, 
                color='#4ECDC4', linewidth=2, marker='o', markersize=4)
        
        plt.fill_between(packets_per_second.index, packets_per_second.values, 
                        alpha=0.3, color='#4ECDC4')
        
        plt.xlabel('Time', fontsize=12, fontweight='bold')
        plt.ylabel('Packets per Second', fontsize=12, fontweight='bold')
        plt.title('Network Traffic Timeline', fontsize=16, fontweight='bold', pad=20)
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        
        filepath = os.path.join(self.output_dir, 'traffic_timeline.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_top_talkers(self, packets_df, top_n=10):
        """
        Create bar chart of top source IPs
        """
        if packets_df is None:
            return
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # Top source IPs
        top_src = packets_df['src_ip'].value_counts().head(top_n)
        ax1.barh(range(len(top_src)), top_src.values, color='#FF6B6B', alpha=0.7)
        ax1.set_yticks(range(len(top_src)))
        ax1.set_yticklabels(top_src.index)
        ax1.set_xlabel('Packet Count', fontsize=12, fontweight='bold')
        ax1.set_title('Top Source IPs', fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3, axis='x')
        
        # Top destination IPs
        top_dst = packets_df['dst_ip'].value_counts().head(top_n)
        ax2.barh(range(len(top_dst)), top_dst.values, color='#4ECDC4', alpha=0.7)
        ax2.set_yticks(range(len(top_dst)))
        ax2.set_yticklabels(top_dst.index)
        ax2.set_xlabel('Packet Count', fontsize=12, fontweight='bold')
        ax2.set_title('Top Destination IPs', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3, axis='x')
        
        plt.tight_layout()
        
        filepath = os.path.join(self.output_dir, 'top_talkers.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_anomaly_detection(self, results_df):
        """
        Create scatter plot showing normal vs anomalous traffic
        """
        if results_df is None:
            return
        
        plt.figure(figsize=(12, 8))
        
        normal = results_df[results_df['is_anomaly'] == False]
        anomalies = results_df[results_df['is_anomaly'] == True]
        
        # Plot normal traffic
        plt.scatter(normal['packet_count'], normal['unique_dst_ports'],
                   s=100, c='#4ECDC4', alpha=0.6, label='Normal Traffic',
                   edgecolors='black', linewidth=1)
        
        # Plot anomalies
        if len(anomalies) > 0:
            plt.scatter(anomalies['packet_count'], anomalies['unique_dst_ports'],
                       s=200, c='#FF6B6B', alpha=0.8, label='Anomalies',
                       edgecolors='black', linewidth=2, marker='^')
            
            # Annotate anomalies
            for idx, row in anomalies.iterrows():
                plt.annotate(f"{row['src_ip']}\n{row['risk_level']}",
                           xy=(row['packet_count'], row['unique_dst_ports']),
                           xytext=(10, 10), textcoords='offset points',
                           bbox=dict(boxstyle='round,pad=0.5', fc='yellow', alpha=0.7),
                           fontsize=8, fontweight='bold')
        
        plt.xlabel('Packet Count', fontsize=12, fontweight='bold')
        plt.ylabel('Unique Destination Ports', fontsize=12, fontweight='bold')
        plt.title('Anomaly Detection: Normal vs Suspicious Traffic', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.legend(fontsize=12, loc='upper right')
        plt.grid(True, alpha=0.3)
        
        filepath = os.path.join(self.output_dir, 'anomaly_detection.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_feature_correlation(self, features_df):
        """
        Create correlation heatmap of features
        """
        if features_df is None:
            return
        
        # Select numeric columns only
        numeric_cols = features_df.select_dtypes(include=[np.number]).columns
        
        if len(numeric_cols) < 2:
            return
        
        plt.figure(figsize=(12, 10))
        
        correlation = features_df[numeric_cols].corr()
        
        sns.heatmap(correlation, annot=True, fmt='.2f', cmap='coolwarm',
                   center=0, square=True, linewidths=1,
                   cbar_kws={"shrink": 0.8})
        
        plt.title('Feature Correlation Matrix', fontsize=16, fontweight='bold', pad=20)
        plt.tight_layout()
        
        filepath = os.path.join(self.output_dir, 'feature_correlation.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def plot_port_distribution(self, packets_df, top_n=15):
        """
        Create bar chart of most common ports
        """
        if packets_df is None:
            return
        
        plt.figure(figsize=(12, 6))
        
        # Combine source and destination ports
        all_ports = pd.concat([packets_df['src_port'], packets_df['dst_port']])
        all_ports = all_ports.dropna()
        
        if len(all_ports) == 0:
            return
        
        top_ports = all_ports.value_counts().head(top_n)
        
        bars = plt.bar(range(len(top_ports)), top_ports.values, 
                      color='#45B7D1', alpha=0.7, edgecolor='black')
        
        # Color common ports differently
        common_ports = {80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 22: 'SSH', 
                       21: 'FTP', 25: 'SMTP', 3389: 'RDP'}
        
        for i, (port, count) in enumerate(top_ports.items()):
            if port in common_ports:
                bars[i].set_color('#FF6B6B')
        
        plt.xticks(range(len(top_ports)), 
                  [f"{int(port)}\n{common_ports.get(port, '')}" for port in top_ports.index],
                  rotation=45, ha='right')
        
        plt.xlabel('Port Number', fontsize=12, fontweight='bold')
        plt.ylabel('Frequency', fontsize=12, fontweight='bold')
        plt.title('Most Common Ports', fontsize=16, fontweight='bold', pad=20)
        plt.grid(True, alpha=0.3, axis='y')
        plt.tight_layout()
        
        filepath = os.path.join(self.output_dir, 'port_distribution.png')
        plt.savefig(filepath, dpi=300, bbox_inches='tight')
        print(f"✓ Saved: {filepath}")
        plt.close()
    
    def generate_dashboard(self):
        """
        Create comprehensive visualization dashboard
        """
        print("\n" + "="*80)
        print("GENERATING VISUALIZATIONS")
        print("="*80 + "\n")
        
        # Load all data
        packets_df, features_df, results_df = self.load_data()
        
        if packets_df is None and features_df is None:
            print("Error: No data available for visualization!")
            return
        
        # Generate all plots
        print("\nCreating visualizations...")
        
        if packets_df is not None:
            self.plot_protocol_distribution(packets_df)
            self.plot_packet_size_histogram(packets_df)
            self.plot_traffic_timeline(packets_df)
            self.plot_top_talkers(packets_df)
            self.plot_port_distribution(packets_df)
        
        if features_df is not None:
            self.plot_feature_correlation(features_df)
        
        if results_df is not None:
            self.plot_anomaly_detection(results_df)
        
        print("\n" + "="*80)
        print("✓ All visualizations saved to:")
        print(f"  {self.output_dir}")
        print("="*80 + "\n")
        
        # List all generated files
        viz_files = [f for f in os.listdir(self.output_dir) if f.endswith('.png')]
        print(f"Generated {len(viz_files)} visualization(s):")
        for i, file in enumerate(viz_files, 1):
            print(f"  {i}. {file}")
        print()


# Example usage
if __name__ == "__main__":
    visualizer = TrafficVisualizer()
    visualizer.generate_dashboard()