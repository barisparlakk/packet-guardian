# Smart Packet Sniffer - User Guide

## Table of Contents
1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Module Overview](#module-overview)
4. [Step-by-Step Usage](#step-by-step-usage)
5. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites
- macOS (tested on macOS Tahoe)
- Python 3.11 or higher
- Anaconda or Python virtual environment
- Administrator privileges (for packet capture)

### Required Libraries
```bash
pip install -r requirements.txt
```

Or install individually:
```bash
pip install scapy scikit-learn numpy pandas matplotlib seaborn joblib psutil
```

### System Requirements
```bash
# Install libpcap (required for packet capture)
brew install libpcap
```

---

## Quick Start

### Option 1: Using Main Application (Recommended)

```bash
# Navigate to project directory
cd /path/to/packet-guardian/source

# Run main application
python main.py

# For packet capture (requires sudo)
sudo python main.py
```

### Option 2: Running Modules Individually

```bash
# Step 1: Capture packets (requires sudo)
sudo python packet_capture.py

# Step 2: Extract features
python feature_extraction.py

# Step 3: Train ML model and detect anomalies
python ml_detector.py

# Step 4: Generate visualizations
python visualizer.py
```

---

## Module Overview

### 1. Packet Capture Module (`packet_capture.py`)
**Purpose:** Captures network packets in real-time

**Features:**
- Captures IP, TCP, UDP, and ICMP packets
- Extracts source/destination addresses and ports
- Records packet sizes and timestamps
- Supports BPF filtering
- Saves data to CSV format

**Usage:**
```python
from packet_capture import PacketCapture

capturer = PacketCapture(interface="en0", output_file="captured_packets.csv")
capturer.start_capture(count=1000, timeout=None)
capturer.print_statistics()
```

**Key Parameters:**
- `interface`: Network interface (e.g., "en0" for WiFi, "en1" for Ethernet)
- `count`: Number of packets to capture (0 = unlimited)
- `timeout`: Time limit in seconds (None = wait until count reached)
- `filter_exp`: BPF filter expression (e.g., "tcp port 80")

---

### 2. Feature Extraction Module (`feature_extraction.py`)
**Purpose:** Analyzes captured packets and extracts ML features

**Features:**
- Calculates packet rates and protocol distribution
- Detects port scanning attempts
- Analyzes TCP flag patterns
- Identifies top talkers
- Generates flow-based features for ML

**Usage:**
```python
from feature_extraction import FeatureExtractor

extractor = FeatureExtractor("captured_packets.csv")
extractor.load_data()
extractor.generate_report()
features = extractor.extract_ml_features()
extractor.save_features()
```

**Generated Features:**
- Packet count per source IP
- Unique destination IPs and ports
- Average packet size and standard deviation
- Protocol distribution (TCP/UDP/ICMP counts)
- Packet rate (packets per second)
- Average TTL values

---

### 3. ML Detection Module (`ml_detector.py`)
**Purpose:** Detects anomalous network traffic using machine learning

**Features:**
- Isolation Forest algorithm for anomaly detection
- Risk level classification (HIGH/MEDIUM/LOW)
- Identifies potential attacks (port scans, DoS, flooding)
- Model persistence (save/load trained models)

**Usage:**
```python
from ml_detector import AnomalyDetector

detector = AnomalyDetector(model_type="isolation_forest")
features_df = detector.load_features("extracted_features.csv")
X = detector.preprocess_features(features_df)
detector.train(X, contamination=0.15)
results = detector.detect_anomalies(features_df)
detector.generate_report(results)
detector.save_model()
```

**Key Parameters:**
- `contamination`: Expected proportion of anomalies (0.0 to 0.5)
- Higher values = more aggressive detection
- Typical range: 0.10 to 0.20 (10-20% anomaly rate)

**Attack Detection:**
- **Port Scanning:** High unique destination port count
- **DoS Attack:** High packet rate to single destination
- **Flooding:** Unusually high packet count in short time

---

### 4. Visualization Module (`visualizer.py`)
**Purpose:** Creates charts and graphs for traffic analysis

**Features:**
- Protocol distribution pie chart
- Packet size histogram
- Traffic timeline
- Top talkers bar charts
- Anomaly detection scatter plot
- Feature correlation heatmap
- Port distribution analysis

**Usage:**
```python
from visualizer import TrafficVisualizer

visualizer = TrafficVisualizer()
visualizer.generate_dashboard()
```

**Output Location:**
All visualizations are saved to: `packet-guardian/visualizations/`

---

## Step-by-Step Usage

### Complete Workflow

#### Step 1: Capture Network Traffic

**Using Main Application:**
```bash
sudo python main.py
# Select option 1: Capture Network Packets
```

**Manual Method:**
```bash
cd source
sudo python packet_capture.py
```

**Tips for Better Capture:**
- Browse websites while capturing
- Stream videos for diverse traffic
- Download files to generate bulk traffic
- Use longer capture times for enterprise environments

**Recommended Settings:**
- Home network: 500-1000 packets
- Lab environment: 1000-5000 packets
- Production network: 10000+ packets

---

#### Step 2: Extract Traffic Features

**Using Main Application:**
```bash
python main.py
# Select option 2: Extract Traffic Features
```

**Manual Method:**
```bash
python feature_extraction.py
```

**What to Look For:**
- Number of unique flows (source IPs)
- Protocol distribution percentages
- Suspicious port scanning activity
- High-rate burst detections

**Minimum Requirements:**
- At least 10 unique source IPs for ML
- Mix of protocols (TCP, UDP, ICMP)
- Variety in packet sizes

---

#### Step 3: Train ML Model

**Using Main Application:**
```bash
python main.py
# Select option 3: Train ML Anomaly Detector
```

**Manual Method:**
```bash
python ml_detector.py
```

**Configuration:**
- Contamination rate: 0.10-0.20 recommended
- Model type: Isolation Forest (default)
- Features: Auto-selected numeric features

---

#### Step 4: Detect Anomalies

**Using Main Application:**
```bash
python main.py
# Select option 4: Detect Anomalies
```

The system will:
1. Load trained model
2. Analyze traffic features
3. Classify flows as normal or anomalous
4. Assign risk levels
5. Generate detailed report

---

#### Step 5: Generate Visualizations

**Using Main Application:**
```bash
python main.py
# Select option 5: Generate Visualizations
```

**Output Files:**
1. `protocol_distribution.png` - Traffic composition
2. `packet_size_histogram.png` - Size distribution
3. `traffic_timeline.png` - Activity over time
4. `top_talkers.png` - Most active IPs
5. `port_distribution.png` - Common ports
6. `anomaly_detection.png` - Detected threats
7. `feature_correlation.png` - Feature relationships

---

## Troubleshooting

### Common Issues

#### 1. "Permission Denied" Error
**Cause:** Packet capture requires root privileges

**Solution:**
```bash
sudo python packet_capture.py
# or
sudo python main.py
```

---

#### 2. "No Module Named 'scapy'" Error
**Cause:** Required libraries not installed

**Solution:**
```bash
pip install -r requirements.txt
```

---

#### 3. "Interface Not Found" Error
**Cause:** Invalid network interface specified

**Solution:**
```bash
# List available interfaces
ifconfig

# Common interfaces:
# - en0: WiFi
# - en1: Ethernet
# - lo0: Loopback
```

---

#### 4. Capturing Too Few Packets
**Cause:** Low network activity or timeout too short

**Solution:**
- Remove timeout: `timeout=None`
- Generate traffic while capturing
- Use broader filters: `filter_exp="ip"`
- Browse web/stream video during capture

---

#### 5. "Not Enough Features for ML"
**Cause:** Too few unique source IPs in capture

**Solution:**
- Capture more packets (500-1000+)
- Capture during active network usage
- Combine multiple capture sessions

---

#### 6. Visualizations Not Generating
**Cause:** Missing data files

**Solution:**
```bash
# Verify files exist:
ls -la ../data/captured_packets.csv
ls -la ../data/extracted_features.csv
ls -la ../data/anomaly_results.csv

# If missing, run previous steps
```

---

### Getting Help

**Check File Structure:**
```
packet-guardian/
├── source/
│   ├── packet_capture.py
│   ├── feature_extraction.py
│   ├── ml_detector.py
│   ├── visualizer.py
│   └── main.py
├── data/
│   ├── captured_packets.csv
│   ├── extracted_features.csv
│   └── anomaly_results.csv
├── models/
│   └── anomaly_detector.pkl
├── visualizations/
│   └── (PNG files)
└── requirements.txt
```

**Verify Installation:**
```bash
python -c "import scapy; print('Scapy OK')"
python -c "import sklearn; print('Scikit-learn OK')"
python -c "import pandas; print('Pandas OK')"
```

---

## Advanced Usage

### Custom Filtering

**Capture only HTTP/HTTPS traffic:**
```python
capturer.start_capture(count=1000, filter_exp="tcp port 80 or tcp port 443")
```

**Capture only DNS queries:**
```python
capturer.start_capture(count=500, filter_exp="udp port 53")
```

**Capture from specific host:**
```python
capturer.start_capture(count=500, filter_exp="host 192.168.1.1")
```

---

### Model Tuning

**Adjust anomaly sensitivity:**
```python
# More sensitive (detects more anomalies)
detector.train(X, contamination=0.25)

# Less sensitive (fewer false positives)
detector.train(X, contamination=0.10)
```

---

### Batch Processing

**Process multiple capture files:**
```python
import glob

for csv_file in glob.glob("../data/capture_*.csv"):
    extractor = FeatureExtractor(csv_file)
    extractor.load_data()
    extractor.extract_ml_features()
```

---

## Performance Tips

1. **Faster Capture:** Use specific filters to reduce processing
2. **Better Detection:** Capture during varied network activity
3. **More Accurate ML:** Collect baseline "normal" traffic first
4. **Resource Usage:** Limit packet count for real-time processing

---

## Security Considerations

⚠️ **Important Notes:**
- Only capture traffic on networks you own or have permission to monitor
- Packet sniffing may be illegal on public/corporate networks without authorization
- Handle captured data securely (may contain sensitive information)
- This tool is for educational and authorized security testing only

---

## Support

For issues or questions:
1. Check the troubleshooting section
2. Verify all prerequisites are installed
3. Review the module documentation
4. Check file permissions and network interface settings