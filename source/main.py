"""
Smart Packet Sniffer with ML-Based Anomaly Detection
Main Application - Integrates all modules
"""

import sys
import os
from packet_capture import PacketCapture
from feature_extraction import FeatureExtractor
from ml_detector import AnomalyDetector
from visualizer import TrafficVisualizer


class PacketGuardian:
    def __init__(self):
        """
        Initialize Smart Packet Sniffer application
        """
        self.interface = "en0"
        self.packet_count = 100
        print("\n" + "="*80)
        print("PACKET GUARDIAN - SMART PACKET SNIFFER WITH ML-BASED ANOMALY DETECTION")
        print("="*80 + "\n")
    
    def print_menu(self):
        """
        Display main menu
        """
        print("\n" + "="*80)
        print("MAIN MENU")
        print("="*80)
        print("1. Capture Network Packets")
        print("2. Extract Traffic Features")
        print("3. Train ML Anomaly Detector")
        print("4. Detect Anomalies")
        print("5. Generate Visualizations")
        print("6. Run Full Pipeline (All Steps)")
        print("7. Configuration Settings")
        print("8. View Results Summary")
        print("9. Exit")
        print("="*80)
    
    def capture_packets(self):
        """
        Step 1: Capture network packets
        """
        print("\n" + "="*80)
        print("STEP 1: PACKET CAPTURE")
        print("="*80)
        
        # Get user input
        interface = input(f"Enter interface (default: {self.interface}): ") or self.interface
        count_input = input(f"Enter packet count (default: {self.packet_count}): ")
        count = int(count_input) if count_input else self.packet_count
        
        use_filter = input("Apply filter? (y/n): ").lower()
        filter_exp = None
        if use_filter == 'y':
            filter_exp = input("Enter BPF filter (e.g., 'tcp port 80'): ")
        
        # Capture packets
        print("\nStarting packet capture...")
        print("(This requires sudo privileges)")
        
        capturer = PacketCapture(interface=interface, output_file="captured_packets.csv")
        capturer.start_capture(count=count, timeout=None, filter_exp=filter_exp)
        capturer.print_statistics()
        
        print("\n✓ Packet capture completed!")
        input("Press Enter to continue...")
    
    def extract_features(self):
        """
        Step 2: Extract traffic features
        """
        print("\n" + "="*80)
        print("STEP 2: FEATURE EXTRACTION")
        print("="*80 + "\n")
        
        extractor = FeatureExtractor("captured_packets.csv")
        
        if extractor.load_data():
            extractor.generate_report()
            
            features = extractor.extract_ml_features()
            if features is not None:
                extractor.save_features()
                print("\n✓ Feature extraction completed!")
            else:
                print("\n✗ Feature extraction failed!")
        else:
            print("\n✗ Could not load packet data!")
        
        input("Press Enter to continue...")
    
    def train_model(self):
        """
        Step 3: Train ML model
        """
        print("\n" + "="*80)
        print("STEP 3: ML MODEL TRAINING")
        print("="*80 + "\n")
        
        detector = AnomalyDetector(model_type="isolation_forest")
        features_df = detector.load_features("extracted_features.csv")
        
        if features_df is not None and len(features_df) > 0:
            X = detector.preprocess_features(features_df)
            
            # Get contamination parameter
            contam_input = input("Expected anomaly rate (0.0-0.5, default: 0.15): ")
            contamination = float(contam_input) if contam_input else 0.15
            
            detector.train(X, contamination=contamination)
            detector.save_model("anomaly_detector.pkl")
            
            print("\n✓ Model training completed!")
        else:
            print("\n✗ No features available! Run feature extraction first.")
        
        input("Press Enter to continue...")
    
    def detect_anomalies(self):
        """
        Step 4: Detect anomalies
        """
        print("\n" + "="*80)
        print("STEP 4: ANOMALY DETECTION")
        print("="*80 + "\n")
        
        detector = AnomalyDetector(model_type="isolation_forest")
        
        # Load trained model
        if detector.load_model("anomaly_detector.pkl"):
            features_df = detector.load_features("extracted_features.csv")
            
            if features_df is not None:
                results = detector.detect_anomalies(features_df)
                detector.generate_report(results)
                detector.save_results(results, "anomaly_results.csv")
                
                print("\n✓ Anomaly detection completed!")
            else:
                print("\n✗ No features available!")
        else:
            print("\n✗ No trained model found! Train model first.")
        
        input("Press Enter to continue...")
    
    def generate_visualizations(self):
        """
        Step 5: Generate visualizations
        """
        print("\n" + "="*80)
        print("STEP 5: VISUALIZATION GENERATION")
        print("="*80 + "\n")
        
        visualizer = TrafficVisualizer()
        visualizer.generate_dashboard()
        
        print("✓ Visualizations completed!")
        input("Press Enter to continue...")
    
    def run_full_pipeline(self):
        """
        Step 6: Run complete pipeline
        """
        print("\n" + "="*80)
        print("RUNNING FULL PIPELINE")
        print("="*80 + "\n")
        
        response = input("This will run all steps. Continue? (y/n): ")
        if response.lower() != 'y':
            return
        
        # Step 1: Capture (skip - user should run with sudo separately)
        print("\n⚠️  Note: Packet capture must be run separately with sudo")
        print("   Run: sudo python main.py and select option 1")
        
        proceed = input("\nHave you already captured packets? (y/n): ")
        if proceed.lower() != 'y':
            print("Please capture packets first!")
            input("Press Enter to continue...")
            return
        
        # Step 2: Feature Extraction
        print("\n[2/4] Extracting features...")
        extractor = FeatureExtractor("captured_packets.csv")
        if extractor.load_data():
            extractor.extract_ml_features()
            extractor.save_features()
        
        # Step 3: Train Model
        print("\n[3/4] Training ML model...")
        detector = AnomalyDetector(model_type="isolation_forest")
        features_df = detector.load_features("extracted_features.csv")
        if features_df is not None:
            X = detector.preprocess_features(features_df)
            detector.train(X, contamination=0.15)
            detector.save_model("anomaly_detector.pkl")
        
        # Step 4: Detect Anomalies
        print("\n[4/4] Detecting anomalies...")
        detector = AnomalyDetector(model_type="isolation_forest")
        if detector.load_model("anomaly_detector.pkl"):
            features_df = detector.load_features("extracted_features.csv")
            if features_df is not None:
                results = detector.detect_anomalies(features_df)
                detector.generate_report(results)
                detector.save_results(results)
        
        # Step 5: Visualizations
        print("\n[5/5] Generating visualizations...")
        visualizer = TrafficVisualizer()
        visualizer.generate_dashboard()
        
        print("\n" + "="*80)
        print("✓ FULL PIPELINE COMPLETED!")
        print("="*80)
        input("Press Enter to continue...")
    
    def configuration(self):
        """
        Configuration settings
        """
        print("\n" + "="*80)
        print("CONFIGURATION SETTINGS")
        print("="*80)
        print(f"\nCurrent Settings:")
        print(f"  Interface: {self.interface}")
        print(f"  Default Packet Count: {self.packet_count}")
        
        change = input("\nChange settings? (y/n): ")
        if change.lower() == 'y':
            new_interface = input(f"New interface (current: {self.interface}): ")
            if new_interface:
                self.interface = new_interface
            
            new_count = input(f"New packet count (current: {self.packet_count}): ")
            if new_count:
                self.packet_count = int(new_count)
            
            print("\n✓ Settings updated!")
        
        input("Press Enter to continue...")
    
    def view_summary(self):
        """
        View results summary
        """
        print("\n" + "="*80)
        print("RESULTS SUMMARY")
        print("="*80)
        
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        
        # Check for files
        files_status = {
            "captured_packets.csv": "Packet Data",
            "extracted_features.csv": "Feature Data",
            "anomaly_results.csv": "Detection Results"
        }
        
        print("\nGenerated Files:")
        for filename, description in files_status.items():
            filepath = os.path.join(data_dir, filename)
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                print(f"  ✓ {description:20} : {filename} ({size:,} bytes)")
            else:
                print(f"  ✗ {description:20} : Not found")
        
        # Check model
        models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
        model_path = os.path.join(models_dir, "anomaly_detector.pkl")
        if os.path.exists(model_path):
            print(f"  ✓ {'Trained Model':20} : anomaly_detector.pkl")
        else:
            print(f"  ✗ {'Trained Model':20} : Not found")
        
        # Check visualizations
        viz_dir = os.path.join(os.path.dirname(__file__), "..", "visualizations")
        if os.path.exists(viz_dir):
            viz_files = [f for f in os.listdir(viz_dir) if f.endswith('.png')]
            print(f"  ✓ {'Visualizations':20} : {len(viz_files)} images")
        else:
            print(f"  ✗ {'Visualizations':20} : Not found")
        
        print("\n" + "="*80)
        input("Press Enter to continue...")
    
    def run(self):
        """
        Main application loop
        """
        while True:
            self.print_menu()
            choice = input("\nEnter choice (1-9): ")
            
            if choice == '1':
                self.capture_packets()
            elif choice == '2':
                self.extract_features()
            elif choice == '3':
                self.train_model()
            elif choice == '4':
                self.detect_anomalies()
            elif choice == '5':
                self.generate_visualizations()
            elif choice == '6':
                self.run_full_pipeline()
            elif choice == '7':
                self.configuration()
            elif choice == '8':
                self.view_summary()
            elif choice == '9':
                print("\n" + "="*80)
                print("Thank you for using Packet Guardian!")
                print("="*80 + "\n")
                sys.exit(0)
            else:
                print("\n✗ Invalid choice! Please enter 1-9.")
                input("Press Enter to continue...")


if __name__ == "__main__":
    app = PacketGuardian()
    app.run()