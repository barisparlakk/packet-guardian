"""
Packet Guardian - Smart Packet Sniffer - Graphical User Interface
GUI wrapper for the packet sniffer application
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
from datetime import datetime

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from packet_capture import PacketCapture
from feature_extraction import FeatureExtractor
from ml_detector import AnomalyDetector
from visualizer import TrafficVisualizer


class PacketSnifferGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Guardian - Smart Packet Sniffer with ML Anomaly Detection")
        self.root.geometry("900x700")
        self.root.resizable(True, True)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Variables
        self.interface_var = tk.StringVar(value="en0")
        self.packet_count_var = tk.StringVar(value="100")
        self.filter_var = tk.StringVar(value="")
        self.contamination_var = tk.StringVar(value="0.15")
        self.is_capturing = False
        
        # Create UI
        self.create_header()
        self.create_status_bar()  # Create status bar BEFORE notebook
        self.create_notebook()
        
    def create_header(self):
        """Create header with title and logo"""
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=80)
        header_frame.pack(fill=tk.X, side=tk.TOP)
        
        title_label = tk.Label(
            header_frame,
            text="🔍 Packet Guardian ",
            font=("Helvetica", 24, "bold"),
            bg="#2c3e50",
            fg="white"
        )
        title_label.pack(pady=20)
        
        subtitle_label = tk.Label(
            header_frame,
            text="ML-Based Network Anomaly Detection System",
            font=("Helvetica", 11),
            bg="#2c3e50",
            fg="#ecf0f1"
        )
        subtitle_label.pack()
    
    def create_notebook(self):
        """Create tabbed interface"""
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Packet Capture
        self.capture_tab = ttk.Frame(notebook)
        notebook.add(self.capture_tab, text="📦 Packet Capture")
        self.create_capture_tab()
        
        # Tab 2: Analysis
        self.analysis_tab = ttk.Frame(notebook)
        notebook.add(self.analysis_tab, text="📊 Traffic Analysis")
        self.create_analysis_tab()
        
        # Tab 3: ML Detection
        self.ml_tab = ttk.Frame(notebook)
        notebook.add(self.ml_tab, text="🤖 ML Detection")
        self.create_ml_tab()
        
        # Tab 4: Visualization
        self.viz_tab = ttk.Frame(notebook)
        notebook.add(self.viz_tab, text="📈 Visualizations")
        self.create_viz_tab()
        
        # Tab 5: Results
        self.results_tab = ttk.Frame(notebook)
        notebook.add(self.results_tab, text="📋 Results")
        self.create_results_tab()
    
    def create_capture_tab(self):
        """Create packet capture interface"""
        # Configuration frame
        config_frame = ttk.LabelFrame(self.capture_tab, text="Capture Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Interface
        ttk.Label(config_frame, text="Network Interface:").grid(row=0, column=0, sticky=tk.W, pady=5)
        interface_entry = ttk.Entry(config_frame, textvariable=self.interface_var, width=20)
        interface_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="(e.g., en0, en1, lo0)", foreground="gray").grid(row=0, column=2, sticky=tk.W)
        
        # Packet count
        ttk.Label(config_frame, text="Packet Count:").grid(row=1, column=0, sticky=tk.W, pady=5)
        count_entry = ttk.Entry(config_frame, textvariable=self.packet_count_var, width=20)
        count_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        # Filter
        ttk.Label(config_frame, text="BPF Filter (optional):").grid(row=2, column=0, sticky=tk.W, pady=5)
        filter_entry = ttk.Entry(config_frame, textvariable=self.filter_var, width=40)
        filter_entry.grid(row=2, column=1, columnspan=2, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text='e.g., "tcp port 80" or "udp"', foreground="gray").grid(row=3, column=1, sticky=tk.W, padx=5)
        
        # Buttons
        button_frame = ttk.Frame(self.capture_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.capture_btn = ttk.Button(
            button_frame,
            text="▶ Start Capture",
            command=self.start_capture,
            width=20
        )
        self.capture_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text="⏹ Stop Capture",
            command=self.stop_capture,
            state=tk.DISABLED,
            width=20
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Output console
        output_frame = ttk.LabelFrame(self.capture_tab, text="Capture Output", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.capture_output = scrolledtext.ScrolledText(
            output_frame,
            height=15,
            font=("Courier", 10),
            bg="#1e1e1e",
            fg="#00ff00",
            insertbackground="white"
        )
        self.capture_output.pack(fill=tk.BOTH, expand=True)
        
        # Warning label
        warning_label = ttk.Label(
            self.capture_tab,
            text="⚠️ Note: Packet capture requires sudo/administrator privileges",
            foreground="red",
            font=("Helvetica", 10, "bold")
        )
        warning_label.pack(pady=5)
    
    def create_analysis_tab(self):
        """Create traffic analysis interface"""
        # Button
        button_frame = ttk.Frame(self.analysis_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            button_frame,
            text="🔍 Analyze Traffic",
            command=self.analyze_traffic,
            width=25
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="💾 Save Features",
            command=self.save_features,
            width=25
        ).pack(side=tk.LEFT, padx=5)
        
        # Output
        output_frame = ttk.LabelFrame(self.analysis_tab, text="Analysis Report", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.analysis_output = scrolledtext.ScrolledText(
            output_frame,
            height=20,
            font=("Courier", 10),
            bg="#f8f9fa"
        )
        self.analysis_output.pack(fill=tk.BOTH, expand=True)
    
    def create_ml_tab(self):
        """Create ML detection interface"""
        # Configuration
        config_frame = ttk.LabelFrame(self.ml_tab, text="ML Configuration", padding=10)
        config_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(config_frame, text="Contamination Rate:").grid(row=0, column=0, sticky=tk.W, pady=5)
        ttk.Entry(config_frame, textvariable=self.contamination_var, width=10).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(config_frame, text="(0.1 - 0.3 recommended)", foreground="gray").grid(row=0, column=2, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(self.ml_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            button_frame,
            text="🎓 Train Model",
            command=self.train_model,
            width=20
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="🔍 Detect Anomalies",
            command=self.detect_anomalies,
            width=20
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="💾 Save Model",
            command=self.save_model,
            width=20
        ).pack(side=tk.LEFT, padx=5)
        
        # Output
        output_frame = ttk.LabelFrame(self.ml_tab, text="Detection Results", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.ml_output = scrolledtext.ScrolledText(
            output_frame,
            height=20,
            font=("Courier", 10),
            bg="#f8f9fa"
        )
        self.ml_output.pack(fill=tk.BOTH, expand=True)
    
    def create_viz_tab(self):
        """Create visualization interface"""
        # Buttons
        button_frame = ttk.Frame(self.viz_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            button_frame,
            text="📊 Generate All Visualizations",
            command=self.generate_visualizations,
            width=30
        ).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(
            button_frame,
            text="📂 Open Visualizations Folder",
            command=self.open_viz_folder,
            width=30
        ).pack(side=tk.LEFT, padx=5)
        
        # Info frame
        info_frame = ttk.LabelFrame(self.viz_tab, text="Generated Visualizations", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.viz_listbox = tk.Listbox(
            info_frame,
            font=("Courier", 11),
            height=20,
            bg="#f8f9fa"
        )
        self.viz_listbox.pack(fill=tk.BOTH, expand=True)
        self.viz_listbox.bind('<Double-Button-1>', self.open_visualization)
        
        ttk.Label(
            self.viz_tab,
            text="💡 Tip: Double-click on a file to open it",
            foreground="gray"
        ).pack(pady=5)
    
    def create_results_tab(self):
        """Create results summary interface"""
        # Refresh button
        button_frame = ttk.Frame(self.results_tab)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(
            button_frame,
            text="🔄 Refresh Results",
            command=self.refresh_results,
            width=25
        ).pack(side=tk.LEFT, padx=5)
        
        # Results display
        results_frame = ttk.LabelFrame(self.results_tab, text="Project Files Summary", padding=10)
        results_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.results_output = scrolledtext.ScrolledText(
            results_frame,
            height=20,
            font=("Courier", 10),
            bg="#f8f9fa"
        )
        self.results_output.pack(fill=tk.BOTH, expand=True)
        
        # Auto-refresh on tab creation
        self.refresh_results()
    
    def create_status_bar(self):
        """Create status bar at bottom"""
        status_frame = tk.Frame(self.root, bg="#34495e", height=30)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM)
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg="#34495e",
            fg="white",
            font=("Helvetica", 10),
            anchor=tk.W
        )
        self.status_label.pack(fill=tk.X, padx=10)
    
    # Action methods
    def update_status(self, message):
        """Update status bar message"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_label.config(text=f"[{timestamp}] {message}")
        self.root.update()
    
    def log_output(self, text_widget, message):
        """Log message to output widget"""
        text_widget.insert(tk.END, message + "\n")
        text_widget.see(tk.END)
        self.root.update()
    
    def start_capture(self):
        """Start packet capture"""
        interface = self.interface_var.get()
        try:
            count = int(self.packet_count_var.get())
        except ValueError:
            messagebox.showerror("Error", "Packet count must be a number!")
            return
        
        filter_exp = self.filter_var.get() if self.filter_var.get() else None
        
        # Warning about sudo
        if not messagebox.askyesno(
            "Sudo Required",
            "Packet capture requires sudo privileges.\n\n"
            "Make sure you run this application with:\n"
            "sudo python gui.py\n\n"
            "Continue?"
        ):
            return
        
        self.capture_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.capture_output.delete(1.0, tk.END)
        self.is_capturing = True
        
        self.update_status(f"Capturing {count} packets on {interface}...")
        
        # Run in thread to avoid freezing GUI
        def capture_thread():
            try:
                capturer = PacketCapture(interface=interface, output_file="captured_packets.csv")
                
                # Override callback to show in GUI
                original_callback = capturer.packet_callback
                def gui_callback(packet):
                    original_callback(packet)
                    if capturer.packet_count % 10 == 0:  # Update every 10 packets
                        self.log_output(
                            self.capture_output,
                            f"Captured {capturer.packet_count} packets..."
                        )
                
                capturer.packet_callback = gui_callback
                capturer.start_capture(count=count, timeout=None, filter_exp=filter_exp)
                
                self.log_output(self.capture_output, "\n" + "="*50)
                self.log_output(self.capture_output, "✓ Capture completed!")
                self.log_output(self.capture_output, f"✓ Saved {capturer.packet_count} packets")
                self.update_status("Capture completed successfully")
                
            except Exception as e:
                self.log_output(self.capture_output, f"\n✗ Error: {str(e)}")
                self.update_status(f"Capture failed: {str(e)}")
            finally:
                self.capture_btn.config(state=tk.NORMAL)
                self.stop_btn.config(state=tk.DISABLED)
                self.is_capturing = False
        
        threading.Thread(target=capture_thread, daemon=True).start()
    
    def stop_capture(self):
        """Stop packet capture"""
        self.is_capturing = False
        self.update_status("Stopping capture...")
    
    def analyze_traffic(self):
        """Analyze captured traffic"""
        self.analysis_output.delete(1.0, tk.END)
        self.update_status("Analyzing traffic...")
        
        try:
            extractor = FeatureExtractor("captured_packets.csv")
            
            if not extractor.load_data():
                self.log_output(self.analysis_output, "✗ No packet data found. Capture packets first!")
                return
            
            # Redirect output to GUI
            import io
            from contextlib import redirect_stdout
            
            output = io.StringIO()
            with redirect_stdout(output):
                extractor.generate_report()
            
            self.analysis_output.insert(tk.END, output.getvalue())
            self.update_status("Traffic analysis completed")
            
        except Exception as e:
            self.log_output(self.analysis_output, f"✗ Error: {str(e)}")
            self.update_status(f"Analysis failed: {str(e)}")
    
    def save_features(self):
        """Save extracted features"""
        try:
            extractor = FeatureExtractor("captured_packets.csv")
            if extractor.load_data():
                features = extractor.extract_ml_features()
                if features is not None:
                    extractor.save_features()
                    messagebox.showinfo("Success", "Features saved successfully!")
                    self.update_status("Features saved")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def train_model(self):
        """Train ML model"""
        self.ml_output.delete(1.0, tk.END)
        self.update_status("Training ML model...")
        
        try:
            contamination = float(self.contamination_var.get())
            if not (0.0 <= contamination <= 0.5):
                raise ValueError("Contamination must be between 0.0 and 0.5")
        except ValueError as e:
            messagebox.showerror("Error", str(e))
            return
        
        try:
            detector = AnomalyDetector(model_type="isolation_forest")
            features_df = detector.load_features("extracted_features.csv")
            
            if features_df is None or len(features_df) == 0:
                self.log_output(self.ml_output, "✗ No features found. Run traffic analysis first!")
                return
            
            X = detector.preprocess_features(features_df)
            
            # Redirect output
            import io
            from contextlib import redirect_stdout
            
            output = io.StringIO()
            with redirect_stdout(output):
                detector.train(X, contamination=contamination)
                detector.save_model()
            
            self.ml_output.insert(tk.END, output.getvalue())
            self.update_status("Model training completed")
            messagebox.showinfo("Success", "Model trained and saved successfully!")
            
        except Exception as e:
            self.log_output(self.ml_output, f"✗ Error: {str(e)}")
            self.update_status(f"Training failed: {str(e)}")
    
    def detect_anomalies(self):
        """Detect anomalies using trained model"""
        self.ml_output.delete(1.0, tk.END)
        self.update_status("Detecting anomalies...")
        
        try:
            detector = AnomalyDetector(model_type="isolation_forest")
            
            if not detector.load_model("anomaly_detector.pkl"):
                self.log_output(self.ml_output, "✗ No trained model found. Train model first!")
                return
            
            features_df = detector.load_features("extracted_features.csv")
            if features_df is None:
                self.log_output(self.ml_output, "✗ No features found!")
                return
            
            results = detector.detect_anomalies(features_df)
            
            # Redirect output
            import io
            from contextlib import redirect_stdout
            
            output = io.StringIO()
            with redirect_stdout(output):
                detector.generate_report(results)
                detector.save_results(results)
            
            self.ml_output.insert(tk.END, output.getvalue())
            self.update_status("Anomaly detection completed")
            
        except Exception as e:
            self.log_output(self.ml_output, f"✗ Error: {str(e)}")
            self.update_status(f"Detection failed: {str(e)}")
    
    def save_model(self):
        """Save trained model"""
        try:
            messagebox.showinfo("Info", "Model is automatically saved after training!")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def generate_visualizations(self):
        """Generate all visualizations"""
        self.update_status("Generating visualizations...")
        
        try:
            visualizer = TrafficVisualizer()
            visualizer.generate_dashboard()
            
            self.refresh_viz_list()
            self.update_status("Visualizations generated successfully")
            messagebox.showinfo("Success", "All visualizations generated!")
            
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.update_status(f"Visualization failed: {str(e)}")
    
    def refresh_viz_list(self):
        """Refresh visualization list"""
        self.viz_listbox.delete(0, tk.END)
        
        viz_dir = os.path.join(os.path.dirname(__file__), "..", "visualizations")
        if os.path.exists(viz_dir):
            viz_files = sorted([f for f in os.listdir(viz_dir) if f.endswith('.png')])
            for f in viz_files:
                self.viz_listbox.insert(tk.END, f"📊 {f}")
        else:
            self.viz_listbox.insert(tk.END, "No visualizations generated yet")
    
    def open_viz_folder(self):
        """Open visualizations folder"""
        viz_dir = os.path.join(os.path.dirname(__file__), "..", "visualizations")
        if os.path.exists(viz_dir):
            os.system(f'open "{viz_dir}"')
        else:
            messagebox.showwarning("Warning", "Visualizations folder not found!")
    
    def open_visualization(self, event):
        """Open selected visualization"""
        selection = self.viz_listbox.curselection()
        if selection:
            filename = self.viz_listbox.get(selection[0]).replace("📊 ", "")
            viz_dir = os.path.join(os.path.dirname(__file__), "..", "visualizations")
            filepath = os.path.join(viz_dir, filename)
            if os.path.exists(filepath):
                os.system(f'open "{filepath}"')
    
    def refresh_results(self):
        """Refresh results summary"""
        self.results_output.delete(1.0, tk.END)
        self.update_status("Refreshing results...")
        
        data_dir = os.path.join(os.path.dirname(__file__), "..", "data")
        models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
        viz_dir = os.path.join(os.path.dirname(__file__), "..", "visualizations")
        
        self.log_output(self.results_output, "="*60)
        self.log_output(self.results_output, "PROJECT FILES SUMMARY")
        self.log_output(self.results_output, "="*60 + "\n")
        
        # Check data files
        self.log_output(self.results_output, "Data Files:")
        files = {
            "captured_packets.csv": "Packet Data",
            "extracted_features.csv": "Feature Data",
            "anomaly_results.csv": "Detection Results"
        }
        
        for filename, desc in files.items():
            filepath = os.path.join(data_dir, filename)
            if os.path.exists(filepath):
                size = os.path.getsize(filepath)
                self.log_output(self.results_output, f"  ✓ {desc:20} : {filename} ({size:,} bytes)")
            else:
                self.log_output(self.results_output, f"  ✗ {desc:20} : Not found")
        
        # Check model
        self.log_output(self.results_output, "\nModel Files:")
        model_path = os.path.join(models_dir, "anomaly_detector.pkl")
        if os.path.exists(model_path):
            size = os.path.getsize(model_path)
            self.log_output(self.results_output, f"  ✓ Trained Model        : anomaly_detector.pkl ({size:,} bytes)")
        else:
            self.log_output(self.results_output, f"  ✗ Trained Model        : Not found")
        
        # Check visualizations
        self.log_output(self.results_output, "\nVisualizations:")
        if os.path.exists(viz_dir):
            viz_files = [f for f in os.listdir(viz_dir) if f.endswith('.png')]
            self.log_output(self.results_output, f"  ✓ Generated Images     : {len(viz_files)} files")
            for viz_file in sorted(viz_files):
                self.log_output(self.results_output, f"     - {viz_file}")
        else:
            self.log_output(self.results_output, f"  ✗ No visualizations    : Folder not found")
        
        self.log_output(self.results_output, "\n" + "="*60)
        self.update_status("Results refreshed")


def main():
    """Main function to run GUI"""
    root = tk.Tk()
    app = PacketSnifferGUI(root)
    
    # Center window on screen
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()


if __name__ == "__main__":
    main()