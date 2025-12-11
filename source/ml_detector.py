"""

ML-Based Anomaly Detection Module
Detects unusual network traffic patterns using Isolation Forest

"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
import joblib
import os
from datetime import datetime


class AnomalyDetector:
    def __init__(self, model_type="isolation_forest"):
        """
        Initialize anomaly detector
        
        Args:
            model_type: "isolation_forest" or "kmeans"
        """
        self.model_type = model_type
        self.model = None
        self.scaler = StandardScaler()
        self.feature_columns = None
        self.is_trained = False
        
    def load_features(self, csv_file="extracted_features.csv"):
        """
        Load extracted features from CSV
        
        Args:
            csv_file: Path to features CSV file
            
        Returns:
            pandas.DataFrame: Feature data
        """
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        filepath = os.path.join(data_dir, csv_file)
        
        try:
            df = pd.read_csv(filepath)
            print(f"✓ Loaded features from {filepath}")
            print(f"  Shape: {df.shape[0]} samples, {df.shape[1]} features")
            return df
        except Exception as e:
            print(f"Error loading features: {e}")
            return None
    
    def preprocess_features(self, df):
        """
        Preprocess features for ML model
        
        Args:
            df: Feature DataFrame
            
        Returns:
            numpy.ndarray: Preprocessed features
        """
        # Remove non-numeric columns (like src_ip)
        numeric_df = df.select_dtypes(include=[np.number])
        
        # Handle missing values
        numeric_df = numeric_df.fillna(0)
        
        # Store feature column names
        self.feature_columns = numeric_df.columns.tolist()
        
        print(f"✓ Preprocessed {len(self.feature_columns)} features:")
        for i, col in enumerate(self.feature_columns, 1):
            print(f"   {i:2}. {col}")
        
        return numeric_df.values
    
    def train(self, X, contamination=0.1):
        """
        Train anomaly detection model
        
        Args:
            X: Feature matrix
            contamination: Expected proportion of anomalies (0.0 to 0.5)
        """
        print(f"\n{'='*80}")
        print(f"TRAINING {self.model_type.upper()} MODEL")
        print(f"{'='*80}")
        print(f"Training samples: {X.shape[0]}")
        print(f"Features: {X.shape[1]}")
        print(f"Expected anomaly rate: {contamination*100:.1f}%")
        
        # Normalize features
        X_scaled = self.scaler.fit_transform(X)
        
        if self.model_type == "isolation_forest":
            # Isolation Forest
            self.model = IsolationForest(
                contamination=contamination,
                random_state=42,
                n_estimators=100,
                max_samples='auto',
                verbose=0
            )
            self.model.fit(X_scaled)
            print(f"✓ Isolation Forest trained with {self.model.n_estimators} trees")
            
        elif self.model_type == "kmeans":
            # K-Means clustering
            n_clusters = max(2, int(X.shape[0] / 10))  # Dynamic cluster count
            self.model = KMeans(
                n_clusters=n_clusters,
                random_state=42,
                n_init=10
            )
            self.model.fit(X_scaled)
            print(f"✓ K-Means trained with {n_clusters} clusters")
        
        self.is_trained = True
        print(f"{'='*80}\n")
    
    def predict(self, X):
        """
        Predict anomalies
        
        Args:
            X: Feature matrix
            
        Returns:
            numpy.ndarray: Predictions (-1 for anomaly, 1 for normal)
        """
        if not self.is_trained:
            raise ValueError("Model not trained! Call train() first.")
        
        # Normalize features
        X_scaled = self.scaler.transform(X)
        
        if self.model_type == "isolation_forest":
            # Isolation Forest: -1 = anomaly, 1 = normal
            predictions = self.model.predict(X_scaled)
            scores = self.model.score_samples(X_scaled)
            return predictions, scores
        
        elif self.model_type == "kmeans":
            # K-Means: use distance from cluster center
            distances = self.model.transform(X_scaled).min(axis=1)
            threshold = np.percentile(distances, 90)  # Top 10% as anomalies
            predictions = np.where(distances > threshold, -1, 1)
            scores = -distances  # Negative for consistency with IF
            return predictions, scores
    
    def detect_anomalies(self, df):
        """
        Detect anomalies in feature DataFrame
        
        Args:
            df: Feature DataFrame with src_ip column
            
        Returns:
            pandas.DataFrame: Results with anomaly labels
        """
        if not self.is_trained:
            raise ValueError("Model not trained! Call train() first.")
        
        # Store source IPs
        src_ips = df['src_ip'].values if 'src_ip' in df.columns else None
        
        # Preprocess features
        X = self.preprocess_features(df)
        
        # Predict
        predictions, scores = self.predict(X)
        
        # Create results DataFrame
        results = df.copy()
        results['anomaly'] = predictions
        results['anomaly_score'] = scores
        results['is_anomaly'] = predictions == -1
        
        # Add risk level
        def get_risk_level(score):
            if score < np.percentile(scores, 10):
                return "HIGH"
            elif score < np.percentile(scores, 30):
                return "MEDIUM"
            else:
                return "LOW"
        
        results['risk_level'] = results['anomaly_score'].apply(get_risk_level)
        
        return results
    
    def generate_report(self, results):
        """
        Generate anomaly detection report
        
        Args:
            results: DataFrame with anomaly predictions
        """
        anomalies = results[results['is_anomaly'] == True]
        normal = results[results['is_anomaly'] == False]
        
        print("\n" + "="*80)
        print("ANOMALY DETECTION REPORT")
        print("="*80)
        
        print(f"\n DETECTION SUMMARY")
        print(f"   Total Flows: {len(results)}")
        print(f"   Normal Traffic: {len(normal)} ({len(normal)/len(results)*100:.1f}%)")
        print(f"   Anomalous Traffic: {len(anomalies)} ({len(anomalies)/len(results)*100:.1f}%)")
        
        if len(anomalies) > 0:
            print(f"\n  DETECTED ANOMALIES")
            print(f"   High Risk: {len(anomalies[anomalies['risk_level']=='HIGH'])}")
            print(f"   Medium Risk: {len(anomalies[anomalies['risk_level']=='MEDIUM'])}")
            print(f"   Low Risk: {len(anomalies[anomalies['risk_level']=='LOW'])}")
            
            print(f"\n TOP 5 SUSPICIOUS FLOWS:")
            top_anomalies = anomalies.nsmallest(5, 'anomaly_score')
            
            for idx, row in top_anomalies.iterrows():
                print(f"\n   Source IP: {row.get('src_ip', 'Unknown')}")
                print(f"   Risk Level: {row['risk_level']}")
                print(f"   Anomaly Score: {row['anomaly_score']:.3f}")
                print(f"   Packets: {row.get('packet_count', 0)}")
                print(f"   Unique Destinations: {row.get('unique_dst_ips', 0)}")
                print(f"   Unique Ports: {row.get('unique_dst_ports', 0)}")
                
                # Identify potential attack types
                if row.get('unique_dst_ports', 0) > 10:
                    print(f"   !!!  Possible port scan detected!")
                if row.get('packet_rate', 0) > 100:
                    print(f"   !!!  High packet rate detected!")
                if row.get('packet_count', 0) > 100 and row.get('unique_dst_ips', 1) == 1:
                    print(f"   !!!  Possible DoS attack detected!")
        else:
            print(f"\n✓ No anomalies detected - all traffic appears normal")
        
        print("\n" + "="*80 + "\n")
    
    def save_model(self, model_name="anomaly_detector.pkl"):
        """
        Save trained model to file
        
        Args:
            model_name: Filename for model
        """
        if not self.is_trained:
            print("Model not trained! Nothing to save.")
            return
        
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
        os.makedirs(models_dir, exist_ok=True)
        filepath = os.path.join(models_dir, model_name)
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_columns': self.feature_columns,
            'model_type': self.model_type,
            'trained_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        try:
            joblib.dump(model_data, filepath)
            print(f"✓ Model saved to {filepath}")
        except Exception as e:
            print(f"Error saving model: {e}")
    
    def load_model(self, model_name="anomaly_detector.pkl"):
        """
        Load trained model from file
        
        Args:
            model_name: Filename of saved model
        """
        models_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
        filepath = os.path.join(models_dir, model_name)
        
        try:
            model_data = joblib.load(filepath)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_columns = model_data['feature_columns']
            self.model_type = model_data['model_type']
            self.is_trained = True
            
            print(f"✓ Model loaded from {filepath}")
            print(f"  Model type: {self.model_type}")
            print(f"  Trained at: {model_data['trained_at']}")
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def save_results(self, results, output_file="anomaly_results.csv"):
        """
        Save detection results to CSV
        
        Args:
            results: Results DataFrame
            output_file: Output filename
        """
        data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        filepath = os.path.join(data_dir, output_file)
        
        try:
            results.to_csv(filepath, index=False)
            print(f"✓ Results saved to {filepath}")
        except Exception as e:
            print(f"Error saving results: {e}")


# Example usage
if __name__ == "__main__":
    print("ML-Based Anomaly Detection System")
    print("="*80 + "\n")
    
    # Create detector
    detector = AnomalyDetector(model_type="isolation_forest")
    
    # Load features
    features_df = detector.load_features("extracted_features.csv")
    
    if features_df is not None and len(features_df) > 0:
        # Preprocess features
        X = detector.preprocess_features(features_df)
        
        # Train model
        detector.train(X, contamination=0.15)  # Expect 15% anomalies
        
        # Detect anomalies
        print("Detecting anomalies...")
        results = detector.detect_anomalies(features_df)
        
        # Generate report
        detector.generate_report(results)
        
        # Save model and results
        detector.save_model("anomaly_detector.pkl")
        detector.save_results(results, "anomaly_results.csv")
        
        print("\n✓ Anomaly detection complete!")
        print("\nNext steps:")
        print("  1. Review anomaly_results.csv for detailed findings")
        print("  2. Investigate suspicious IPs")
        print("  3. Run visualization module for charts")
    else:
        print("Error: No features available. Run feature_extraction.py first!")