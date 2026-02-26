from config.config import FAILED_LOGIN_THRESHOLD
from sklearn.ensemble import IsolationForest
import numpy as np

class AnomalyDetector:
    """Main anomaly detection class that combines all detection methods"""
    
    def __init__(self, dataframe):
        self.df = dataframe
        self.advanced_detector = AdvancedAnomalyDetector(dataframe)
    
    def detect_unknown_devices(self, allowed_macs):
        """Detect devices that are not in the allowed MAC list"""
        unknown = self.df[~self.df['mac_address'].isin(allowed_macs)]
        return unknown[['username', 'mac_address', 'timestamp', 'login_status']].drop_duplicates()
    
    def detect_bruteforce_attempts(self):
        """Detect brute force login attempts"""
        return self.advanced_detector.detect_bruteforce_attempts()
    
    def detect_login_spikes(self):
        """Detect unusual login frequency spikes"""
        return self.advanced_detector.detect_login_spikes()
    
    def detect_anomalies(self):
        """Run ML-based anomaly detection"""
        return self.advanced_detector.isolation_forest_detection()


class AdvancedAnomalyDetector:

    def __init__(self, dataframe):
        self.df = dataframe

    # 1️⃣ Brute Force Detection
    def detect_bruteforce_attempts(self):
        failed = self.df[self.df['login_status'] == "failed"]
        counts = failed.groupby('mac_address').size()
        suspicious = counts[counts >= FAILED_LOGIN_THRESHOLD]
        return suspicious

    # 2️⃣ Login Frequency Spike Detection
    def detect_login_spikes(self):
        login_counts = self.df.groupby(self.df['timestamp'].dt.hour).size()
        mean = login_counts.mean()
        std = login_counts.std()

        threshold = mean + 2 * std
        spikes = login_counts[login_counts > threshold]

        return spikes

    # 3️⃣ Isolation Forest (Advanced ML Anomaly Detection)
    def isolation_forest_detection(self):

        df_copy = self.df.copy()

        df_copy['hour'] = df_copy['timestamp'].dt.hour
        df_copy['failed_flag'] = df_copy['login_status'].apply(
            lambda x: 1 if x == "failed" else 0
        )

        features = df_copy[['hour','failed_flag']]

        model = IsolationForest(contamination=0.2, random_state=42)
        df_copy['anomaly_score'] = model.fit_predict(features)

        anomalies = df_copy[df_copy['anomaly_score'] == -1]

        return anomalies[['username','mac_address','timestamp']]