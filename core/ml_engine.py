"""
Machine Learning Engine for Smart Campus NAC
Enhanced with Decision Tree, SVM, K-Means clustering, and model comparison
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.tree import DecisionTreeClassifier, DecisionTreeRegressor
from sklearn.svm import SVC, SVR
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.model_selection import train_test_split
from sklearn.metrics import (accuracy_score, precision_score, recall_score, 
                           f1_score, classification_report, confusion_matrix)
import warnings
warnings.filterwarnings('ignore')


class EnhancedMLEngine:
    """Enhanced ML engine with multiple models for different tasks"""
    
    def __init__(self, dataframe):
        self.df = dataframe.copy()
        self.results = {}
        self.label_encoders = {}
        self.scaler = StandardScaler()
        
    def _prepare_features(self, feature_cols):
        """Prepare features for ML training"""
        # Encode categorical variables
        for col in self.df.columns:
            if self.df[col].dtype == 'object' and col not in self.label_encoders:
                le = LabelEncoder()
                self.df[col + '_encoded'] = le.fit_transform(self.df[col].astype(str))
                self.label_encoders[col] = le
        
        # Select feature columns
        available_features = []
        for col in feature_cols:
            if col + '_encoded' in self.df.columns:
                available_features.append(col + '_encoded')
            elif col in self.df.columns:
                available_features.append(col)
        
        X = self.df[available_features].fillna(0)
        return X
    
    def login_success_failure_trends(self):
        """Analyze login success/failure trends over time"""
        if 'timestamp' not in self.df.columns:
            return {}
        
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        self.df['hour'] = self.df['timestamp'].dt.hour
        self.df['date'] = self.df['timestamp'].dt.date
        self.df['day_of_week'] = self.df['timestamp'].dt.day_name()
        
        # Hourly trends
        hourly_trend = self.df.groupby('hour')['login_status'].value_counts().unstack(fill_value=0)
        
        # Daily trends
        daily_trend = self.df.groupby('date')['login_status'].value_counts().unstack(fill_value=0)
        
        # Calculate success rate over time
        if 'success' in hourly_trend.columns and 'failed' in hourly_trend.columns:
            hourly_trend['success_rate'] = hourly_trend['success'] / (hourly_trend['success'] + hourly_trend['failed']) * 100
        
        return {
            'hourly': hourly_trend.to_dict(),
            'daily': daily_trend.to_dict() if len(daily_trend) > 0 else {},
            'hourly_df': hourly_trend,
            'daily_df': daily_trend
        }
    
    def device_fingerprint_clustering(self, n_clusters=3):
        """K-Means clustering for device fingerprinting"""
        # Create device fingerprint features
        device_features = self.df.groupby('mac_address').agg({
            'login_status': lambda x: (x == 'success').sum(),
            'os': 'nunique',
            'user_role': 'nunique',
            'username': 'nunique'
        }).reset_index()
        
        device_features.columns = ['mac_address', 'success_count', 'os_variety', 
                                   'role_variety', 'user_variety']
        
        # Add failure count
        failure_counts = self.df[self.df['login_status'] == 'failed'].groupby('mac_address').size()
        device_features['failure_count'] = device_features['mac_address'].map(failure_counts).fillna(0)
        
        # Cluster devices
        X = device_features[['success_count', 'os_variety', 'role_variety', 'user_variety', 'failure_count']]
        X_scaled = self.scaler.fit_transform(X)
        
        kmeans = KMeans(n_clusters=n_clusters, random_state=42, n_init=10)
        device_features['cluster'] = kmeans.fit_predict(X_scaled)
        
        # Analyze clusters
        cluster_summary = device_features.groupby('cluster').agg({
            'success_count': 'mean',
            'failure_count': 'mean',
            'os_variety': 'mean',
            'mac_address': 'count'
        }).rename(columns={'mac_address': 'device_count'})
        
        return {
            'device_features': device_features,
            'cluster_summary': cluster_summary,
            'kmeans_model': kmeans
        }
    
    def detect_unknown_mac_anomalies(self):
        """Detect anomalies based on unknown MAC addresses"""
        from config.config import ALLOWED_MACS
        
        # Mark unknown devices
        self.df['is_known_device'] = self.df['mac_address'].isin(ALLOWED_MACS)
        
        # Find anomalies
        unknown_devices = self.df[self.df['is_known_device'] == False]
        
        # Count by hour
        unknown_by_hour = unknown_devices.groupby(
            unknown_devices['timestamp'].dt.hour
        ).size() if 'timestamp' in self.df.columns else pd.Series()
        
        return {
            'unknown_count': len(unknown_devices),
            'unknown_devices': unknown_devices['mac_address'].unique(),
            'unknown_by_hour': unknown_by_hour.to_dict() if len(unknown_by_hour) > 0 else {},
            'total_devices': self.df['mac_address'].nunique(),
            'known_ratio': 1 - (len(unknown_devices) / len(self.df))
        }
    
    def time_based_access_patterns(self):
        """Analyze time-based access usage patterns"""
        if 'timestamp' not in self.df.columns:
            return {}
        
        self.df['timestamp'] = pd.to_datetime(self.df['timestamp'])
        self.df['hour'] = self.df['timestamp'].dt.hour
        
        # Access patterns by role
        role_hour = self.df.groupby(['user_role', 'hour']).size().unstack(fill_value=0)
        
        # Access patterns by day
        role_day = self.df.groupby(['user_role', 'day_of_week']).size().unstack(fill_value=0)
        
        # Peak hours
        peak_hours = self.df.groupby('hour').size().sort_values(ascending=False).head(5)
        
        # Access duration (time between first and last login per user)
        user_access = self.df.groupby('username').agg({
            'timestamp': ['min', 'max', 'count'],
            'hour': lambda x: x.max() - x.min()  # Access span in hours
        })
        user_access.columns = ['first_login', 'last_login', 'login_count', 'access_span_hours']
        user_access['session_duration_hours'] = (user_access['last_login'] - user_access['first_login']).dt.total_seconds() / 3600
        
        return {
            'role_hour_patterns': role_hour.to_dict(),
            'role_day_patterns': role_day.to_dict() if len(role_day) > 0 else {},
            'peak_hours': peak_hours.to_dict(),
            'role_hour_df': role_hour,
            'user_access_stats': user_access
        }
    
    def decision_tree_device_classification(self):
        """Decision Tree for device classification based on behavior"""
        # Prepare features
        df_device = self.df.groupby('mac_address').agg({
            'login_status': lambda x: (x == 'success').mean(),
            'os': lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else 'Unknown',
            'user_role': lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else 'Unknown',
            'timestamp': 'count'
        }).reset_index()
        
        df_device.columns = ['mac_address', 'success_rate', 'primary_os', 'primary_role', 'login_count']
        
        # Encode OS
        le_os = LabelEncoder()
        df_device['os_encoded'] = le_os.fit_transform(df_device['primary_os'])
        
        # Classify device risk level
        df_device['risk_level'] = pd.cut(
            df_device['success_rate'], 
            bins=[0, 0.5, 0.8, 1.0], 
            labels=['HIGH_RISK', 'MEDIUM_RISK', 'LOW_RISK']
        )
        
        # Features for classification
        le_risk = LabelEncoder()
        df_device['risk_encoded'] = le_risk.fit_transform(df_device['risk_level'].astype(str))
        
        X = df_device[['login_count', 'os_encoded']].fillna(0)
        y = df_device['risk_encoded']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)
        
        # Train Decision Tree
        dt = DecisionTreeClassifier(max_depth=5, random_state=42)
        dt.fit(X_train, y_train)
        y_pred = dt.predict(X_test)
        
        # Feature importance
        feature_importance = dict(zip(['login_count', 'os_encoded'], dt.feature_importances_))
        
        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, average='weighted', zero_division=0),
            'recall': recall_score(y_test, y_pred, average='weighted', zero_division=0),
            'f1': f1_score(y_test, y_pred, average='weighted', zero_division=0),
            'feature_importance': feature_importance,
            'model': dt,
            'device_risk': df_device,
            'class_names': list(le_risk.classes_)
        }
    
    def svm_intrusion_detection(self):
        """SVM for intrusion detection"""
        # Create intrusion labels
        self.df['is_intrusion'] = ((self.df['login_status'] == 'failed') & 
                                   (self.df['failure_reason'].isin(['Invalid credentials', 
                                                                   'Account locked', 
                                                                   'Policy violation',
                                                                   'Certificate expired',
                                                                   'Password expired',
                                                                   'MAC not authorized',
                                                                   'Time-based restriction']))).astype(int)
        
        # Prepare features
        feature_cols = ['os', 'user_role']
        X = self._prepare_features(feature_cols)
        
        # Add time-based features
        if 'timestamp' in self.df.columns:
            self.df['hour'] = pd.to_datetime(self.df['timestamp']).dt.hour
            X['hour'] = self.df['hour'].fillna(12)
        
        y = self.df['is_intrusion']
        
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train SVM
        svm = SVC(kernel='rbf', class_weight='balanced', random_state=42)
        svm.fit(X_train_scaled, y_train)
        y_pred = svm.predict(X_test_scaled)
        
        return {
            'accuracy': accuracy_score(y_test, y_pred),
            'precision': precision_score(y_test, y_pred, zero_division=0),
            'recall': recall_score(y_test, y_pred, zero_division=0),
            'f1': f1_score(y_test, y_pred, zero_division=0),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'model': svm,
            'training_size': len(X_train),
            'test_size': len(X_test)
        }
    
    def compare_models(self):
        """Compare Decision Tree vs SVM performance"""
        # Device classification (Decision Tree)
        dt_results = self.decision_tree_device_classification()
        
        # Intrusion detection (SVM)
        svm_results = self.svm_intrusion_detection()
        
        comparison = pd.DataFrame({
            'Model': ['Decision Tree (Device Classification)', 'SVM (Intrusion Detection)'],
            'Accuracy': [dt_results['accuracy'], svm_results['accuracy']],
            'Precision': [dt_results['precision'], svm_results['precision']],
            'Recall': [dt_results['recall'], svm_results['recall']],
            'F1-Score': [dt_results['f1'], svm_results['f1']]
        })
        
        return {
            'comparison_df': comparison,
            'decision_tree': dt_results,
            'svm': svm_results
        }
    
    def run_all_analyses(self):
        """Run all ML analyses"""
        return {
            'login_trends': self.login_success_failure_trends(),
            'device_clusters': self.device_fingerprint_clustering(),
            'unknown_mac': self.detect_unknown_mac_anomalies(),
            'time_patterns': self.time_based_access_patterns(),
            'model_comparison': self.compare_models()
        }


# Keep backward compatibility
class MLEngine(EnhancedMLEngine):
    """Backward compatible ML Engine"""
    
    def prepare_data(self):
        le_os = LabelEncoder()
        le_role = LabelEncoder()
        le_status = LabelEncoder()

        self.df['os_encoded'] = le_os.fit_transform(self.df['os'])
        self.df['role_encoded'] = le_role.fit_transform(self.df['user_role'])
        self.df['status_encoded'] = le_status.fit_transform(self.df['login_status'])

        X = self.df[['os_encoded', 'status_encoded']]
        y = self.df['role_encoded']

        return train_test_split(X, y, test_size=0.3, random_state=42)

    def run_models(self, X_train, X_test, y_train, y_test):
        dt = DecisionTreeClassifier()
        dt.fit(X_train, y_train)
        dt_pred = dt.predict(X_test)
        dt_acc = accuracy_score(y_test, dt_pred)

        svm = SVC()
        svm.fit(X_train, y_train)
        svm_pred = svm.predict(X_test)
        svm_acc = accuracy_score(y_test, svm_pred)

        return {
            "Decision Tree Accuracy": dt_acc,
            "SVM Accuracy": svm_acc
        }

