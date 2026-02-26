from core.log_parser import LogParser
from core.access_control import AccessControlEngine
from core.anomaly_detection import AnomalyDetector
from core.ml_engine import MLEngine
from core.visualization import Visualizer
from config.config import ALLOWED_MACS

def main():

    # Load & preprocess logs
    parser = LogParser("data/auth_logs.csv")
    df = parser.load_logs()
    df = parser.preprocess()

    # Apply access control
    ac_engine = AccessControlEngine(df)
    df = ac_engine.apply_policies()

    print("\nAccess Decisions:")
    print(df[['username','mac_address','access_decision']])

    # Anomaly detection
    detector = AnomalyDetector(df)

    print("\nUnknown Devices:")
    print(detector.detect_unknown_devices(ALLOWED_MACS))

    print("\nBrute Force Attempts:")
    print(detector.detect_bruteforce_attempts())

    # Machine Learning
    ml_engine = MLEngine(df)
    X_train, X_test, y_train, y_test = ml_engine.prepare_data()
    results = ml_engine.run_models(X_train, X_test, y_train, y_test)

    print("\nModel Performance:")
    print(results)

    # Visualization
    viz = Visualizer(df)
    viz.plot_login_trends()

if __name__ == "__main__":
    main()