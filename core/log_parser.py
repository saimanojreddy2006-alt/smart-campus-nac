import pandas as pd
import logging

logging.basicConfig(level=logging.INFO)

class LogParser:

    def __init__(self, file_path):
        self.file_path = file_path
        self.data = None

    def load_logs(self):
        try:
            self.data = pd.read_csv(self.file_path)
            self.data['timestamp'] = pd.to_datetime(self.data['timestamp'])
            logging.info("Authentication logs loaded successfully.")
        except Exception as e:
            logging.error(f"Error loading logs: {e}")

        return self.data

    def preprocess(self):
        if self.data is None:
            raise ValueError("No data loaded.")

        self.data.dropna(inplace=True)
        self.data.reset_index(drop=True, inplace=True)
        logging.info("Preprocessing completed.")

        return self.data