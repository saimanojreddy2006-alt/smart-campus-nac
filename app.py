from flask import Flask
import pandas as pd
import os
import matplotlib.pyplot as plt

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(BASE_DIR, "data", "auth_logs.csv")


@app.route("/")
def home():

    df = pd.read_csv(file_path)

    total = len(df)
    success = len(df[df["login_status"] == "success"])
    failed = len(df[df["login_status"] == "failed"])
    unique_devices = df["mac_address"].nunique()

    # Generate chart
    chart_path = os.path.join(BASE_DIR, "static")
    os.makedirs(chart_path, exist_ok=True)

    plt.figure()
    df["login_status"].value_counts().plot(kind="bar")
    plt.title("Login Success vs Failure")
    plt.xlabel("Status")
    plt.ylabel("Count")
    plt.tight_layout()
    chart_file = os.path.join(chart_path, "login_chart.png")
    plt.savefig(chart_file)
    plt.close()

    # Intrusion detection (simple)
    failed_counts = df[df["login_status"] == "failed"].groupby("mac_address").size()
    suspicious = failed_counts[failed_counts > 1]

    intrusion_html = ""
    if not suspicious.empty:
        intrusion_html = "<h3 style='color:red;'>⚠ Suspicious Devices Detected:</h3>"
        for device in suspicious.index:
            intrusion_html += f"<p>{device} (Multiple Failed Logins)</p>"
    else:
        intrusion_html = "<p style='color:green;'>No Intrusion Detected</p>"

    return f"""
    <html>
    <head>
        <title>Smart Campus NAC Dashboard</title>
        <style>
            body {{
                font-family: Arial;
                background-color: #f4f6f9;
                padding: 20px;
            }}
            .card {{
                background: white;
                padding: 20px;
                margin: 10px;
                border-radius: 10px;
                box-shadow: 0px 2px 5px rgba(0,0,0,0.1);
                display: inline-block;
                width: 22%;
                text-align: center;
            }}
            h1 {{
                text-align: center;
            }}
        </style>
    </head>
    <body>
        <h1>🔐 Smart Campus Network Security Dashboard</h1>

        <div class="card">
            <h2>{total}</h2>
            <p>Total Attempts</p>
        </div>

        <div class="card">
            <h2>{success}</h2>
            <p>Successful Logins</p>
        </div>

        <div class="card">
            <h2>{failed}</h2>
            <p>Failed Logins</p>
        </div>

        <div class="card">
            <h2>{unique_devices}</h2>
            <p>Unique Devices</p>
        </div>

        <hr>

        <h2>📊 Login Trend</h2>
        <img src="/static/login_chart.png" width="400">

        <hr>

        <h2>🛡 Intrusion Detection</h2>
        {intrusion_html}

    </body>
    </html>
    """


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(debug=True, port=5055)
