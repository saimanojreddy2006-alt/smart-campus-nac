"""
Smart Campus Network Access Control Dashboard
A comprehensive Streamlit dashboard for NAC monitoring and security analytics
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import os

# Configure page
st.set_page_config(
    page_title="Smart Campus NAC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set style
plt.style.use('seaborn-v0_8-whitegrid')

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(BASE_DIR, "data", "auth_logs.csv")


@st.cache_data
def load_data():
    """Load and preprocess authentication data"""
    try:
        df = pd.read_csv(DATA_PATH)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['hour'] = df['timestamp'].dt.hour
        df['date'] = df['timestamp'].dt.date
        df['day_of_week'] = df['timestamp'].dt.day_name()
        return df
    except FileNotFoundError:
        st.error(f"Data file not found at {DATA_PATH}")
        return None


def style_success_fail(val):
    """Style success/fail values in dataframe"""
    if val == 'success':
        return 'background-color: #d4edda; color: #155724'
    elif val == 'failed':
        return 'background-color: #f8d7da; color: #721c24'
    return ''


def render_sidebar(df):
    """Render sidebar with filters"""
    st.sidebar.title("🛡️ NAC Dashboard")
    st.sidebar.markdown("---")
    
    # Date range filter
    min_date = df['date'].min()
    max_date = df['date'].max()
    
    date_range = st.sidebar.date_input(
        "Select Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )
    
    # Role filter
    all_roles = ['All'] + sorted(df['user_role'].unique().tolist())
    selected_role = st.sidebar.selectbox("User Role", all_roles)
    
    # Status filter
    all_statuses = ['All'] + sorted(df['login_status'].unique().tolist())
    selected_status = st.sidebar.selectbox("Login Status", all_statuses)
    
    # MAC filter
    all_macs = ['All'] + sorted(df['mac_address'].unique().tolist())
    selected_mac = st.sidebar.selectbox("Device MAC", all_macs)
    
    # Apply filters
    filtered_df = df.copy()
    
    if len(date_range) == 2:
        filtered_df = filtered_df[
            (filtered_df['date'] >= date_range[0]) & 
            (filtered_df['date'] <= date_range[1])
        ]
    
    if selected_role != 'All':
        filtered_df = filtered_df[filtered_df['user_role'] == selected_role]
    
    if selected_status != 'All':
        filtered_df = filtered_df[filtered_df['login_status'] == selected_status]
    
    if selected_mac != 'All':
        filtered_df = filtered_df[filtered_df['mac_address'] == selected_mac]
    
    st.sidebar.markdown("---")
    st.sidebar.info(f"Showing {len(filtered_df)} of {len(df)} records")
    
    return filtered_df


def render_kpi_metrics(df):
    """Render KPI metric cards at the top"""
    col1, col2, col3, col4, col5 = st.columns(5)
    
    total = len(df)
    success = len(df[df['login_status'] == 'success'])
    failed = len(df[df['login_status'] == 'failed'])
    success_rate = (success / total * 100) if total > 0 else 0
    unique_devices = df['mac_address'].nunique()
    unique_users = df['username'].nunique()
    
    with col1:
        st.metric("Total Attempts", f"{total:,}", delta_color="off")
    with col2:
        st.metric("Successful", f"{success:,}", delta=f"+{success_rate:.1f}%", delta_color="normal")
    with col3:
        st.metric("Failed", f"{failed:,}", delta=f"-{100-success_rate:.1f}%", delta_color="inverse")
    with col4:
        st.metric("Unique Devices", f"{unique_devices:,}")
    with col5:
        st.metric("Unique Users", f"{unique_users:,}")


def render_login_trends(df):
    """Render login trends over time"""
    st.subheader("📈 Login Trends Over Time")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Daily login counts
        daily_counts = df.groupby('date').size()
        fig, ax = plt.subplots(figsize=(12, 5))
        ax.plot(daily_counts.index, daily_counts.values, marker='o', linewidth=2, markersize=6, color='#3498DB')
        ax.fill_between(daily_counts.index, daily_counts.values, alpha=0.3, color='#3498DB')
        ax.set_xlabel('Date', fontsize=12)
        ax.set_ylabel('Number of Login Attempts', fontsize=12)
        ax.set_title('Daily Login Attempts', fontsize=14, fontweight='bold')
        ax.tick_params(axis='x', rotation=45)
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Success vs Failure pie chart
        status_counts = df['login_status'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 6))
        colors = ['#2ECC71', '#E74C3C']
        wedges, texts, autotexts = ax.pie(
            status_counts.values, 
            labels=status_counts.index, 
            autopct='%1.1f%%',
            colors=colors,
            explode=(0.05, 0),
            shadow=True,
            startangle=90
        )
        ax.set_title('Login Status Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        st.pyplot(fig)


def render_role_analysis(df):
    """Render role-based analysis"""
    st.subheader("👥 Role-Based Analysis")
    
    col1, col2, col3, col4 = st.columns(4)
    
    # Role distribution
    role_counts = df['user_role'].value_counts()
    
    with col1:
        fig, ax = plt.subplots(figsize=(5, 4))
        colors = ['#3498DB', '#2ECC71', '#F39C12', '#9B59B6']
        bars = ax.bar(role_counts.index, role_counts.values, color=colors[:len(role_counts)])
        ax.set_xlabel('User Role', fontsize=11)
        ax.set_ylabel('Count', fontsize=11)
        ax.set_title('Logins by Role', fontsize=12, fontweight='bold')
        for bar, val in zip(bars, role_counts.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5, 
                   str(val), ha='center', va='bottom', fontsize=10)
        plt.tight_layout()
        st.pyplot(fig)
    
    # Success rate by role
    with col2:
        role_success = df.groupby('user_role')['login_status'].apply(
            lambda x: (x == 'success').sum() / len(x) * 100
        )
        fig, ax = plt.subplots(figsize=(5, 4))
        colors = ['#2ECC71' if v > 70 else '#F39C12' if v > 50 else '#E74C3C' for v in role_success.values]
        bars = ax.barh(role_success.index, role_success.values, color=colors)
        ax.set_xlabel('Success Rate (%)', fontsize=11)
        ax.set_title('Success Rate by Role', fontsize=12, fontweight='bold')
        ax.set_xlim(0, 100)
        for bar, val in zip(bars, role_success.values):
            ax.text(val + 2, bar.get_y() + bar.get_height()/2, 
                   f'{val:.1f}%', ha='left', va='center', fontsize=10)
        plt.tight_layout()
        st.pyplot(fig)
    
    # Hourly distribution by role
    with col3:
        hourly_role = df.groupby(['hour', 'user_role']).size().unstack(fill_value=0)
        fig, ax = plt.subplots(figsize=(6, 4))
        hourly_role.plot(kind='area', stacked=True, ax=ax, alpha=0.7)
        ax.set_xlabel('Hour of Day', fontsize=11)
        ax.set_ylabel('Login Count', fontsize=11)
        ax.set_title('Hourly Logins by Role', fontsize=12, fontweight='bold')
        ax.legend(title='Role', fontsize=8, loc='upper right')
        plt.tight_layout()
        st.pyplot(fig)
    
    # Device distribution by role
    with col4:
        role_devices = df.groupby('user_role')['mac_address'].nunique()
        fig, ax = plt.subplots(figsize=(5, 4))
        colors = ['#3498DB', '#2ECC71', '#F39C12', '#9B59B6']
        bars = ax.bar(role_devices.index, role_devices.values, color=colors[:len(role_devices)])
        ax.set_xlabel('User Role', fontsize=11)
        ax.set_ylabel('Unique Devices', fontsize=11)
        ax.set_title('Devices by Role', fontsize=12, fontweight='bold')
        for bar, val in zip(bars, role_devices.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                   str(val), ha='center', va='bottom', fontsize=10)
        plt.tight_layout()
        st.pyplot(fig)


def render_device_management(df):
    """Render device management section"""
    st.subheader("📱 Device Management")
    
    # Device registry
    device_stats = df.groupby('mac_address').agg({
        'username': 'nunique',
        'login_status': lambda x: (x == 'success').sum(),
        'user_role': 'first',
        'os': lambda x: x.mode().iloc[0] if not x.mode().empty else 'Unknown',
        'source_ip': 'first'
    }).reset_index()
    
    device_stats.columns = ['MAC Address', 'Unique Users', 'Successful Logins', 'Role', 'OS', 'IP Address']
    device_stats['Total Attempts'] = df.groupby('mac_address').size().values
    device_stats['Success Rate'] = (device_stats['Successful Logins'] / device_stats['Total Attempts'] * 100).round(1)
    
    # Display devices
    col1, col2 = st.columns([3, 1])
    
    with col1:
        st.dataframe(
            device_stats,
            use_container_width=True,
            hide_index=True
        )
    
    with col2:
        st.markdown("### Device Summary")
        st.metric("Total Devices", len(device_stats))
        st.metric("Most Active Role", device_stats.groupby('Role')['Total Attempts'].sum().idxmax())
    
    # OS Distribution
    col1, col2 = st.columns(2)
    
    with col1:
        os_counts = df['os'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = plt.cm.Set3(np.linspace(0, 1, len(os_counts)))
        wedges, texts, autotexts = ax.pie(
            os_counts.values, 
            labels=os_counts.index,
            autopct='%1.1f%%',
            colors=colors,
            startangle=90
        )
        ax.set_title('OS Distribution', fontsize=12, fontweight='bold')
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Failed login devices
        failed_devices = df[df['login_status'] == 'failed'].groupby('mac_address').size().sort_values(ascending=False).head(10)
        if not failed_devices.empty:
            fig, ax = plt.subplots(figsize=(6, 4))
            colors = ['#E74C3C' if v > 5 else '#F39C12' for v in failed_devices.values]
            bars = ax.barh(failed_devices.index, failed_devices.values, color=colors)
            ax.set_xlabel('Failed Attempts', fontsize=11)
            ax.set_title('Top Devices with Failed Logins', fontsize=12, fontweight='bold')
            ax.invert_yaxis()
            plt.tight_layout()
            st.pyplot(fig)
        else:
            st.info("No failed login attempts")


def render_intrusion_detection(df):
    """Render intrusion detection section"""
    st.subheader("🚨 Intrusion Detection & Security")
    
    from core.access_control import IntrusionDetectionSystem
    
    ids = IntrusionDetectionSystem(df)
    
    # Run detection
    brute_force = ids.detect_brute_force(threshold=3)
    port_scan = ids.detect_port_scanning(threshold=10)
    cred_stuffing = ids.detect_credential_stuffing(threshold=5)
    mac_spoofing = ids.detect_mac_spoofing()
    
    # Threat summary
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Brute Force Threats", brute_force['total_threats'], 
                  delta="High" if brute_force['total_threats'] > 0 else None,
                  delta_color="inverse")
    with col2:
        st.metric("Port Scans", port_scan['total_threats'],
                  delta="Medium" if port_scan['total_threats'] > 0 else None,
                  delta_color="inverse")
    with col3:
        st.metric("Credential Stuffing", cred_stuffing['total_threats'],
                  delta="High" if cred_stuffing['total_threats'] > 0 else None,
                  delta_color="inverse")
    with col4:
        st.metric("MAC Spoofing", mac_spoofing['total_threats'],
                  delta="Medium" if mac_spoofing['total_threats'] > 0 else None,
                  delta_color="inverse")
    
    # Detailed threats
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔴 Brute Force Attempts")
        if brute_force['suspicious_macs']:
            bf_df = pd.DataFrame([
                {'MAC Address': k, 'Failed Attempts': v} 
                for k, v in brute_force['suspicious_macs'].items()
            ])
            st.dataframe(bf_df, use_container_width=True, hide_index=True)
        else:
            st.success("No brute force attempts detected")
        
        if brute_force['suspicious_users']:
            st.markdown("**Suspicious Users:**")
            for user, count in brute_force['suspicious_users'].items():
                st.warning(f"  ⚠️ {user}: {count} failed attempts")
    
    with col2:
        st.markdown("#### 🟡 Port Scanning Activity")
        if port_scan['suspicious_ips']:
            ps_df = pd.DataFrame([
                {'Source IP': k, 'Unique Ports': v}
                for k, v in port_scan['suspicious_ips'].items()
            ])
            st.dataframe(ps_df, use_container_width=True, hide_index=True)
        else:
            st.success("No port scanning detected")
    
    # Time-based anomaly detection
    st.markdown("#### 🔵 Time-Based Anomalies")
    roles = df['user_role'].unique()
    anomaly_data = []
    
    for role in roles:
        anomaly = ids.detect_time_based_anomaly(role)
        time_windows = {'faculty': '0-23', 'student': '8-18', 'guest': '10-16'}
        if anomaly['total_threats'] > 0:
            anomaly_data.append({
                'Role': role,
                'Anomalies': anomaly['total_threats'],
                'Time Window': time_windows.get(role, 'N/A')
            })
    
    if anomaly_data:
        st.dataframe(pd.DataFrame(anomaly_data), use_container_width=True, hide_index=True)
    else:
        st.success("No time-based anomalies detected - all access within allowed time windows")
    
    # Generate threat report
    st.markdown("#### 📋 Comprehensive Threat Report")
    threat_report = ids.generate_threat_report()
    if not threat_report.empty:
        # Color by severity
        def severity_color(sev):
            return '🔴' if sev == 'HIGH' else '🟡'
        
        threat_report['Severity'] = threat_report['Severity'].apply(severity_color)
        st.dataframe(threat_report, use_container_width=True, hide_index=True)
    else:
        st.info("No threats detected")


def render_access_rules(df):
    """Render access rules section"""
    st.subheader("🔐 Access Control Policies")
    
    from core.access_control import AccessRuleEngine
    
    rule_engine = AccessRuleEngine()
    policy_summary = rule_engine.get_role_summary()
    
    # Display policies
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### Role-Based Access Policies")
        st.dataframe(policy_summary, use_container_width=True, hide_index=True)
    
    with col2:
        st.markdown("#### Policy Summary")
        st.metric("Total Roles", len(policy_summary))
        faculty_policy = policy_summary[policy_summary['role'] == 'faculty']
        if not faculty_policy.empty:
            st.info(f"Faculty: {faculty_policy.iloc[0]['start_hour']}:00 - {faculty_policy.iloc[0]['end_hour']}:00")
    
    # Evaluate access
    st.markdown("#### 🔍 Access Decision Analysis")
    
    df_eval = df.head(100).copy()
    df_eval['access_decision'] = df_eval.apply(lambda row: rule_engine.evaluate_access(row), axis=1)
    
    decision_counts = df_eval['access_decision'].value_counts()
    
    col1, col2 = st.columns(2)
    
    with col1:
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = ['#2ECC71' if 'GRANTED' in str(x) else '#E74C3C' for x in decision_counts.index]
        bars = ax.barh(range(len(decision_counts)), decision_counts.values, color=colors)
        ax.set_yticks(range(len(decision_counts)))
        ax.set_yticklabels([str(x)[:40] + '...' if len(str(x)) > 40 else str(x) for x in decision_counts.index])
        ax.set_xlabel('Count', fontsize=11)
        ax.set_title('Access Decisions', fontsize=12, fontweight='bold')
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Time violation analysis
        time_violations = df_eval[df_eval['access_decision'].str.contains('Time restriction', na=False)]
        if not time_violations.empty:
            st.warning(f"Found {len(time_violations)} time-based violations in sample")
            st.dataframe(time_violations[['username', 'user_role', 'timestamp', 'access_decision']], 
                        use_container_width=True, hide_index=True)
        else:
            st.success("No time-based violations in sample")


def render_network_traffic(df):
    """Render network traffic analysis"""
    st.subheader("🌐 Network Traffic Analysis")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # Protocol distribution
        protocol_counts = df['protocol'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 5))
        colors = ['#3498DB', '#E74C3C', '#2ECC71', '#F39C12']
        bars = ax.bar(protocol_counts.index, protocol_counts.values, color=colors[:len(protocol_counts)])
        ax.set_xlabel('Protocol', fontsize=11)
        ax.set_ylabel('Count', fontsize=11)
        ax.set_title('Protocol Distribution', fontsize=12, fontweight='bold')
        for bar, val in zip(bars, protocol_counts.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10, 
                   str(val), ha='center', va='bottom', fontsize=10)
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Auth method distribution
        auth_counts = df['auth_method'].value_counts().head(8)
        fig, ax = plt.subplots(figsize=(6, 5))
        colors = plt.cm.Set2(np.linspace(0, 1, len(auth_counts)))
        bars = ax.barh(auth_counts.index, auth_counts.values, color=colors)
        ax.set_xlabel('Count', fontsize=11)
        ax.set_title('Authentication Methods', fontsize=12, fontweight='bold')
        ax.invert_yaxis()
        plt.tight_layout()
        st.pyplot(fig)
    
    # Top source IPs
    col1, col2 = st.columns(2)
    
    with col1:
        top_ips = df['source_ip'].value_counts().head(10)
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = ['#9B59B6' if v > 100 else '#3498DB' for v in top_ips.values]
        bars = ax.barh(top_ips.index, top_ips.values, color=colors)
        ax.set_xlabel('Connection Count', fontsize=11)
        ax.set_title('Top Source IPs', fontsize=12, fontweight='bold')
        ax.invert_yaxis()
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Destination port analysis
        top_ports = df['destination_port'].value_counts().head(10)
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = ['#E74C3C' if p in [22, 23, 3389] else '#3498DB' for p in top_ports.index]
        bars = ax.bar(top_ports.index.astype(str), top_ports.values, color=colors)
        ax.set_xlabel('Port', fontsize=11)
        ax.set_ylabel('Count', fontsize=11)
        ax.set_title('Top Destination Ports', fontsize=12, fontweight='bold')
        plt.tight_layout()
        st.pyplot(fig)


def render_auth_protocols(df):
    """Render RADIUS/LDAP authentication details"""
    st.subheader("🔐 RADIUS & LDAP Authentication")
    
    col1, col2 = st.columns(2)
    
    with col1:
        # RADIUS attributes
        radius_df = df[df['auth_protocol'] == 'RADIUS']
        if not radius_df.empty:
            st.markdown("#### RADIUS Session Details")
            radius_cols = ['username', 'mac_address', 'radius_acct_session_id', 'radius_nas_ip', 
                         'radius_service_type', 'session_timeout']
            available_cols = [c for c in radius_cols if c in radius_df.columns]
            if available_cols:
                st.dataframe(radius_df[available_cols].head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No RADIUS authentication data")
    
    with col2:
        # LDAP attributes
        ldap_df = df[df['auth_protocol'] == 'LDAP']
        if not ldap_df.empty:
            st.markdown("#### LDAP Bind Details")
            ldap_cols = ['username', 'ldap_bind_dn', 'ldap_search_base', 'ldap_filter', 
                        'ldap_result_code', 'ldap_result_message']
            available_cols = [c for c in ldap_cols if c in ldap_df.columns]
            if available_cols:
                st.dataframe(ldap_df[available_cols].head(10), use_container_width=True, hide_index=True)
        else:
            st.info("No LDAP authentication data")
    
    # Auth protocol comparison
    col1, col2 = st.columns(2)
    
    with col1:
        auth_protocol_counts = df['auth_protocol'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = ['#2ECC71', '#3498DB', '#F39C12', '#E74C3C']
        wedges, texts, autotexts = ax.pie(
            auth_protocol_counts.values,
            labels=auth_protocol_counts.index,
            autopct='%1.1f%%',
            colors=colors[:len(auth_protocol_counts)],
            startangle=90
        )
        ax.set_title('Auth Protocol Distribution', fontsize=12, fontweight='bold')
        plt.tight_layout()
        st.pyplot(fig)
    
    with col2:
        # Success rate by auth protocol
        protocol_success = df.groupby('auth_protocol')['login_status'].apply(
            lambda x: (x == 'success').sum() / len(x) * 100
        )
        fig, ax = plt.subplots(figsize=(6, 4))
        colors = ['#2ECC71' if v > 70 else '#F39C12' if v > 50 else '#E74C3C' for v in protocol_success.values]
        bars = ax.bar(protocol_success.index, protocol_success.values, color=colors)
        ax.set_xlabel('Auth Protocol', fontsize=11)
        ax.set_ylabel('Success Rate (%)', fontsize=11)
        ax.set_title('Success Rate by Auth Protocol', fontsize=12, fontweight='bold')
        ax.set_ylim(0, 100)
        for bar, val in zip(bars, protocol_success.values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2, 
                   f'{val:.1f}%', ha='center', va='bottom', fontsize=10)
        plt.tight_layout()
        st.pyplot(fig)


def render_raw_data(df):
    """Render raw data table"""
    st.subheader("📊 Raw Authentication Data")
    
    # Show sample data with styling
    display_df = df[['timestamp', 'username', 'mac_address', 'user_role', 
                    'login_status', 'source_ip', 'protocol', 'auth_method']].copy()
    
    # Add filters
    rows_to_show = st.slider("Rows to display", 10, 100, 25)
    
    # Apply status styling
    styled = display_df.head(rows_to_show).style.applymap(style_success_fail, subset=['login_status'])
    st.dataframe(styled, use_container_width=True, hide_index=True)
    
    # Download button
    csv = df.to_csv(index=False)
    st.download_button(
        label="📥 Download Full Data",
        data=csv,
        file_name="auth_logs_export.csv",
        mime="text/csv"
    )


def main():
    """Main dashboard function"""
    # Load data
    df = load_data()
    
    if df is None:
        st.error("Failed to load data. Please generate data first using: python generate_data.py")
        return
    
    # Header
    st.title("🛡️ Smart Campus Network Access Control Dashboard")
    st.markdown("---")
    
    # Render sidebar and get filtered data
    filtered_df = render_sidebar(df)
    
    # Main content - render based on sidebar selection
    page = st.radio(
        "Select Dashboard View",
        ["Overview", "Login Analytics", "Device Management", "Intrusion Detection", 
         "Access Rules", "Network Traffic", "Auth Protocols", "Raw Data"],
        horizontal=True
    )
    
    st.markdown("---")
    
    # Render KPIs at top for all pages
    render_kpi_metrics(filtered_df)
    st.markdown("---")
    
    # Render selected page
    if page == "Overview":
        render_login_trends(filtered_df)
        render_role_analysis(filtered_df)
    
    elif page == "Login Analytics":
        render_login_trends(filtered_df)
        render_role_analysis(filtered_df)
    
    elif page == "Device Management":
        render_device_management(filtered_df)
    
    elif page == "Intrusion Detection":
        render_intrusion_detection(filtered_df)
    
    elif page == "Access Rules":
        render_access_rules(filtered_df)
    
    elif page == "Network Traffic":
        render_network_traffic(filtered_df)
    
    elif page == "Auth Protocols":
        render_auth_protocols(filtered_df)
    
    elif page == "Raw Data":
        render_raw_data(filtered_df)
    
    # Footer
    st.markdown("---")
    st.markdown(
        "<div style='text-align: center; color: gray;'>"
        "🛡️ Smart Campus NAC System | Network Security Dashboard"
        "</div>",
        unsafe_allow_html=True
    )


if __name__ == "__main__":
    main()

