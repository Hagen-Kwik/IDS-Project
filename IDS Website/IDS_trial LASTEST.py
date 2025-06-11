from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import threading
import time
from collections import deque
from scapy.layers.http import HTTPRequest, HTTPResponse
from urllib.parse import unquote
import pickle
import numpy as np
import warnings
warnings.filterwarnings("ignore", category=UserWarning)

app = Flask(__name__)
socketio = SocketIO(app)

VULNERABLE_WEBSITE_IP = '192.168.1.11'
recent_packets = deque(maxlen=1000)

SERVICE_MAP = {
    ('tcp', 20):   'ftp_data',    ('tcp', 21):   'ftp',        ('tcp', 22):   'ssh',
    ('tcp', 23):   'telnet',      ('tcp', 25):   'smtp',       ('tcp', 37):   'time',
    ('udp', 37):   'time',        ('tcp', 43):   'whois',      ('tcp', 53):   'domain',
    ('udp', 53):   'domain_u',    ('tcp', 70):   'gopher',     ('tcp', 79):   'finger',
    ('tcp', 80):   'http',        ('tcp', 101):  'hostnames',  ('tcp', 102):  'iso_tsap',
    ('tcp', 105):  'csnet_ns',    ('tcp', 109):  'pop_2',      ('tcp', 110):  'pop_3',
    ('tcp', 111):  'sunrpc',      ('tcp', 115):  'efs',        ('udp', 79):   'finger',
    ('tcp', 117):  'uucp_path',   ('tcp', 119):  'nntp',       ('udp', 123):  'ntp_u',
    ('tcp', 137):  'netbios_ns',  ('tcp', 138):  'netbios_dgm', ('tcp', 139):  'netbios_ssn',
    ('tcp', 143):  'imap4',       ('tcp', 179):  'bgp',        ('tcp', 389):  'ldap',
    ('tcp', 443):  'http_443',    ('tcp', 512):  'exec',       ('tcp', 513):  'login',
    ('tcp', 514):  'shell',       ('tcp', 515):  'printer',    ('tcp', 530):  'courier',
    ('tcp', 543):  'klogin',      ('tcp', 544):  'kshell',     ('tcp', 95):   'supdup',
    ('tcp', 15):   'netstat',     ('tcp', 7):    'echo',       ('udp', 7):    'echo',
    ('tcp', 9):    'discard',     ('udp', 9):    'discard',    ('tcp', 11):   'systat',
    ('tcp', 13):   'daytime',     ('udp', 13):   'daytime',    ('tcp', 77):   'rje',
    ('tcp', 113):  'auth',        ('tcp', 59):  'private',     ('tcp', 84):  'ctf',
    ('tcp', 540):  'uucp',        ('tcp', 175):  'vmnet',      ('tcp', 28):  'link',
    ('tcp', 433):  'nnsp',        ('tcp', 57):  'mtp',         ('tcp', 194):  'IRC',
    ('tcp', 6000):  'X11',        ('tcp', 133): 'harvest',     ('tcp', 71): 'remote_job',
    ('udp', 42): 'name',          ('tcp', 66): 'sql_net',      ('tcp', 210): 'Z39_50',
}
# ICMP type/code to service
ICMP_MAP = {
    (8, 0):  'eco_i',
    (0, 0):  'ecr_i',
    (3, 1):  'urh_i',
    (3, 3):  'urp_i',
    (13, 0): 'tim_i',
    (14, 0): 'efs'
}

def determine_kdd_flag(tcp_flags):
    """
    Convert TCP flags to KDD-99 standard flag labels
    Returns one of: 'SF', 'S0', 'REJ', 'RSTO', 'RSTR', 'SH', 'OTH'
    """
    if isinstance(tcp_flags, str):  # Already in flag format
        return tcp_flags if tcp_flags in ['SF','S0','REJ','RSTO','RSTR','SH','OTH'] else 'OTH'
    
    # Handle dictionary format
    s = tcp_flags.get('S', 0)
    a = tcp_flags.get('A', 0)
    r = tcp_flags.get('R', 0)
    f = tcp_flags.get('F', 0)

    if s and a and not r: return 'SF'     # Normal established connection
    elif s and not a: return 'S0'         # Connection attempt
    elif s and r: return 'REJ'            # Rejected connection
    elif a and r: return 'RSTR'           # Reset by responder
    elif s and a and f: return 'RSTO'     # Reset by originator
    elif s and f: return 'SH'             # SYN to honeypot
    else: return 'OTH'                    # Other cases

# Store session and feature data
sessions = {}
user_stats = {}
detected_connections = []

with open('anomaly_model.pkl', 'rb') as am:
    anomaly_model = pickle.load(am)
with open('scaler.pkl', 'rb') as s:
    feature_scaler = pickle.load(s)
with open('le_service.pkl', 'rb') as se:
    service_encoder = pickle.load(se)
with open('le_protocol.pkl', 'rb') as pe:
    protocol_encoder = pickle.load(pe)
with open('le_flag.pkl', 'rb') as fe:
    flag_encoder = pickle.load(fe)
with open('threshold.pkl', 'rb') as t:
    THRESHOLD = pickle.load(t)


# ── NEW ── Define the exact feature order your model expects
FEATURE_ORDER = [
    'duration', 'protocol_type', 'service', 'flag',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent',
    'hot', 'num_failed_logins', 'num_compromised',
    'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'is_guest_login', 'count', 'srv_count',
    'serror_rate', 'rerror_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_src_port_rate',
]


def parse_behavior_log(cookie_header=None):
    # Only parse cookie-based behavior logs
    if cookie_header:
        # Handle different types of cookie_header (bytes, list, str)
        if isinstance(cookie_header, bytes):
            # Decode bytes to string
            ch = cookie_header.decode('utf-8', errors='ignore')
        elif isinstance(cookie_header, list):
            # Decode each part if it's bytes and join with ';'
            decoded_parts = []
            for part in cookie_header:
                if isinstance(part, bytes):
                    decoded_part = part.decode('utf-8', errors='ignore')
                else:
                    decoded_part = str(part)
                decoded_parts.append(decoded_part)
            ch = ';'.join(decoded_parts)
        else:
            # Convert to string if it's not bytes or list
            ch = str(cookie_header)

        # Split into individual cookie parts
        for part in ch.split(';'):
            part = part.strip()
            if part.startswith('X-Behavior-Log='):
                # Extract the value part
                val_part = part[len('X-Behavior-Log='):].strip()
                # Remove surrounding quotes
                val = val_part.strip('"')
                # URL-decode the value
                decoded = unquote(val)
                # Split into components and strip whitespace
                parts = [p.strip() for p in decoded.split('|')]
                if len(parts) == 4:
                    ts, ev, ip, det = parts
                    return {
                        'timestamp': ts,
                        'event':     ev,
                        'ip':        ip,
                        'details':   det
                    }
    return None

with open('anomaly_model.pkl', 'rb') as am:
    anomaly_model = pickle.load(am)
with open('scaler.pkl', 'rb') as s:
    feature_scaler = pickle.load(s)
with open('le_service.pkl', 'rb') as se:
    service_encoder = pickle.load(se)
with open('le_protocol.pkl', 'rb') as pe:
    protocol_encoder = pickle.load(pe)
with open('le_flag.pkl', 'rb') as fe:
    flag_encoder = pickle.load(fe)
with open('threshold.pkl', 'rb') as t:
    THRESHOLD = pickle.load(t)

def safe_divide(a, b):
    return float(a) / b if b else 0.0


def safe_transform(enc, val, fallback):
    try:
        return enc.transform([val])[0]
    except:
        return enc.transform([fallback])[0] if fallback in enc.classes_ else 0


def extract_features(packet, now):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    src_ip, dst_ip = ip_layer.src, ip_layer.dst
    protocol = 'icmp'
    dst_port = 0
    src_port = 0
    cookies = []

    if packet.haslayer(TCP):
        if packet.haslayer(HTTPRequest):
            cookies = packet[HTTPRequest].fields.get('Cookie', [])
        if packet.haslayer(HTTPResponse):
            cookies = packet[HTTPResponse].fields.get('Set-Cookie', [])
        protocol = 'tcp'
        dst_port = packet[TCP].dport
        src_port = packet[TCP].sport
    elif packet.haslayer(UDP):
        protocol = 'udp'
        dst_port = packet[UDP].dport
        src_port = packet[UDP].sport

    # Track connections for rate-based features
    recent_packets.append({
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'src_port': src_port,
        'dst_port': dst_port,
        'protocol': protocol,
        'cookies': cookies,
        'timestamp': now
    })

    # Create session key
    session_key = (src_ip, dst_ip, protocol)
    if session_key not in sessions:
        sessions[session_key] = {
            'start_time': now,
            'src_bytes': 0,
            'dst_bytes': 0,
            'flag_count': {'S': 0, 'A': 0, 'R': 0, 'F': 0},
            'land': int(src_ip == dst_ip),
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_compromised': 0,
        }

    session = sessions[session_key]

    if ip_layer.src == session_key[0]:
        session['src_bytes'] += len(packet)
    else:
        session['dst_bytes'] += len(packet)

    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        for flag_char in str(tcp_flags):
            if flag_char in session['flag_count']:
                session['flag_count'][flag_char] += 1

    log_data = parse_behavior_log(cookies)

    if log_data:
        log_ip = log_data['ip']
        event = log_data['event']
        details = log_data['details']
        print(f"Parsed log → IP: {log_ip}, Event: {event}, Details: {details}")

        # ensure all fields exist
        if log_ip not in user_stats:
            user_stats[log_ip] = {
                'root_shell':        0,
                'num_failed_logins': 0,
                'num_file_creations': 0,
                'num_shells':        0,
                'num_access_files':  0,
                'num_root':          0,
                'is_guest_login':    0,
                'su_attempted':      0,
            }
        stats = user_stats[log_ip]

        if event == 'login_fail':
            stats['num_failed_logins'] += 1
            if 'Guest' in details:
                stats['is_guest_login'] = 1
        elif event == 'root_shell':
            stats['root_shell'] += 1
            stats['num_shells'] += 1
        elif event == 'unauthorized_shell':
            stats['num_shells'] += 1
        elif event == 'file_created':
            stats['num_file_creations'] += 1
        elif event == 'view_log':
            stats['num_access_files'] += 1
        elif event == 'su_attempted':
            stats['su_attempted'] += 1


    # --- Rate-based features calculation DONE---
    window = [c for c in recent_packets if now - c['timestamp'] <= 2.0]
    count = srv_count = dst_host_count = serror = rerror = same_src_port = 0
    srv_diff_host = dst_host_rerror = dst_host_srv_count = 0

    for c in window:
        same_dst = c['dst_ip'] == dst_ip
        same_port = c['dst_port'] == dst_port
        same_src = c['src_port'] == src_port
        flag = c.get('flag')

        if same_dst:
            count += 1
            dst_host_count += 1
            if same_port:
                srv_count += 1
                dst_host_srv_count += 1
            if same_src:
                same_src_port += 1
            if flag == 'S':
                serror += 1
            elif flag == 'R':
                rerror += 1
                dst_host_rerror += 1
        if same_port and not same_dst:
            srv_diff_host += 1

    if protocol == 'icmp' and packet.haslayer(ICMP):
        ic = packet[ICMP]
        svc = ICMP_MAP.get((ic.type, ic.code), 'other')
    else:
        svc = SERVICE_MAP.get((protocol, dst_port), 'other')

    duration = now - sessions[session_key]['start_time']

    features = {
        # basic info
        'src_ip': src_ip,
        'dst_ip': dst_ip,
        'timestamp': datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S'),
        'duration': duration,
        'protocol_type': protocol,
        'service': svc,
        'flag': determine_kdd_flag(session['flag_count']),
        'dst_bytes': session['dst_bytes'],
        'land': session['land'],
        'wrong_fragment': session['wrong_fragment'],
        'urgent': session['urgent'],
        # Security-related
        'hot': session['hot'],
        'num_failed_logins': user_stats.get(src_ip, {}).get('num_failed_logins', 0),
        'num_compromised': session['num_compromised'],
        'root_shell': user_stats.get(src_ip, {}).get('root_shell', 0),
        'su_attempted': user_stats.get(src_ip, {}).get('su_attempted', 0),
        'num_root': user_stats.get(src_ip, {}).get('num_root', 0),
        'num_file_creations': user_stats.get(src_ip, {}).get('num_file_creations', 0),
        'num_shells': user_stats.get(src_ip, {}).get('num_shells', 0),
        'num_access_files': user_stats.get(src_ip, {}).get('num_access_files', 0),
        'is_guest_login': user_stats.get(src_ip, {}).get('is_guest_login', 0),
        # rate related # DONE
        'count': max(count, 1),
        'srv_count': max(srv_count, 1),
        'serror_rate': safe_divide(serror, count),
        'rerror_rate': safe_divide(rerror, count),
        'srv_diff_host_rate': safe_divide(srv_diff_host, srv_count),
        'dst_host_count': dst_host_count,
        'dst_host_srv_count': dst_host_srv_count,
        'dst_host_same_src_port_rate': safe_divide(same_src_port, dst_host_count),
    }

    try:
        vec = []
        for f in FEATURE_ORDER:
            if f == 'protocol_type':
                vec.append(protocol_encoder.transform([features[f]])[0])
            elif f == 'service':
                vec.append(service_encoder.transform([features[f]])[0])
            elif f == 'flag':
                vec.append(safe_transform(flag_encoder, determine_kdd_flag(session['flag_count']), 'OTH'))
            else:
                vec.append(features[f])
        X_array = np.array(vec).reshape(1, -1)

        X_scaled = feature_scaler.transform(X_array)

    except KeyError as e:
        print("FEATURE_ORDER mismatch:", e)
        # fallback: emit without prediction
        detected_connections.insert(0, features)
        if len(detected_connections) > 200:
            detected_connections.pop()
        return features
    except ValueError as e:
        print("ValueError during preprocessing:", e)
        return features

    # Predict anomaly (IsolationForest: -1=anomaly, +1=normal)
    score = -anomaly_model.decision_function(X_scaled)[0]
    features['prediction'] = 'anomaly' if score > 0.12 else 'normal'
    features['anomaly_score'] = float(score)
    features['threshold'] = 0.12

    detected_connections.insert(0, features)

    if len(detected_connections) > 300:
        detected_connections.pop()

    return features


def packet_callback(packet):
    try:
        if not packet.haslayer(IP):
            return
        # Check if packet is to/from the vulnerable server
        if packet[IP].src != VULNERABLE_WEBSITE_IP and packet[IP].dst != VULNERABLE_WEBSITE_IP:
            return

        now = time.time()
        features = extract_features(packet, now)

        if features:
            socketio.emit('vulnerable_traffic', features)

    except Exception as e:
        print(f"Packet processing error: {e}")


def start_sniffing():
    sniff(iface="eth0",
          filter=f"host {VULNERABLE_WEBSITE_IP}", prn=packet_callback, store=0)


@app.route('/')
def dashboard():
    return render_template("index.html")


@app.route('/history')
def history():
    return render_template("detected-attacks.html")


@app.route('/get_connections')
def get_connections():
    def convert_numpy_types(obj):
        if isinstance(obj, (np.integer, np.int64)):
            return int(obj)
        elif isinstance(obj, (np.floating, np.float64)):
            return float(obj)
        return obj

    return jsonify([{k: convert_numpy_types(v)
                   for k, v in conn.items()}
                   for conn in detected_connections])
                   


if __name__ == '__main__':
    threading.Thread(target=start_sniffing, daemon=True).start()
    socketio.run(app, debug=True)
