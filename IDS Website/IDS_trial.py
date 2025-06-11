import threading
import time
from flask_socketio import SocketIO
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP, UDP, ICMP 
from datetime import datetime
from collections import defaultdict, deque

app = Flask(__name__)

detected_connections = []
session_history = deque(maxlen=10000)
socketio = SocketIO(app, async_mode='threading')
VULNERABLE_WEBSITE_IP = "192.168.1.10"  

class SessionManager:
    def __init__(self):
        # Initialize data structures to track network sessions and statistics
        self.sessions = {}  # Stores active sessions with their features
        self.host_service_pairs = defaultdict(set)  # Tracks which services each host connects to
        self.host_stats = defaultdict(lambda: {  # Stores statistics for each host
            'dst_count': 0,  # Total destination count for this host
            'srv_count': defaultdict(int),  # Service count per host
            'srv_diff_host': defaultdict(set),  # Different hosts per service
            'same_src_port_count': defaultdict(int),  # Count of same source ports
            'serror_count': 0,  # SYN error count
            'rerror_count': 0,  # RST error count
            'failed_logins': 0,  # Failed login attempts
            'compromised': 0,  # Potential compromise indicators
            'root_access': 0,  # Root access attempts
            'file_creations': 0,  # File creation operations
            'shells': 0,  # Shell spawns
            'access_files': 0,  # Sensitive file accesses
            'outbound_cmds': 0,  # Outbound commands (e.g., FTP)
            'hot_indicators': 0  # Indicators of high-risk activity
        })
        self.user_stats = defaultdict(lambda: {  # Tracks user-specific behaviors
            'logged_in': 0,  # Login success
            'root_shell': 0,  # Root shell obtained
            'su_attempted': 0,  # SU/sudo attempts
            'is_hot_login': 0,  # From known suspicious IP
            'is_guest_login': 0  # Guest login detected
        })
        self.window_time = 2  # Time window for calculating rates (in seconds)

    def _get_session_key(self, pkt):
        # Creates a unique key for each session based on 5-tuple
        return (
            pkt[IP].src,  # Source IP
            pkt[IP].dst,  # Destination IP
            pkt[TCP].sport,  # Source port
            pkt[TCP].dport,  # Destination port
            pkt[IP].proto  # Protocol
        )

    def _detect_login_attempt(self, payload):
        # Detects login attempts in payload
        payload = payload.lower()
        return (b'login' in payload or b'password' in payload)

    def _detect_failed_login(self, payload):
        # Detects failed login attempts in payload
        payload = payload.lower()
        return (b'fail' in payload and b'login' in payload)

    def _detect_root_access(self, payload):
        # Detects root access attempts in payload
        payload = payload.lower()
        return (b'root' in payload or b'su root' in payload)

    def _detect_file_operations(self, payload):
        # Detects file operations in payload
        payload = payload.lower()
        return (b'mkdir' in payload or b'touch' in payload or b'echo' in payload)

    def safe_divide(self, numerator, denominator):
        # Safe division function to prevent division by zero
        return numerator / denominator if denominator != 0 else 0

    def extract_features(self, pkt, timestamp):
        # Main method that extracts features from each packet
        key = self._get_session_key(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        protocol = pkt[IP].proto
        payload = bytes(pkt[TCP].payload)

        # Initialize new session if this is the first packet
        if key not in self.sessions:
            self.sessions[key] = {
                'start_time': timestamp,
                'src_bytes': 0,
                'dst_bytes': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'land': 1 if src_ip == dst_ip else 0,
                'flag': pkt.sprintf('%TCP.flags%'),
                'proto': protocol,
                'service': dst_port,
                'connections': 0,
                # Security-related features
                'hot': 0,
                'num_failed_logins': 0,
                'num_compromised': 0,
                'num_root': 0,
                'num_file_creations': 0,
                'num_shells': 0,
                'num_access_files': 0,
                'num_outbound_cmds': 0
            }

        session = self.sessions[key]
        session_duration = time.time() - session['start_time']
        src_bytes = len(payload)
        dst_bytes = 0  # Currently only tracking src->dst

        # Update session statistics
        session['src_bytes'] += src_bytes
        session['connections'] += 1

        # Track error flags in TCP
        if 'S' in session['flag'] and 'A' not in session['flag']:
            self.host_stats[src_ip]['serror_count'] += 1
        if 'R' in session['flag']:
            self.host_stats[src_ip]['rerror_count'] += 1

        # Update host statistics
        self.host_stats[src_ip]['dst_count'] += 1
        self.host_stats[src_ip]['srv_count'][dst_port] += 1
        self.host_service_pairs[src_ip].add(dst_port)
        self.host_stats[dst_ip]['same_src_port_count'][pkt[TCP].sport] += 1
        self.host_stats[src_ip]['srv_diff_host'][dst_ip].add(dst_port)

        # Detect security-related events in payload
        if self._detect_login_attempt(payload):
            if self._detect_failed_login(payload):
                session['num_failed_logins'] += 1
                self.host_stats[src_ip]['failed_logins'] += 1
            else:
                self.user_stats[src_ip]['logged_in'] = 1

        if self._detect_root_access(payload):
            session['num_root'] += 1
            self.host_stats[src_ip]['root_access'] += 1
            self.user_stats[src_ip]['su_attempted'] = 1
            if b'root@' in payload.lower():
                self.user_stats[src_ip]['root_shell'] = 1

        if self._detect_file_operations(payload):
            session['num_file_creations'] += 1
            self.host_stats[src_ip]['file_creations'] += 1

        if b'sh' in payload.lower() or b'bash' in payload.lower():
            session['num_shells'] += 1
            self.host_stats[src_ip]['shells'] += 1

        if b'/etc/passwd' in payload or b'/etc/shadow' in payload:
            session['num_access_files'] += 1
            self.host_stats[src_ip]['access_files'] += 1

        if dst_port == 21 and len(payload) > 0:  # FTP
            session['num_outbound_cmds'] += 1
            self.host_stats[src_ip]['outbound_cmds'] += 1

        # Check for high-risk ports
        if dst_port in [22, 3389, 5900]:  # SSH, RDP, VNC
            session['hot'] += 1
            self.host_stats[src_ip]['hot_indicators'] += 1

        if dst_port in [4444, 31337]:  # Common backdoor ports
            session['num_compromised'] += 1
            self.host_stats[src_ip]['compromised'] += 1

        if b'guest' in payload.lower():
            self.user_stats[src_ip]['is_guest_login'] = 1

        # Clean up old sessions
        self.cleanup_sessions(timestamp)
        session_history.append((timestamp, src_ip, dst_ip, dst_port, key))

        # Calculate rates within time window
        same_host = [s for s in session_history if s[1] == src_ip and timestamp - s[0] <= self.window_time]
        count = len(same_host)
        same_srv = [s for s in same_host if s[2] == dst_ip and s[3] == dst_port]
        
        # Use safe division for all rate calculations
        same_srv_rate = self.safe_divide(len(same_srv), count)
        diff_srv_rate = 1 - same_srv_rate if count > 0 else 0

        dst_host_same_srv_rate = self.safe_divide(
            self.host_stats[dst_ip]['srv_count'][dst_port], 
            self.host_stats[dst_ip]['dst_count']
        )
        dst_host_diff_srv_rate = self.safe_divide(
            len(self.host_stats[dst_ip]['srv_count']), 
            self.host_stats[dst_ip]['dst_count']
        )
        dst_host_same_src_port_rate = self.safe_divide(
            self.host_stats[dst_ip]['same_src_port_count'][pkt[TCP].sport], 
            self.host_stats[dst_ip]['dst_count']
        )

        # Build complete feature set
        features = {
            # Basic connection information
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'duration': session_duration,
            'protocol_type': protocol,
            'service': dst_port,
            'flag': session['flag'],
            'src_bytes': session['src_bytes'],
            'dst_bytes': dst_bytes,
            'land': session['land'],
            'wrong_fragment': session['wrong_fragment'],
            'urgent': session['urgent'],
            
            # Rate-based features (all using safe division)
            'count': count,
            'srv_count': len(self.host_service_pairs[src_ip]),
            'serror_rate': self.safe_divide(self.host_stats[src_ip]['serror_count'], count),
            'srv_serror_rate': self.safe_divide(
                self.host_stats[src_ip]['serror_count'], 
                len(self.host_service_pairs[src_ip])
            ),
            'rerror_rate': self.safe_divide(self.host_stats[src_ip]['rerror_count'], count),
            'srv_rerror_rate': self.safe_divide(
                self.host_stats[src_ip]['rerror_count'], 
                len(self.host_service_pairs[src_ip])
            ),
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': self.safe_divide(
                len(self.host_stats[src_ip]['srv_diff_host']), 
                len(self.host_service_pairs[src_ip])
            ),
            'dst_host_count': self.host_stats[dst_ip]['dst_count'],
            'dst_host_srv_count': len(self.host_stats[dst_ip]['srv_count']),
            'dst_host_same_srv_rate': dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
            'dst_host_srv_diff_host_rate': self.safe_divide(
                len(self.host_stats[dst_ip]['srv_diff_host']), 
                len(self.host_stats[dst_ip]['srv_count'])
            ),
            'dst_host_serror_rate': self.safe_divide(
                self.host_stats[dst_ip]['serror_count'], 
                self.host_stats[dst_ip]['dst_count']
            ),
            'dst_host_srv_serror_rate': self.safe_divide(
                self.host_stats[dst_ip]['serror_count'], 
                len(self.host_stats[dst_ip]['srv_count'])
            ),
            'dst_host_rerror_rate': self.safe_divide(
                self.host_stats[dst_ip]['rerror_count'], 
                self.host_stats[dst_ip]['dst_count']
            ),
            'dst_host_srv_rerror_rate': self.safe_divide(
                self.host_stats[dst_ip]['rerror_count'], 
                len(self.host_stats[dst_ip]['srv_count'])
            ),
            
            # Security-related features
            'hot': session['hot'],
            'num_failed_logins': session['num_failed_logins'],
            'logged_in': self.user_stats[src_ip]['logged_in'],
            'num_compromised': session['num_compromised'],
            'root_shell': self.user_stats[src_ip]['root_shell'],
            'su_attempted': self.user_stats[src_ip]['su_attempted'],
            'num_root': session['num_root'],
            'num_file_creations': session['num_file_creations'],
            'num_shells': session['num_shells'],
            'num_access_files': session['num_access_files'],
            'num_outbound_cmds': session['num_outbound_cmds'],
            'is_hot_login': self.user_stats[src_ip]['is_hot_login'],
            'is_guest_login': self.user_stats[src_ip]['is_guest_login'],
            'timestamp': datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Store the connection data
        detected_connections.insert(0, features)
        if len(detected_connections) > 1000:
            detected_connections.pop()

        return features

    def cleanup_sessions(self, now):
        # Remove sessions older than 60 seconds to prevent memory leaks
        to_remove = [k for k, s in self.sessions.items() if now - s['start_time'] > 60]
        for k in to_remove:
            del self.sessions[k]
    
     
session_manager = SessionManager()

def packet_callback(packet):
    try:
        if not packet.haslayer(IP):
            return
            
        # Initialize protocol-specific variables
        protocol = None
        port = 0
        flags = 'N/A'
        payload_size = 0

        
        # Handle each protocol type separately
        if packet.haslayer(TCP):
            protocol = 'tcp'
            port = packet[TCP].dport
            flags = packet.sprintf('%TCP.flags%')
            payload_size = len(packet[TCP].payload)
        elif packet.haslayer(UDP):
            protocol = 'udp'
            port = packet[UDP].dport
            payload_size = len(packet[UDP].payload)
        elif packet.haslayer(ICMP):
            protocol = 'icmp'
            payload_size = len(packet[ICMP].payload)
        else:
            return  # Skip other protocols
            
        # Only process packets targeting our vulnerable website
        if packet[IP].dst == VULNERABLE_WEBSITE_IP:
            now = time.time()
            features = session_manager.extract_features(packet, now)
            
            alert_data = {
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'timestamp': datetime.fromtimestamp(now).strftime('%Y-%m-%d %H:%M:%S'),
                'protocol': protocol,
                'port': port,
                'flags': flags,
                'payload_size': payload_size,
                'features': features
            }
            
            socketio.emit('vulnerable_traffic', alert_data)
            
    except Exception as e:
        print(f"Error processing packet: {str(e)}")
        
        
def start_sniffing():
    sniff(
        iface="eth0",
        filter=f"host {VULNERABLE_WEBSITE_IP}",
        prn=packet_callback,
        store=0,
        promisc=True 
    )

@app.route('/')
def home():
    return render_template('index.html')
    
@app.route('/history')
def history():
    return render_template('detected-attacks.html')

@app.route('/get_connections')
def get_connections():
	return jsonify(detected_connections)

# @socketio.on('connect')
# def handle_connect():
#     print('Client connected')

if __name__ == '__main__':
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    socketio.run(app, debug=True)

