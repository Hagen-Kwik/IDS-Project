import threading
import time
from flask import Flask, render_template, jsonify
from scapy.all import sniff, IP, TCP
from datetime import datetime
from collections import defaultdict, deque

app = Flask(__name__)

detected_connections = []
session_history = deque(maxlen=10000)

class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.host_service_pairs = defaultdict(set)  # For tracking host-service pairs
        self.host_stats = defaultdict(lambda: {
            'dst_count': 0, 'srv_count': defaultdict(int), 'srv_diff_host': defaultdict(set),
            'same_src_port_count': defaultdict(int), 'serror_count': 0, 'rerror_count': 0
        })
        self.window_time = 2  # 2-second window for temporal features

    def _get_session_key(self, pkt):
        return (
            pkt[IP].src,
            pkt[IP].dst,
            pkt[TCP].sport,
            pkt[TCP].dport,
            pkt[IP].proto
        )

    def extract_features(self, pkt, timestamp):
        key = self._get_session_key(pkt)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        dst_port = pkt[TCP].dport
        protocol = pkt[IP].proto

        if key not in self.sessions:
            self.sessions[key] = {
                'start_time': timestamp,
                'src_bytes': 0,
                'dst_bytes': 0,
                'wrong_fragment': 0,
                'urgent': 0,
                'land': 1 if src_ip == dst_ip else 0,
                'count_window': [],
                'srv_count_window': [],
                'flag': pkt.sprintf('%TCP.flags%'),
                'proto': protocol,
                'service': dst_port,
                'connections': 0
            }

        session = self.sessions[key]
        session_duration = time.time() - session['start_time']
        src_bytes = len(pkt[TCP].payload)
        dst_bytes = 0  # Currently only tracking src->dst

        session['src_bytes'] += src_bytes
        session['connections'] += 1

        # Track SYN and RST errors (serror_rate, rerror_rate)
        if 'S' in session['flag'] and 'A' not in session['flag']:
            self.host_stats[src_ip]['serror_count'] += 1  # SYN sent, no ACK
        if 'R' in session['flag']:
            self.host_stats[src_ip]['rerror_count'] += 1  # RST sent

        # Per service and host tracking
        self.host_stats[src_ip]['dst_count'] += 1
        self.host_stats[src_ip]['srv_count'][dst_port] += 1
        self.host_service_pairs[src_ip].add(dst_port)
        
        # Same source port count for destination host
        self.host_stats[dst_ip]['same_src_port_count'][pkt[TCP].sport] += 1
        
        # Track different services to different hosts
        self.host_stats[src_ip]['srv_diff_host'][dst_ip].add(dst_port)

        self.cleanup_sessions(timestamp)
        session_history.append((timestamp, src_ip, dst_ip, dst_port, key))

        # Calculating rates (e.g., error rates)
        same_host = [s for s in session_history if s[1] == src_ip and timestamp - s[0] <= self.window_time]
        count = len(same_host)
        same_srv = [s for s in same_host if s[2] == dst_ip and s[3] == dst_port]
        same_srv_rate = len(same_srv) / count if count > 0 else 0
        diff_srv_rate = 1 - same_srv_rate if count > 0 else 0

        # Calculating destination host features
        dst_host_same_srv_rate = self.host_stats[dst_ip]['srv_count'][dst_port] / self.host_stats[dst_ip]['dst_count']
        dst_host_diff_srv_rate = len(self.host_stats[dst_ip]['srv_count']) / self.host_stats[dst_ip]['dst_count']
        dst_host_same_src_port_rate = self.host_stats[dst_ip]['same_src_port_count'][pkt[TCP].sport] / self.host_stats[dst_ip]['dst_count']

        return {
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
            'count': count,
            'srv_count': len(self.host_service_pairs[src_ip]),
            'serror_rate': self.host_stats[src_ip]['serror_count'] / count if count > 0 else 0,
            'srv_serror_rate': self.host_stats[src_ip]['serror_count'] / len(self.host_service_pairs[src_ip]) if len(self.host_service_pairs[src_ip]) > 0 else 0,
            'rerror_rate': self.host_stats[src_ip]['rerror_count'] / count if count > 0 else 0,
            'srv_rerror_rate': self.host_stats[src_ip]['rerror_count'] / len(self.host_service_pairs[src_ip]) if len(self.host_service_pairs[src_ip]) > 0 else 0,
            'same_srv_rate': same_srv_rate,
            'diff_srv_rate': diff_srv_rate,
            'srv_diff_host_rate': len(self.host_stats[src_ip]['srv_diff_host']) / len(self.host_service_pairs[src_ip]) if len(self.host_service_pairs[src_ip]) > 0 else 0,
            'dst_host_count': self.host_stats[dst_ip]['dst_count'],
            'dst_host_srv_count': len(self.host_stats[dst_ip]['srv_count']),
            'dst_host_same_srv_rate': dst_host_same_srv_rate,
            'dst_host_diff_srv_rate': dst_host_diff_srv_rate,
            'dst_host_same_src_port_rate': dst_host_same_src_port_rate,
            'dst_host_srv_diff_host_rate': len(self.host_stats[dst_ip]['srv_diff_host']) / len(self.host_stats[dst_ip]['srv_count']) if len(self.host_stats[dst_ip]['srv_count']) > 0 else 0,
            'dst_host_serror_rate': self.host_stats[dst_ip]['serror_count'] / self.host_stats[dst_ip]['dst_count'],
            'dst_host_srv_serror_rate': self.host_stats[dst_ip]['serror_count'] / len(self.host_stats[dst_ip]['srv_count']),
            'dst_host_rerror_rate': self.host_stats[dst_ip]['rerror_count'] / self.host_stats[dst_ip]['dst_count'],
            'dst_host_srv_rerror_rate': self.host_stats[dst_ip]['rerror_count'] / len(self.host_stats[dst_ip]['srv_count']),
        }

    def cleanup_sessions(self, now):
        to_remove = []
        for k, s in self.sessions.items():
            if now - s['start_time'] > 60:  # 60-second session timeout
                to_remove.append(k)
        for k in to_remove:
            del self.sessions[k]

session_manager = SessionManager()


session_manager = SessionManager()

def packet_callback(packet):
    if IP in packet and TCP in packet:
        now = time.time()
        features = session_manager.extract_features(packet, now)

        print(f"Extracted features: {features}")
        detected_connections.insert(0, features)

        if len(detected_connections) > 1000:
            detected_connections.pop()

def start_sniffing():
    sniff(filter="tcp", prn=packet_callback, store=0,
          iface="Realtek RTL8822CE 802.11ac PCIe Adapter")  # Change interface if needed

sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
sniff_thread.start()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/history')
def history():
    return render_template('detected-attacks.html')

@app.route('/get_connections')
def get_connections():
    return jsonify(detected_connections)

if __name__ == '__main__':
    app.run(debug=True)




# model = pickle.load(open('random_forest_model.pkl', 'rb'))


# @app.route('/predict', methods=['POST'])
# def predict():
#     try:
#         user_data = {
#             'loan_amnt': request.form['loan_amnt'],
#             'term': int(request.form['term']),
#             'int_rate': float(request.form['int_rate']),
#             'installment': float(request.form['installment']),
#             'emp_length': int(request.form['emp_length']),
#             'home_ownership': int(request.form['home_ownership']),
#             'annual_inc': float(request.form['annual_inc']),
#             'verification_status': int(request.form['verification_status']),
#             'dti': float(request.form['dti']),
#             'open_acc': int(request.form['open_acc']),
#             'pub_rec': int(request.form['pub_rec']),
#             'revol_bal': float(request.form['revol_bal']),
#             'revol_util': float(request.form['revol_util']),
#             'total_acc': int(request.form['total_acc']),
#             'application_type': int(request.form['application_type']),
#             'mort_acc': int(request.form['mort_acc']),
#             'pub_rec_bankruptcies': int(request.form['pub_rec_bankruptcies']),
#             'issue_month': int(request.form['issue_month']),
#             'issue_year': int(request.form['issue_year']),
#             'cr_line_month': int(request.form['cr_line_month']),
#             'cr_line_year': int(request.form['cr_line_year']),
#         }

#         data_changed = np.array(list(user_data.values())).reshape(1, -1)
#         prediction = model.predict(data_changed)
#         prediction[0] = 0
#         print(prediction[0])

#         return render_template('predicted.html', data=prediction[0])
#     except Exception as e:
#         print("Error: ${str(e)}")
#         return render_template('website.html', prediction_text=f'Error: {str(e)}')
