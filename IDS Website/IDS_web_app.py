import threading
from flask import Flask, render_template, jsonify
from scapy.all import sniff, conf, IP
from datetime import datetime

app = Flask(__name__)

# Global variable to store detected connections
detected_connections = []

def packet_callback(packet):
    """Handles incoming packets and logs detected connections."""
    if IP in packet:
        connection = {
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        print(f"New connection detected: {connection}")
        detected_connections.insert(0, connection)  # Insert at the beginning (newest first)

        # Keep only the last 1000 records to prevent memory issues
        if len(detected_connections) > 1000:
            detected_connections.pop()

def start_sniffing():
    """Starts packet sniffing on a specified network interface."""
    sniff(filter="tcp", prn=packet_callback, store=0,
          iface="Realtek RTL8822CE 802.11ac PCIe Adapter")  # Change to your actual interface

# Run sniffing in a background thread
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
    """API endpoint to fetch detected connections."""
    return jsonify(detected_connections)  # Returns all stored connections

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
