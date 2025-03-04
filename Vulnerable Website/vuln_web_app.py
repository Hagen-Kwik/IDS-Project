
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)

app.secret_key = "supersecretkey"  # Needed for flashing messages
# Global variable to store users
users_db = {}
subscribed_emails = []


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/subscribe', methods=['POST'])
def subscribe():
    email = request.form.get('email')
    if email:
        subscribed_emails.append(email)  # Store email in global list
        return "<script>alert('Subscription successful!'); window.location='/';</script>"

    return "<script>alert('Please enter a valid email!'); window.location='/';</script>"


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email exists and password matches
        if email in users_db and users_db[email] == password:
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password. Please try again.", "danger")

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Check if email is already registered
        if email in users_db:
            flash("Email already registered. Please log in.", "danger")
            return redirect(url_for('register'))

        # Store user in global dictionary
        users_db[email] = password
        flash("Registration successful! Please log in.", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/catalog')
def catalog():
    return render_template('shop.html')


@app.route('/dashboard')
def dashboard():
    return render_template('logged-in.html')


@app.route('/logout')
def logout():
    flash("You have been logged out.", "info")
    return redirect(url_for('login'))


@app.route('/catalog/<game_name>')
def catalog_details(game_name):
    return render_template(f'catalog-details-{game_name}.html')


if __name__ == '__main__':
    app.run(debug=True)

app = Flask(__name__)


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
