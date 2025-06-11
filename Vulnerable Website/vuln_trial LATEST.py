from flask import Flask, render_template, request, redirect, url_for, flash, session, make_response
from datetime import datetime

app = Flask(__name__)

users_db = {
    'admin@example.com': {'password': 'admin123', 'is_admin': True},
    'user@example.com': {'password': 'user123', 'is_admin': False},
    'guest@example.com': {'password': 'guest', 'is_admin': False},
    'hot-user@example.com': {'password': 'hot123', 'is_admin': False}
}

def inject_log(response, log_type, ip, details):
    log_data = "{} | {} | {} | {}".format(
        datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log_type, ip, details
    )
    
    # URL-safe encode the log data to ensure it's safe for use in cookies
    safe_log_data = log_data.replace(' ', '%20').replace('|', '%7C')  # Custom encoding
    
    # Add log to Set-Cookie header
    response.set_cookie('X-Behavior-Log', safe_log_data, max_age=60*5)  # Cookie expires in 5 minutes
    
    return response

@app.route('/')
def home():
    resp = make_response(render_template('index.html'))
    return inject_log(resp, 'view_home', request.remote_addr, 'Home page visited')

@app.route('/catalog/<game_name>')
def catalog_details(game_name):
    resp = make_response(render_template('catalog-details-{}.html'.format(game_name)))
    return inject_log(resp, 'catalog_detail', request.remote_addr, 'Game: {}'.format(game_name))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        ip = request.remote_addr

        user = users_db.get(email)
        if user and user['password'] == password:
            session['logged_in'] = True
            session['email'] = email
            session['is_admin'] = user['is_admin']
            session['is_guest'] = not user['is_admin']
            # Determine user type for logging
            user_type = 'Admin' if user['is_admin'] else 'Guest'
            log_message = f'{user_type}: {email}'
            
            resp = make_response(redirect(url_for('dashboard')))
            return inject_log(resp, 'login_success', ip, log_message)
        else:
            flash("Invalid email or password.", "danger")
            resp = make_response(render_template('login.html'))
            return inject_log(resp, 'login_fail', ip, 'wrong')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        ip = request.remote_addr

        if email in users_db:
            flash("Email already registered.", "danger")
            return redirect(url_for('register'))

        users_db[email] = {'password': password, 'is_admin': False}
        flash("Registration successful!", "success")
        resp = make_response(redirect(url_for('login')))
        return inject_log(resp, 'register', ip, 'New user: {}'.format(email))

    return render_template('register.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    resp = make_response(render_template('logged-in.html'))
    return inject_log(resp, 'dashboard_access', request.remote_addr, 'User: {}'.format(session.get("email")))

@app.route('/logout')
def logout():
    ip = request.remote_addr
    email = session.get('email')
    session.clear()
    resp = make_response(redirect(url_for('login')))
    return inject_log(resp, 'logout', ip, 'User: {} logged out'.format(email))

@app.route('/catalog')
def catalog():
    resp = make_response(render_template('shop.html'))
    return inject_log(resp, 'catalog_view', request.remote_addr, 'Catalog page accessed')

@app.route('/root_shell_trigger')
def root_shell_trigger():
    resp = make_response(redirect('/dashboard'))
    return inject_log(resp, 'root_shell', request.remote_addr, 'Root shell triggered')

@app.route('/file_creation_trigger')
def file_creation_trigger():
    resp = make_response(redirect('/dashboard'))
    return inject_log(resp, 'file_created', request.remote_addr, 'File creation triggered')

@app.route('/shell_trigger')
def shell_trigger():
    resp = make_response(redirect('/dashboard'))
    return inject_log(resp, 'unauthorized_shell', request.remote_addr, 'Shell triggered')

@app.route('/access_file_trigger')
def access_file_trigger():
    resp = make_response(redirect('/dashboard'))
    return inject_log(resp, 'view_log', request.remote_addr, 'File access triggered')

@app.route('/su_attempt_trigger')
def su_attempt_trigger():
    resp = make_response(redirect('/dashboard'))
    return inject_log(resp, 'su_attempted', request.remote_addr, 'SU attempt triggered')




@app.after_request
def add_cache_headers(response):
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'public, max-age=3600'
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=False, port=80)
