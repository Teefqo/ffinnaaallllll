from flask import Flask, render_template, request, redirect, url_for, session
from utils import hide_data_in_image, extract_hidden_data, detect_hidden_data
import sqlite3, os

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = 'supersecretkey'

def init_db():
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
            password TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return redirect(url_for('login_page'))

@app.route('/home')
def home():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    return render_template('home.html', hide_result=None, extract_result=None, check_result=None)

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect('users.db')
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE email=? AND password=?", (email, password))
        user = cur.fetchone()
        conn.close()
        if user:
            session['logged_in'] = True
            session['user'] = email
            return redirect(url_for('home'))
        else:
            error = 'Invalid login details.'
    return render_template('login.html', error=error)

@app.route('/signup', methods=['GET', 'POST'])
def signup_page():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        # تحقق من تطابق كلمة المرور وتأكيدها
        if password != confirm_password:
            error = 'The password and confirmation password do not match.'
            return render_template('signup.html', error=error)

        try:
            conn = sqlite3.connect('users.db')
            cur = conn.cursor()
            cur.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            conn.commit()
            conn.close()
            return redirect(url_for('login_page'))
        except sqlite3.IntegrityError:
            error = 'The email is already in use.'
            conn.close()
    return render_template('signup.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

@app.route('/hide', methods=['POST'])
def hide():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    image = request.files.get('image')
    message = request.form.get('message')
    if not image or not message:
        return redirect(url_for('home'))
    filename, result = hide_data_in_image(image, message)
    image_url = url_for('static', filename=f'uploads/{filename}')
    return render_template('home.html', hide_result=result, image_url=image_url)

@app.route('/extract', methods=['POST'])
def extract():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    image = request.files.get('image')
    extract_result = extract_hidden_data(image) if image else None
    if extract_result:
        extract_result = extract_result.replace('ÿÿÿÿÿÿÿþ', '')
    return render_template('home.html', extract_result=extract_result)

@app.route('/check', methods=['POST'])
def detect():
    if not session.get('logged_in'):
        return redirect(url_for('login_page'))
    image = request.files.get('image')
    result = detect_hidden_data(image) if image else None
    return render_template('home.html', check_result=result)

if __name__ == '__main__':
    os.makedirs('static', exist_ok=True)
    app.run(debug=True, port=5000)