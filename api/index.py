# Impor pustaka yang diperlukan di bagian atas
import os
from dotenv import load_dotenv

# Panggil fungsi ini untuk memuat variabel dari file .env (hanya untuk lokal)
load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import json
import random
import string
import smtplib

# --- Perbaikan Path untuk Vercel ---
# Tentukan path absolut ke direktori root proyek
# Ini akan membantu Flask menemukan folder 'templates' dengan benar
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Inisialisasi Aplikasi Flask dengan path template yang benar
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))


# --- Konfigurasi Keamanan Menggunakan Environment Variables ---
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'kunci-rahasia-default-lokal')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')

# --- Sisa kode Anda ---
bcrypt = Bcrypt(app)

# Path untuk file users.json, relatif terhadap root proyek
USER_FILE = os.path.join(BASE_DIR, 'users.json')
# Di Vercel, kita hanya bisa menulis ke direktori /tmp
TMP_USER_FILE = '/tmp/users.json'


SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

def load_users():
    """Memuat pengguna dari /tmp jika ada, jika tidak dari file asli (hanya saat pertama kali)."""
    if os.path.exists(TMP_USER_FILE):
        with open(TMP_USER_FILE, 'r') as f:
            return json.load(f)
    elif os.path.exists(USER_FILE):
         with open(USER_FILE, 'r') as f:
            return json.load(f)
    return {}


def save_users(users):
    """Menyimpan data pengguna ke direktori /tmp yang bisa ditulis di Vercel."""
    with open(TMP_USER_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp):
    if not SENDER_EMAIL or not SENDER_PASSWORD:
        print("Error: SENDER_EMAIL atau SENDER_PASSWORD tidak diatur.")
        return False
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        subject = 'Kode OTP Anda'
        body = f'Ini adalah kode OTP Anda: {otp}\nJangan bagikan kode ini kepada siapa pun.'
        message = f'Subject: {subject}\n\n{body}'
        
        server.sendmail(SENDER_EMAIL, recipient_email, message)
        server.quit()
        return True
    except Exception as e:
        print(f"Gagal mengirim email: {e}")
        return False

# --- Rute Aplikasi (tetap sama) ---

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()

        if username in users:
            flash('Username sudah ada. Silakan pilih yang lain.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        
        users[username] = {'password': hashed_password}
        save_users(users)
        
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        user_data = users.get(username)

        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            otp = generate_otp()
            if send_otp_email(username, otp):
                session['otp'] = otp
                session['otp_user'] = username
                flash('Login berhasil. Kode OTP telah dikirim ke email Anda.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                flash('Gagal mengirim kode OTP. Silakan coba lagi.', 'danger')
        else:
            flash('Login gagal. Periksa kembali username dan password Anda.', 'danger')
            
    return render_template('login.html')

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp' not in session or 'otp_user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if entered_otp == session['otp']:
            session['logged_in'] = True
            session['username'] = session['otp_user']
            session.pop('otp', None)
            session.pop('otp_user', None)
            flash('Verifikasi berhasil! Selamat datang.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Kode OTP salah. Silakan coba lagi.', 'danger')
            
    return render_template('verify_otp.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('dashboard.html', username=session.get('username'))

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        username = session['username']
        
        users = load_users()
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        users[username]['password'] = hashed_password
        save_users(users)
        
        flash('Password berhasil diubah!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('login'))

