import os
import json
import random
import string
import smtplib
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
from dotenv import load_dotenv

load_dotenv()

# Inisialisasi Aplikasi Flask
app = Flask(__name__)
# Kunci rahasia sangat penting untuk keamanan session
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
bcrypt = Bcrypt(app)

# Path ke file JSON untuk menyimpan pengguna
USER_FILE = 'users.json'

# --- Konfigurasi Email untuk OTP ---
# GANTI DENGAN KREDENSIAL EMAIL ANDA
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# Fungsi bantuan untuk memuat dan menyimpan data pengguna dari/ke file JSON
def load_users():
    """Memuat data pengguna dari file JSON."""
    if not os.path.exists(USER_FILE):
        return {}
    with open(USER_FILE, 'r') as f:
        return json.load(f)

def save_users(users):
    """Menyimpan data pengguna ke file JSON."""
    with open(USER_FILE, 'w') as f:
        json.dump(users, f, indent=4)

# Fungsi bantuan untuk menghasilkan dan mengirim OTP
def generate_otp(length=6):
    """Menghasilkan OTP numerik acak."""
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(recipient_email, otp):
    """Mengirim OTP ke email penerima."""
    try:
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        
        subject = 'Kode OTP Anda'
        body = f'Ini adalah kode OTP Anda: {otp}\nJangan bagikan kode ini kepada siapa pun.'
        message = f'Subject: {subject}\n\n{body}'
        
        server.sendmail(SENDER_EMAIL, recipient_email, message)
        server.quit()
        print(f"OTP berhasil dikirim ke {recipient_email}")
        return True
    except Exception as e:
        print(f"Gagal mengirim email: {e}")
        return False

# --- Rute Aplikasi ---

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

        # Hash password menggunakan bcrypt
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

        # Cek apakah pengguna ada dan password cocok
        if user_data and bcrypt.check_password_hash(user_data['password'], password):
            # Jika login berhasil, buat dan kirim OTP
            otp = generate_otp()
            if send_otp_email(username, otp):
                session['otp'] = otp
                session['otp_user'] = username # Simpan username untuk diverifikasi
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
            # Hapus data OTP dari session setelah berhasil
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
        # Hash password baru
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

if __name__ == '__main__':
    app.run(debug=True)