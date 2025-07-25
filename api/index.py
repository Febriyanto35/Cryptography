import os
import psycopg2
from dotenv import load_dotenv

load_dotenv()

from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import random
import string
import smtplib

# --- Path dan Inisialisasi Aplikasi ---
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates'))

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
DATABASE_URL = os.environ.get('POSTGRES_URL') 

bcrypt = Bcrypt(app)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587

# --- Fungsi Database ---
def get_db_connection():
    """Membuat koneksi ke database."""
    conn = psycopg2.connect(DATABASE_URL)
    return conn

# --- Fungsi Pengiriman Email ---
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

# --- Rute Aplikasi ---
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                "INSERT INTO users (email, password_hash) VALUES (%s, %s)",
                (email, hashed_password)
            )
            conn.commit()
            flash('Registrasi berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
        except psycopg2.IntegrityError:
            # Error ini terjadi jika email sudah ada (karena constraint UNIQUE)
            flash('Email sudah terdaftar. Silakan gunakan email lain.', 'danger')
            return redirect(url_for('register'))
        finally:
            cur.close()
            conn.close()
            
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT password_hash FROM users WHERE email = %s", (email,))
        user_record = cur.fetchone()
        cur.close()
        conn.close()
        
        if user_record and bcrypt.check_password_hash(user_record[0], password):
            otp = generate_otp()
            if send_otp_email(email, otp):
                session['otp'] = otp
                session['otp_user'] = email
                flash('Login berhasil. Kode OTP telah dikirim ke email Anda.', 'info')
                return redirect(url_for('verify_otp'))
            else:
                flash('Gagal mengirim kode OTP. Silakan coba lagi.', 'danger')
        else:
            flash('Login gagal. Periksa kembali email dan password Anda.', 'danger')
            
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
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        email = session['username']
        
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET password_hash = %s WHERE email = %s",
            (hashed_password, email)
        )
        conn.commit()
        cur.close()
        conn.close()
        
        flash('Password berhasil diubah!', 'success')
        return redirect(url_for('dashboard'))
        
    return render_template('change_password.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah berhasil logout.', 'info')
    return redirect(url_for('login'))
