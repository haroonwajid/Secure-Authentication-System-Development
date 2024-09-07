from flask import Flask, render_template, request, redirect, session, flash
import sqlite3, random, smtplib
from datetime import datetime, timedelta
import bcrypt  # Import bcrypt for hashing
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For secure sessions

# Database Connection Helper
def get_db_connection():
    conn = sqlite3.connect('users.db')
    conn.row_factory = sqlite3.Row
    return conn

# User Registration Route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode to bytes for bcrypt
        email = request.form['email']

        # Hash password with bcrypt and gensalt
        hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

        # Save user to database
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
                  (username, hashed_password, email))
        conn.commit()
        conn.close()

        flash('Registered successfully! Please log in.', 'success')
        return redirect('/login')

    return render_template('register.html')

# User Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')  # Encode password to bytes for bcrypt

        # Verify username and password
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password, user['password']):
            # Generate OTP and send to user's email
            otp = random.randint(100000, 999999)
            otp_expiration = datetime.now() + timedelta(minutes=5)

            # Update OTP and expiration in the database
            conn = get_db_connection()
            c = conn.cursor()
            c.execute('UPDATE users SET otp = ?, otp_expiration = ? WHERE id = ?',
                      (otp, otp_expiration, user['id']))
            conn.commit()
            conn.close()

            # Send OTP via email
            send_otp(user['email'], otp)

            session['user_id'] = user['id']
            return redirect('/otp')

        else:
            flash('Invalid credentials, please try again.', 'danger')

    return render_template('login.html')

# OTP Verification Route
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        otp_input = request.form['otp']

        # Fetch OTP and expiration from the database
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        user = c.fetchone()
        conn.close()

        if user and user['otp'] == otp_input and datetime.now() < datetime.fromisoformat(user['otp_expiration']):
            session['logged_in'] = True
            flash('Logged in successfully!', 'success')
            return redirect('/dashboard')
        else:
            flash('Invalid OTP or OTP expired.', 'danger')

    return render_template('otp.html')

# Dashboard (Protected Route)
@app.route('/dashboard')
def dashboard():
    if 'logged_in' not in session:
        return redirect('/login')
    return 'Welcome to the secure dashboard!'

# Logout Route
@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect('/login')

# Helper function to send OTP email
def send_otp(email, otp):
    # Setup your email server configuration here
    server = smtplib.SMTP_SSL('smtp.your_email_provider.com', 465)
    server.login('your_email@example.com', 'password')
    message = f'Subject: Your OTP Code\n\nYour OTP is {otp}. It will expire in 5 minutes.'
    server.sendmail('your_email@example.com', email, message)
    server.quit()

if __name__ == '__main__':
    app.run(debug=True)
