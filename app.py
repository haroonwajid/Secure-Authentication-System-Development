from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from config import Config
import jwt
import datetime
from functools import wraps
from otp_handler import generate_otp, send_otp_email, send_verification_email
from itsdangerous import URLSafeTimedSerializer
import os
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
import random
from sqlalchemy import select
from datetime import datetime, timezone, timedelta
from flask import current_app

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class OTPForm(FlaskForm):
    otp = StringField('OTP', validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField('Verify OTP')

class RockPaperScissorsForm(FlaskForm):
    rock = SubmitField('Rock')
    paper = SubmitField('Paper')
    scissors = SubmitField('Scissors')

app = Flask(__name__)
app.config.from_object(Config)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
limiter = Limiter(app, key_func=get_remote_address)
csrf = CSRFProtect(app)

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    otp = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    is_verified = db.Column(db.Boolean, default=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(id=data['user_id']).first()
        except:
            return redirect(url_for('login'))
        return f(current_user, *args, **kwargs)
    return decorated

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        
        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.is_verified:
                flash('Username or email already exists', 'error')
            else:
                # Resend verification email
                token = s.dumps(email, salt='email-confirm')
                confirm_url = url_for('verify_email', token=token, _external=True)
                send_verification_email(email, confirm_url)
                flash('A new verification email has been sent. Please check your inbox.', 'info')
            return redirect(url_for('login'))
        
        # New user registration process
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, is_verified=False)
        db.session.add(new_user)
        db.session.commit()
        
        token = s.dumps(email, salt='email-confirm')
        confirm_url = url_for('verify_email', token=token, _external=True)
        send_verification_email(email, confirm_url)
        flash('A verification email has been sent. Please check your inbox.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/verify_email/<token>')
def verify_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('login'))
    
    user = User.query.filter_by(email=email).first()
    if user.is_verified:
        flash('Account already verified. Please login.', 'success')
    else:
        user.is_verified = True
        db.session.commit()
        flash('Thank you for verifying your email address!', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            if not user.is_verified:
                flash('Please verify your email before logging in.', 'danger')
                return redirect(url_for('login'))
            
            otp = generate_otp()
            user.otp = otp
            user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
            db.session.commit()
            
            send_otp_email(user.email, otp)
            
            session['user_id'] = user.id
            return redirect(url_for('otp_verification'))
        else:
            flash('Login unsuccessful. Please check your username and password.', 'danger')
    
    return render_template('login.html', form=form)

@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    form = OTPForm()
    user = db.session.execute(select(User).filter_by(id=session['user_id'])).scalar_one_or_none()
    
    if form.validate_on_submit():
        entered_otp = form.otp.data
        current_time = datetime.now(timezone.utc)
        
        # Convert user.otp_expiry to timezone-aware if it's naive
        otp_expiry = user.otp_expiry.replace(tzinfo=timezone.utc) if user.otp_expiry.tzinfo is None else user.otp_expiry
        
        if user.otp == entered_otp and otp_expiry > current_time:
            token = jwt.encode({
                'user_id': user.id,
                'exp': current_time + timedelta(hours=1)
            }, current_app.config['SECRET_KEY'], algorithm="HS256")
            
            session['token'] = token
            user.otp = None
            user.otp_expiry = None
            db.session.commit()
            
            flash('You have been logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP or OTP expired. Please try again.', 'danger')
            return redirect(url_for('login'))
    
    return render_template('otp_verification.html', form=form)

@app.route('/resend_otp')
@limiter.limit("3 per minute")
def resend_otp():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    otp = generate_otp()
    user.otp = otp
    user.otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=5)
    db.session.commit()
    
    send_otp_email(user.email, otp)
    
    flash('A new OTP has been sent to your email.', 'success')
    return redirect(url_for('otp_verification'))

@app.route('/dashboard')
@token_required
def dashboard(current_user):
    return render_template('dashboard.html', username=current_user.username)

@app.route('/rock_paper_scissors', methods=['GET', 'POST'])
@token_required
def rock_paper_scissors(current_user):
    if request.method == 'GET':
        return render_template('rock_paper_scissors.html', username=current_user.username)
    
    current_app.logger.info(f"Received data: {request.get_data()}")
    data = request.get_json()
    current_app.logger.info(f"Parsed JSON: {data}")
    
    if not data or 'choice' not in data:
        current_app.logger.error("Invalid request data")
        return jsonify({'error': 'Invalid request data'}), 400
    
    user_choice = data['choice'].lower()
    if user_choice not in ['rock', 'paper', 'scissors']:
        current_app.logger.error(f"Invalid choice: {user_choice}")
        return jsonify({'error': 'Invalid choice'}), 400
    
    computer_choice = random.choice(['rock', 'paper', 'scissors'])
    
    result = determine_winner(user_choice, computer_choice)
    
    response_data = {
        'user_choice': user_choice,
        'computer_choice': computer_choice,
        'result': result
    }
    current_app.logger.info(f"Sending response: {response_data}")
    return jsonify(response_data)

def determine_winner(user_choice, computer_choice):
    if user_choice == computer_choice:
        return 'Tie'
    elif (
        (user_choice == 'rock' and computer_choice == 'scissors') or
        (user_choice == 'paper' and computer_choice == 'rock') or
        (user_choice == 'scissors' and computer_choice == 'paper')
    ):
        return 'You win!'
    else:
        return 'Computer wins!'

@app.route('/logout')
@token_required
def logout(current_user):
    session.pop('token', None)
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

@app.route('/snake_game')
@token_required
def snake_game(current_user):
    return render_template('snake_game.html', username=current_user.username)

# Print the current working directory and template folder path
print("Current working directory:", os.getcwd())
print("Template folder path:", app.template_folder)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
