import random
import string
from flask import current_app
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_email(to_email, subject, body):
    sender_email = current_app.config['MAIL_USERNAME']
    sender_password = current_app.config['MAIL_PASSWORD']
    smtp_server = current_app.config['MAIL_SERVER']
    smtp_port = current_app.config['MAIL_PORT']

    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = to_email
    message['Subject'] = subject
    message.attach(MIMEText(body, 'plain'))

    print(f"Attempting to send email to {to_email}")
    print(f"Using SMTP server: {smtp_server}:{smtp_port}")
    print(f"Sender email: {sender_email}")

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            print("Connected to SMTP server")
            server.starttls()
            print("Started TLS")
            server.login(sender_email, sender_password)
            print("Logged in successfully")
            server.send_message(message)
            print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")
        print(f"Error type: {type(e).__name__}")
        raise  # This will re-raise the exception and show the full traceback

def send_otp_email(to_email, otp):
    subject = "Your OTP for Authentication"
    body = f"Your OTP is: {otp}. This OTP is valid for 5 minutes."
    send_email(to_email, subject, body)

def send_verification_email(to_email, confirm_url):
    subject = "Verify Your Email Address"
    body = f"Please click on the following link to verify your email address: {confirm_url}"
    send_email(to_email, subject, body)
