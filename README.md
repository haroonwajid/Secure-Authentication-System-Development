# Secure Authentication System

This project implements a secure login system with two-factor authentication using email and One Time Password (OTP). It's built with Flask and incorporates various security features to enhance user authentication.

## Features

- User registration with email verification
- Secure login with username and password
- Two-factor authentication using email-based OTP
- Session management
- Rate limiting to prevent brute-force attacks
- CSRF protection
- Secure password hashing using bcrypt

## Prerequisites

- Python 3.8 or newer
- pip (Python package manager)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/haroonwajid/Secure-Authentication-System-Development.git
   cd Secure-Authentication-System-Development
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - On Windows:
     ```
     venv\Scripts\activate
     ```
   - On macOS and Linux:
     ```
     source venv/bin/activate
     ```

4. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

5. Set up environment variables:
   Create a `.env` file in the project root and add the following:
   ```
   SECRET_KEY=your_secret_key
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_email_password
   ```
   Replace the values with your actual secret key and email credentials.

## Usage

1. Run the Flask application:
   ```
   python app.py
   ```

2. Open a web browser and navigate to `http://127.0.0.1:5000`

3. Register a new account, verify your email, and log in using the OTP sent to your email.

## Project Structure

- `app.py`: Main application file
- `config.py`: Configuration settings
- `otp_handler.py`: OTP generation and email sending functionality
- `templates/`: HTML templates for the web pages
- `static/`: CSS and other static files

## Security Considerations

- Passwords are hashed using bcrypt before storage
- OTPs expire after 5 minutes
- Rate limiting is implemented to prevent brute-force attacks
- CSRF protection is enabled for all forms
- Email verification is required for new accounts

## Contributers

- Haroon Wajid
- Maryam Noor
- Taha Hassan
- Waleed Noman

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
