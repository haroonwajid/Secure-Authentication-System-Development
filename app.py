from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
#users db to store the names and credeitnals in database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)          

# Define User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)

# Create the database
with app.app_context():
    db.create_all()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Check if the user already exists
        user_exists = User.query.filter_by(email=email).first()
        if user_exists:
            # Redirect to a page indicating the user is already registered
            return render_template('register_failed.html', message="You are already registered, please login.")

        # Create a new user and store in the database
        new_user = User(username=username, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to the registration success page
        return redirect(url_for('register_success'))

    return render_template('register.html')

@app.route('/register_success')
def register_success():
    return render_template('register_success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user in the database
        user = User.query.filter_by(username=username).first()

        # Check if the user exists and if the password is correct
        if user and bcrypt.check_password_hash(user.password, password):
            return redirect(url_for('home'))
        else:
            # Render login_failed.html if the login fails
            return render_template('login_failed.html', message="Login failed! Please check your credentials and try again.")

    return render_template('login.html')

if __name__ == '__main__':
    app.run(debug=True)
