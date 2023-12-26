import werkzeug.security
from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
import os
import secrets

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'

# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
app.secret_key = secrets.token_hex()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        email = request.form["email"]
        name = request.form["name"]
        password = request.form["password"]

        hashed_password = generate_password_hash(password, salt_length=8)
        user = User.query.filter_by(email=email).first()
        if email == user.email:
            error = 'User already exists. Please check your email.'
            return render_template("login.html", error=error)
        else:
            new_user = User(
                email=email,
                name=name,
                password=hashed_password
            )
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            flash('Registration successfully!', 'success')
            return render_template("secrets.html", name=new_user.name)
    return render_template("register.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                flash('Login successfully!', 'success')
                return redirect(url_for('secrets'))
            else:
                error = 'Incorrect password. Please try again.'
        else:
            error = 'User not found. Please check your email.'
    return render_template("login.html", error=error)


@app.route('/secrets', methods=['GET', 'POST'])
@login_required
def secrets():
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static/files', "cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)
