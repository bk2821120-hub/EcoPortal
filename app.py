from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin,
    login_user, login_required,
    logout_user, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import csv
import mimetypes

# Fix MIME types (important for Render)
mimetypes.add_type('text/css', '.css')
mimetypes.add_type('application/javascript', '.js')

# Flask App Config
app = Flask(
    __name__,
    static_folder='static',
    template_folder='templates'
)

app.config['SECRET_KEY'] = 'ecoportal-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Extensions
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# =======================
# DATABASE MODELS
# =======================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

class Issue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    location = db.Column(db.String(100), nullable=False)
    issue_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    date_reported = db.Column(db.DateTime, default=datetime.utcnow)

class ContactMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    message = db.Column(db.Text, nullable=False)
    date_sent = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# =======================
# ROUTES
# =======================

@app.route('/')
def home():
    return render_template('index.html')

# ---------- AUTH ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter(
            (User.username == username) | (User.email == username)
        ).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid login details', 'error')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        full_name = request.form.get('full_name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('User already exists', 'error')
            return redirect(url_for('signup'))

        user = User(
            full_name=full_name,
            email=email,
            username=username,
            password_hash=generate_password_hash(password)
        )

        db.session.add(user)
        db.session.commit()

        save_user_csv(full_name, email, username)

        flash('Account created successfully', 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# ---------- PAGES ----------
@app.route('/news')
def news():
    return render_template('news.html')

@app.route('/climate')
def climate():
    return render_template('climate.html')

@app.route('/pollution')
def pollution():
    return render_template('pollution.html')

@app.route('/wildlife')
def wildlife():
    return render_template('wildlife.html')

# ---------- REPORT ISSUE ----------
@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        issue = Issue(
            user_id=current_user.id,
            location=request.form.get('location'),
            issue_type=request.form.get('issue_type'),
            description=request.form.get('description')
        )
        db.session.add(issue)
        db.session.commit()
        flash('Issue reported successfully', 'success')
        return redirect(url_for('home'))

    return render_template('report.html')

@app.route('/my-reports')
@login_required
def my_reports():
    reports = Issue.query.filter_by(user_id=current_user.id).all()
    return render_template('my_reports.html', reports=reports)

# ---------- CONTACT ----------
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        msg = ContactMessage(
            name=request.form.get('name'),
            email=request.form.get('email'),
            subject=request.form.get('subject'),
            message=request.form.get('message')
        )
        db.session.add(msg)
        db.session.commit()
        flash('Message sent successfully', 'success')
        return redirect(url_for('contact'))

    return render_template('contact.html')

# =======================
# CSV USER RECORD
# =======================

def save_user_csv(full_name, email, username):
    file_exists = os.path.isfile('user_records.csv')
    with open('user_records.csv', 'a', newline='') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(['Full Name', 'Email', 'Username', 'Signup Date'])
        writer.writerow([full_name, email, username, datetime.now()])

# =======================
# RUN APP
# =======================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
