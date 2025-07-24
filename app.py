from flask import Flask, render_template, request, redirect, session, url_for
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re  # ✅ For regex validations

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'supersecretkey') # Replace this with an environment variable in production
# MongoDB config
app.config["MONGO_URI"] = os.environ.get("MONGO_URI")

mongo = PyMongo(app)

# Home Route
@app.route('/')
def home():
    if 'username' in session:
        return redirect('/dashboard')
    return redirect('/login')

# Signup Route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # ✅ Username: Must only contain letters (no numbers)
        if not username.isalpha():
            return '❌ Username must contain only letters (no numbers or special characters)! <a href="/signup">Try again</a>'

        # ✅ Password: Minimum 8 chars, must contain both letters and digits
        if len(password) < 8:
            return '❌ Password must be at least 8 characters long! <a href="/signup">Try again</a>'
        if not re.search(r'[A-Za-z]', password) or not re.search(r'\d', password):
            return '❌ Password must contain both letters and numbers! <a href="/signup">Try again</a>'

        existing_user = mongo.db.users.find_one({'username': username})
        if existing_user:
            return '❌ User already exists! <a href="/login">Login here</a>'

        hashed_password = generate_password_hash(password)
        mongo.db.users.insert_one({'username': username, 'password': hashed_password})
        return redirect('/login')
    
    return render_template('signup.html')

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        user = mongo.db.users.find_one({'username': username})
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            return redirect('/dashboard')
        else:
            return '❌ Invalid credentials! <a href="/login">Try again</a>'
    
    return render_template('login.html')

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    
    return render_template('dashboard.html', username=session['username'])

# Logout Route
@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

# ✅ Railway-compatible run block
if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0',port=port)
