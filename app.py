import re

import bcrypt
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_mysqldb import MySQL
import mysql.connector
import os
import pandas as pd
import numpy as np
from werkzeug.utils import secure_filename
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})
app.secret_key = os.urandom(24)

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '27360213@',
    'database': 'fina'
}

@app.route('/')
def message():
    return jsonify(message='Flask server is running'), 200

@app.route('/login', methods=['GET'])
def login():
    email = request.args.get('email').strip()
    password = request.args.get('password').strip()
    print(f"Email: '{email}', Password: '{password}'")

    if email and password:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        print(f"Fetched user: {user}")

        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            session['loggedin'] = True
            session['email'] = user['email']
            return jsonify(message='Logged in successfully!'), 200
        else:
            return jsonify(error='Incorrect email/password!'), 401
    else:
        return jsonify(error='Please provide both email and password'), 400

@app.route('/logout')
def logout():
    # Clear session data
    session.pop('loggedin', None)
    session.pop('userid', None)
    session.pop('email', None)
    return jsonify(message='Logged out successfully!'), 200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    print("Received data:", data)

    if not data:
        print("No JSON body provided")
        return jsonify(error='No JSON body provided'), 400

    username = data.get('username')
    password = data.get('password')
    email = data.get('email')

    # Input validation
    if not username or not password or not email:
        return jsonify(error='Please fill out the form!'), 400

    if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
        return jsonify(error='Invalid email address!'), 400

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if user already exists
        query = "SELECT * FROM user WHERE email = %s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()

        if user:
            return jsonify(error='Account already exists!'), 409

        # Hash the password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        # Insert a new user with hashed password
        query = "INSERT INTO user (username, email, password) VALUES (%s, %s, %s)"
        cursor.execute(query, (username, email, hashed_password.decode('utf-8')))
        conn.commit()

        return jsonify(message='You have successfully registered!'), 201

    except mysql.connector.Error as err:
        print(f"Database error: {err}")
        return jsonify(error='Internal Server Error'), 500

    finally:
        cursor.close()
        conn.close()

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/upload', methods=['POST'])
def upload_file():
    print("Route /upload accessed")  # Debugging

    # Check if a file is provided in the request
    if 'file' not in request.files:
        return handle_error('No file provided')

    file = request.files['file']

    # Check if a file is selected
    if file.filename == '':
        return handle_error('No file selected')

    # Save the uploaded file
    if file:
        filepath = save_file(file)
        return process_file(filepath)

def handle_error(message, status=400):
    """Handles errors by returning a JSON message and HTTP status code."""
    print(message)
    return jsonify(error=message), status

def save_file(file):
    """Saves the uploaded file and returns the file path."""
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return filepath

def process_file(filepath):
    """Processes the uploaded file by reading it with Pandas and inserting the data into the database."""
    try:
        # Process the file with Pandas
        df = pd.read_csv(filepath)
        df.columns = df.columns.str.strip()  # Clean column names

        # Insert data into the database
        insert_into_database(df)

        return jsonify(message='File uploaded and data inserted successfully'), 201
    except Exception as e:
        return handle_error(f'Error processing the file: {e}', 500)

def insert_into_database(df):
    """Inserts data from the DataFrame into the MySQL database."""
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    query = '''
    INSERT INTO transaction (Date, Transaction_ID, Description, Category, Amount, Type) 
    VALUES (%s, %s, %s, %s, %s, %s)
    '''

    for _, row in df.iterrows():
        data = (
            pd.to_datetime(row['Date']).strftime('%Y-%m-%d'),
            row['Transaction_ID'],  # Add Transaction_ID
            row['Description'],
            row['Category'],
            float(row['Amount']),
            row['Type']
        )
        cursor.execute(query, data)

    conn.commit()
    cursor.close()
    conn.close()

@app.route('/manual_entry', methods=['POST'])
def manual_entry():
    data = request.get_json()

    # Validate data
    required_fields = ['transaction_id', 'date', 'description', 'amount', 'type', 'category']
    if not all(field in data for field in required_fields):
        return handle_error('Missing required fields', 400)

    try:
        transaction_id = data['transaction_id']
        date = data['date']
        description = data['description']
        amount = float(data['amount'])
        type_ = data['type']
        category = data['category']

        # Insert data into the database
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        query = '''
        INSERT INTO transaction (transaction_id, date, description, amount, type, category) 
        VALUES (%s, %s, %s, %s, %s, %s)
        '''
        cursor.execute(query, (transaction_id, date, description, amount, type_, category))
        conn.commit()

        cursor.close()
        conn.close()

        return jsonify(message='Transaction manually inserted successfully'), 201
    except Exception as e:
        return handle_error(f'Error inserting data: {e}', 500)

@app.route('/transactions', methods=['GET'])
def get_transactions():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute('SELECT * FROM transaction')
    transactions = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify(transactions)

@app.route('/api/transaction_data', methods=['GET'])
def transaction_data():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Query for monthly spending trends
    cursor.execute("""
        SELECT DATE_FORMAT(date, '%Y-%m') AS month, 
               SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) AS spending,
               SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) AS income
        FROM transaction
        GROUP BY month
    """)
    spending_income = cursor.fetchall()

    # Query for spending by category
    cursor.execute("""
        SELECT category, SUM(amount) AS amount
        FROM transaction
        WHERE type = 'expense'
        GROUP BY category
    """)
    spending_by_category = cursor.fetchall()

    cursor.close()
    conn.close()

    return jsonify({
        'spending_income': spending_income,
        'spending_by_category': spending_by_category
    })

if __name__ == '__main__':
    app.run(debug=True)
