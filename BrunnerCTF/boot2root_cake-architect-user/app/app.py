from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
import os

# Import our modules
from utils import get_or_generate_admin_password, login_required, admin_required
from database import (
    init_db_pool, wait_for_db, setup_users, setup_sample_cakes,
    get_user_by_credentials, create_user, get_user_cakes, get_cake_by_id,
    save_cake, get_all_users, calculate_nutrition
)
from admin_bot import start_admin_bot

app = Flask(__name__)
app.secret_key = os.urandom(64).hex()

app.config['SESSION_COOKIE_HTTPONLY'] = False

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        
        if not username or not password or not email:
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        # Basic validation
        if len(username) < 3 or len(password) < 6:
            flash('Username must be at least 3 characters and password at least 6', 'error')
            return render_template('signup.html')
        
        if create_user(username, email, password):
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Registration failed', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        user = get_user_by_credentials(username, password)
        
        if user:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['role'] = user[2]
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    cakes = get_user_cakes(session['username'])
    return render_template('dashboard.html', cakes=cakes, user=session)

@app.route('/cake/<int:cake_id>')
@login_required
def view_cake(cake_id):
    cake = get_cake_by_id(cake_id)
    
    if not cake:
        flash('Cake not found', 'error')
        return redirect(url_for('dashboard'))
    
    # Check if user can view this cake
    if not cake[5] and cake[4] != session['username'] and session.get('role') != 'admin':
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('view_cake.html', cake=cake, user=session)

@app.route('/report-issue', methods=['GET', 'POST'])
@login_required
def report_issue():
    if request.method == 'POST':
        cake_id = request.form.get('cake_id')
        issue_description = request.form.get('issue_description')
        
        if not cake_id or not issue_description:
            flash('Cake ID and issue description are required', 'error')
            return render_template('report_issue.html')
        
        try:
            # Validate cake_id is numeric
            if not cake_id.isdigit():
                flash('Invalid Cake ID format', 'error')
                return render_template('report_issue.html')

            base_url = 'http://localhost:5000'
            cake_url = f"{base_url}/cake/{cake_id}"

            start_admin_bot(cake_url, admin_pass)

            flash('Issue reported successfully! An admin will review it soon.', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            print(f"❌ Report issue error: {e}")
            flash('Failed to process the issue report', 'error')

    return render_template('report_issue.html')

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = get_all_users()
    return render_template('admin.html', users=users)

@app.route('/admin/calculate-nutrition', methods=['POST'])
@admin_required
def calculate_nutrition_route():
    cake_id = request.json.get('cake_id', 0)

    result = calculate_nutrition(cake_id)
    if result is None:
        return jsonify({'error': 'Procedure failed or not found'}), 400

    return jsonify({'result': result})

@app.route('/cake-builder')
@login_required
def cake_builder():
    return render_template('cake_builder.html')

@app.route('/api/save-cake', methods=['POST'])
@login_required
def save_cake_api():
    data = request.get_json()
    name = data.get('name', '')
    ingredients = data.get('ingredients', {})
    instructions = data.get('instructions', '')
    
    if not name or not ingredients:
        return jsonify({'error': 'Name and ingredients are required'}), 400
    
    if save_cake(name, ingredients, instructions, session['username']):
        return jsonify({'status': 'success', 'message': 'Cake saved successfully'})
    else:
        return jsonify({'error': 'Failed to save cake'}), 400

if __name__ == '__main__':
    if wait_for_db():
        init_db_pool()
        
        # Set up initial data
        admin_pass = get_or_generate_admin_password()
        setup_users(admin_pass)
        setup_sample_cakes()
        
        app.run(host='0.0.0.0', debug=True)
    else:
        print("Failed to start application due to database connection issues")
