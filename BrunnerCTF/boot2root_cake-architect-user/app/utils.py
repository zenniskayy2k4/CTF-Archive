import hashlib
from functools import wraps
from flask import session, redirect, url_for, flash
import os

def hash_password(password):
    """Hash a password using SHA256"""
    return hashlib.sha256(password.encode()).hexdigest()

def login_required(f):
    """Decorator to require user login"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Admin privileges required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def get_or_generate_admin_password(path="/opt/.admin_pass"):
    """Read admin password from file or generate and store it if it doesn't exist."""
    if os.path.exists(path):
        with open(path, "r") as f:
            password = f.read().strip()
            if password:
                return password

    password = os.urandom(32).hex()
    with open(path, "w") as f:
        f.write(password)
    return password
