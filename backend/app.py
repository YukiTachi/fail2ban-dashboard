#!/usr/bin/env python3
"""
Fail2ban Dashboard - Flask Application
"""
import os
from functools import wraps
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from fail2ban_service import Fail2banService
from geoip_service import GeoIPService
from log_parser import LogParser

load_dotenv()

app = Flask(__name__,
            template_folder='../templates',
            static_folder='../frontend')
app.secret_key = os.environ.get('SECRET_KEY', 'change-this-secret-key-in-production')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Services
fail2ban_service = Fail2banService()
geoip_service = GeoIPService()
log_parser = LogParser()

# Simple user model (in production, use a database)
class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

# Default admin user (change password in .env file)
ADMIN_USERNAME = os.environ.get('ADMIN_USERNAME', 'admin')
ADMIN_PASSWORD_HASH = generate_password_hash(os.environ.get('ADMIN_PASSWORD', 'admin'))
users = {
    '1': User('1', ADMIN_USERNAME, ADMIN_PASSWORD_HASH)
}

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

# Jail color mapping
JAIL_COLORS = {
    'sshd': {'bg': 'bg-blue-500', 'border': 'border-blue-600', 'text': 'text-blue-600'},
    'postfix-sasl': {'bg': 'bg-green-500', 'border': 'border-green-600', 'text': 'text-green-600'},
    'postfix': {'bg': 'bg-emerald-500', 'border': 'border-emerald-600', 'text': 'text-emerald-600'},
    'nginx-http-auth': {'bg': 'bg-orange-500', 'border': 'border-orange-600', 'text': 'text-orange-600'},
    'nginx-botsearch': {'bg': 'bg-amber-500', 'border': 'border-amber-600', 'text': 'text-amber-600'},
    'apache-auth': {'bg': 'bg-red-500', 'border': 'border-red-600', 'text': 'text-red-600'},
    'dovecot': {'bg': 'bg-cyan-500', 'border': 'border-cyan-600', 'text': 'text-cyan-600'},
    'default': {'bg': 'bg-purple-500', 'border': 'border-purple-600', 'text': 'text-purple-600'}
}

def get_jail_color(jail_name):
    """Get color scheme for a jail"""
    for key in JAIL_COLORS:
        if key in jail_name.lower():
            return JAIL_COLORS[key]
    return JAIL_COLORS['default']

# Routes
@app.route('/')
@login_required
def index():
    """Dashboard main page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = None
        for u in users.values():
            if u.username == username:
                user = u
                break

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))

        return render_template('login.html', error='Invalid username or password')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Logout"""
    logout_user()
    return redirect(url_for('login'))

@app.route('/detail/<jail_name>')
@login_required
def detail(jail_name):
    """Jail detail page"""
    return render_template('detail.html', jail_name=jail_name)

# API Endpoints
@app.route('/api/jails')
@login_required
def api_jails():
    """Get list of all jails with their status"""
    try:
        jails = fail2ban_service.get_all_jails()
        result = []

        for jail_name in jails:
            status = fail2ban_service.get_jail_status(jail_name)
            if status:
                status['color'] = get_jail_color(jail_name)
                result.append(status)

        return jsonify({'success': True, 'jails': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/jail/<jail_name>')
@login_required
def api_jail_detail(jail_name):
    """Get detailed status for a specific jail"""
    try:
        status = fail2ban_service.get_jail_status(jail_name)
        if not status:
            return jsonify({'success': False, 'error': 'Jail not found'}), 404

        # Get banned IPs with country info
        banned_ips = fail2ban_service.get_banned_ips(jail_name)
        ips_with_country = []

        for ip_info in banned_ips[:30]:  # Top 30
            country = geoip_service.get_country(ip_info['ip'])
            ip_info['country'] = country
            ips_with_country.append(ip_info)

        # Get failed IPs
        failed_ips = fail2ban_service.get_failed_ips(jail_name)

        status['banned_ips'] = ips_with_country
        status['failed_ips'] = failed_ips
        status['color'] = get_jail_color(jail_name)

        return jsonify({'success': True, 'jail': status})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/jail/<jail_name>/histogram')
@login_required
def api_jail_histogram(jail_name):
    """Get histogram data for reject counts"""
    try:
        histogram = fail2ban_service.get_reject_histogram(jail_name)
        return jsonify({'success': True, 'histogram': histogram})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/jail/<jail_name>/ban', methods=['POST'])
@login_required
def api_ban_ip(jail_name):
    """Ban an IP address"""
    try:
        data = request.get_json()
        ip = data.get('ip')

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        result = fail2ban_service.ban_ip(jail_name, ip)
        return jsonify({'success': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/jail/<jail_name>/unban', methods=['POST'])
@login_required
def api_unban_ip(jail_name):
    """Unban an IP address"""
    try:
        data = request.get_json()
        ip = data.get('ip')

        if not ip:
            return jsonify({'success': False, 'error': 'IP address required'}), 400

        result = fail2ban_service.unban_ip(jail_name, ip)
        return jsonify({'success': result})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/logs/<jail_name>')
@login_required
def api_logs(jail_name):
    """Get parsed log entries for a jail"""
    try:
        logs = log_parser.parse_logs(jail_name)
        return jsonify({'success': True, 'logs': logs})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
