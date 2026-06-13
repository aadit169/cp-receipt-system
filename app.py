import os
import uuid
import datetime
from io import BytesIO
from threading import Thread

from flask import (
    Flask, render_template_string, request, redirect, url_for, flash,
    send_file, abort, session
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer as Serializer

from fpdf import FPDF
import pandas as pd

# ----------------------------------------------------------------------
# Helper: Indian Standard Time (UTC+5:30)
# ----------------------------------------------------------------------
def ist_now():
    return datetime.datetime.utcnow() + datetime.timedelta(hours=5, minutes=30)

# ----------------------------------------------------------------------
# App setup
# ----------------------------------------------------------------------
app = Flask(__name__)
# Use DATABASE_URL if provided (for PostgreSQL), otherwise use SQLite in /tmp (writable on Vercel)
if os.environ.get('DATABASE_URL'):
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ['DATABASE_URL']
else:
    # Vercel: only /tmp is writable
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/receipts.db'
# Use PostgreSQL on Vercel (via DATABASE_URL) or fallback to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///receipts.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email (for password reset & receipts)
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', '')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', '')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', '')
app.config['IT_EMAIL'] = os.environ.get('IT_EMAIL', 'it@cp.com')

UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# ----------------------------------------------------------------------
# Models
# ----------------------------------------------------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(10), nullable=False)  # 'EM' or 'IT'
    name = db.Column(db.String(120))
    email = db.Column(db.String(120))
    dob = db.Column(db.Date)
    phone = db.Column(db.String(20))
    photo = db.Column(db.String(200))
    branch = db.Column(db.String(120))
    reset_token = db.Column(db.String(200))
    reset_token_expiry = db.Column(db.DateTime)
    receipts = db.relationship('Receipt', backref='employee', lazy=True)
    delete_requests = db.relationship('DeleteRequest', backref='requested_by', lazy=True,
                                      foreign_keys='DeleteRequest.em_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)


class Receipt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_number = db.Column(db.String(36), unique=True, nullable=False)
    customer_name = db.Column(db.String(120))
    customer_email = db.Column(db.String(120))
    customer_phone = db.Column(db.String(20))
    item_description = db.Column(db.Text)
    total_amount = db.Column(db.Float, nullable=False)
    token_amount = db.Column(db.Float)
    amount_received = db.Column(db.Float, nullable=False)
    payment_type = db.Column(db.String(10))
    remaining_balance = db.Column(db.Float)
    status = db.Column(db.String(20), default='token')
    created_at = db.Column(db.DateTime, default=ist_now)
    completed_at = db.Column(db.DateTime)
    em_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    branch = db.Column(db.String(120))
    final_payment_done = db.Column(db.Boolean, default=False)
    delete_request = db.relationship('DeleteRequest', backref='receipt', uselist=False, lazy=True)


class DeleteRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('receipt.id'), nullable=False)
    em_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requested_at = db.Column(db.DateTime, default=ist_now)
    expiry_at = db.Column(db.DateTime, nullable=False)
    status = db.Column(db.String(20), default='pending')
    accepted_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    accepted_at = db.Column(db.DateTime)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------------------------------------------------------------
# Email sending
# ----------------------------------------------------------------------
def send_email(to, subject, body, attachment_bytes=None, attachment_name='report.pdf'):
    if app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD']:
        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart
        from email.mime.base import MIMEBase
        from email import encoders

        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = to
        msg.attach(MIMEText(body, 'html'))

        if attachment_bytes:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment_bytes)
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename="{attachment_name}"')
            msg.attach(part)

        try:
            server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
            server.starttls()
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.sendmail(app.config['MAIL_USERNAME'], to, msg.as_string())
            server.quit()
            print(f"[EMAIL] Sent to {to}")
        except Exception as e:
            print(f"[EMAIL] Failed: {e}")
    else:
        print(f"\n{'='*50}\nDEMO EMAIL\nTo: {to}\nSubject: {subject}\n{'='*50}\n")


def async_send_email(*args, **kwargs):
    Thread(target=send_email, args=args, kwargs=kwargs).start()


# ----------------------------------------------------------------------
# PDF generators (using INR for latin-1 safety)
# ----------------------------------------------------------------------
def generate_receipt_pdf(receipt):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "COMPANY CP - OFFICIAL RECEIPT", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 8, f"Receipt No: {receipt.receipt_number}", ln=True)
    pdf.cell(0, 8, f"Date: {receipt.created_at.strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.cell(0, 8, f"Branch: {receipt.branch}", ln=True)
    pdf.cell(0, 8, f"Employee: {receipt.employee.name}", ln=True)
    pdf.ln(5)
    pdf.cell(0, 8, f"Customer: {receipt.customer_name}", ln=True)
    if receipt.customer_email:
        pdf.cell(0, 8, f"Email: {receipt.customer_email}", ln=True)
    if receipt.customer_phone:
        pdf.cell(0, 8, f"Phone: {receipt.customer_phone}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 8, "Purchase Details:", ln=True)
    pdf.set_font("Arial", '', 12)
    pdf.multi_cell(0, 8, receipt.item_description)
    pdf.ln(3)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 8, f"Total Amount: INR {receipt.total_amount:,.2f}", ln=True)

    if receipt.payment_type == 'token':
        pdf.cell(0, 8, f"Token Payment Date: {receipt.created_at.strftime('%Y-%m-%d %H:%M')}", ln=True)
        pdf.cell(0, 8, f"Token Paid: INR {receipt.token_amount:,.2f}", ln=True)
        if receipt.final_payment_done:
            pdf.cell(0, 8, f"Final Payment Date: {receipt.completed_at.strftime('%Y-%m-%d %H:%M')}", ln=True)
            pdf.cell(0, 8, f"Balance Paid: INR {(receipt.total_amount - receipt.token_amount):,.2f}", ln=True)
        else:
            pdf.cell(0, 8, f"Remaining: INR {receipt.remaining_balance:,.2f}", ln=True)
    else:
        pdf.cell(0, 8, f"Payment Type: Full Payment", ln=True)
        pdf.cell(0, 8, f"Amount Received: INR {receipt.amount_received:,.2f}", ln=True)

    pdf.cell(0, 8, f"Status: {'Completed' if receipt.status=='completed' else 'Token Paid'}", ln=True)
    pdf.ln(10)
    pdf.set_font("Arial", 'I', 10)
    pdf.cell(0, 8, "This is a computer generated receipt.", ln=True, align='C')
    return pdf.output(dest='S').encode('latin-1')


def generate_daily_report_pdf(receipts, employee, date):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, f"DAILY REPORT - {date}", ln=True, align='C')
    pdf.set_font("Arial", '', 12)
    pdf.cell(0, 8, f"Employee: {employee.name} ({employee.branch})", ln=True)
    pdf.ln(5)
    total_token = sum(r.token_amount for r in receipts if r.payment_type == 'token')
    total_full = sum(r.amount_received for r in receipts if r.payment_type == 'full')
    pdf.cell(0, 8, f"Total Token Collected: INR {total_token:,.2f}", ln=True)
    pdf.cell(0, 8, f"Total Full Payments: INR {total_full:,.2f}", ln=True)
    pdf.cell(0, 8, f"Total Receipts: {len(receipts)}", ln=True)
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 10)
    col_widths = [30, 35, 35, 30, 30, 30]
    headers = ['Receipt No', 'Customer', 'Item', 'Total', 'Paid', 'Status']
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 8, h, 1)
    pdf.ln()
    pdf.set_font("Arial", '', 10)
    for r in receipts:
        pdf.cell(col_widths[0], 8, r.receipt_number[:8], 1)
        pdf.cell(col_widths[1], 8, r.customer_name[:15], 1)
        pdf.cell(col_widths[2], 8, r.item_description[:15], 1)
        pdf.cell(col_widths[3], 8, f"INR {r.total_amount:,.0f}", 1)
        paid = r.token_amount if r.payment_type == 'token' else r.amount_received
        pdf.cell(col_widths[4], 8, f"INR {paid:,.0f}", 1)
        pdf.cell(col_widths[5], 8, r.status, 1)
        pdf.ln()
    return pdf.output(dest='S').encode('latin-1')


# ----------------------------------------------------------------------
# HTML Templates (full, same as your original)
# ----------------------------------------------------------------------
LOGIN_HTML = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>CP Receipt System - Login</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <h3 class="text-center mb-4">CP Receipt System</h3>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{category}}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="POST">
        <div class="mb-3">
          <label>Email / Username</label>
          <input type="text" name="username" class="form-control" required>
        </div>
        <div class="mb-3">
          <label>Password</label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary w-100">Login</button>
      </form>
      <div class="mt-3 text-center">
        <a href="{{ url_for('forgot_password') }}">Forgot Password?</a>
      </div>
      <p class="mt-3 text-muted text-center">Demo: it@cp.com / password<br>EM: em1@cp.com / password</p>
    </div>
  </div>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

FORGOT_PASSWORD_HTML = '''
<!doctype html>
<html>
<head>
  <title>Forgot Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <h3>Reset Password</h3>
      {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages %}
          {% for category, message in messages %}
            <div class="alert alert-{{category}}">{{ message }}</div>
          {% endfor %}
        {% endif %}
      {% endwith %}
      <form method="POST">
        <div class="mb-3">
          <label>Enter your registered email</label>
          <input type="email" name="email" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-primary">Send Reset Link</button>
        <a href="{{ url_for('login') }}" class="btn btn-link">Back to Login</a>
      </form>
    </div>
  </div>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

RESET_PASSWORD_HTML = '''
<!doctype html>
<html>
<head>
  <title>Reset Password</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container mt-5">
  <div class="row justify-content-center">
    <div class="col-md-5">
      <h3>Set New Password</h3>
      <form method="POST">
        <div class="mb-3">
          <label>New Password</label>
          <input type="password" name="password" class="form-control" required>
        </div>
        <button type="submit" class="btn btn-success">Reset Password</button>
      </form>
    </div>
  </div>
</div>
</body>
</html>
'''

EM_DASHBOARD_HTML = '''
<!doctype html>
<html>
<head>
  <title>EM Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-expand-lg navbar-dark bg-primary">
  <div class="container">
    <a class="navbar-brand" href="#">CP Receipt System</a>
    <div class="collapse navbar-collapse">
      <ul class="navbar-nav ms-auto">
        <li class="nav-item"><a class="nav-link" href="{{ url_for('new_receipt') }}">New Receipt</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('search_receipt') }}">Search</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('em_history') }}">History</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('daily_report') }}">Daily Report</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('em_profile') }}">Profile</a></li>
        <li class="nav-item"><a class="nav-link" href="{{ url_for('logout') }}">Logout</a></li>
      </ul>
    </div>
  </div>
</nav>
<div class="container mt-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <h3>Today's Summary</h3>
  <p>Token Collected: &#8377;{{ "%.2f"|format(token_total) }} | Full Payments: &#8377;{{ "%.2f"|format(full_total) }}</p>
  <hr>
  <h4>Today's Receipts</h4>
  <table class="table table-sm">
    <thead><tr><th>#</th><th>Customer</th><th>Total</th><th>Paid</th><th>Status</th></tr></thead>
    <tbody>
    {% for r in receipts %}
    <tr>
      <td><a href="{{ url_for('view_receipt', receipt_id=r.id) }}">{{ r.receipt_number[:8] }}</a></td>
      <td>{{ r.customer_name }}</td>
      <td>&#8377;{{ "%.2f"|format(r.total_amount) }}</td>
      <td>&#8377;{{ "%.2f"|format(r.token_amount if r.payment_type=='token' else r.amount_received) }}</td>
      <td>{{ r.status }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

NEW_RECEIPT_HTML = '''
<!doctype html>
<html>
<head><title>New Receipt</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  <h3>Create New Receipt</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" onsubmit="return validateForm()">
    <div class="mb-3">
      <label>Customer Name *</label>
      <input type="text" name="customer_name" class="form-control" required>
    </div>
    <div class="mb-3">
      <label>Customer Email</label>
      <input type="email" name="customer_email" class="form-control">
    </div>
    <div class="mb-3">
      <label>Customer Phone</label>
      <input type="text" name="customer_phone" class="form-control">
    </div>
    <div class="mb-3">
      <label>Item / Service *</label>
      <select name="item_category" id="item_category" class="form-select" required onchange="toggleOther()">
        <option value="">-- Select --</option>
        <option value="car booking amount">Car Booking Amount</option>
        <option value="workshop receipt">Workshop Receipt</option>
        <option value="bodyshop receipt">Bodyshop Receipt</option>
        <option value="renewal insurance">Renewal Insurance</option>
        <option value="driving school fee">Driving School Fee</option>
        <option value="OTHER">OTHER</option>
      </select>
    </div>
    <div class="mb-3" id="other_description_div" style="display:none;">
      <label>Please specify *</label>
      <textarea name="other_description" id="other_description" class="form-control" rows="2"></textarea>
    </div>
    <div class="mb-3">
      <label>Total Amount (&#8377;) *</label>
      <input type="number" step="0.01" name="total_amount" class="form-control" required id="total_amount">
    </div>
    <div class="mb-3">
      <label>Payment Type *</label>
      <select name="payment_type" id="payment_type" class="form-select" required onchange="toggleTokenAmount()">
        <option value="">-- Select --</option>
        <option value="token">Token</option>
        <option value="full">Full Payment</option>
      </select>
    </div>
    <div class="mb-3" id="token_amount_div" style="display:none;">
      <label>Token Amount (&#8377;) *</label>
      <input type="number" step="0.01" name="token_amount" class="form-control" id="token_amount">
    </div>
    <button type="submit" class="btn btn-success">Generate Receipt</button>
    <a href="{{ url_for('em_dashboard') }}" class="btn btn-secondary">Back</a>
  </form>
</div>
<script>
function toggleOther() {
    var cat = document.getElementById('item_category').value;
    var otherDiv = document.getElementById('other_description_div');
    var otherField = document.getElementById('other_description');
    if (cat === 'OTHER') {
        otherDiv.style.display = 'block';
        otherField.setAttribute('required', 'required');
    } else {
        otherDiv.style.display = 'none';
        otherField.removeAttribute('required');
        otherField.value = '';
    }
}
function toggleTokenAmount() {
    var type = document.getElementById('payment_type').value;
    var tokenDiv = document.getElementById('token_amount_div');
    if (type === 'token') {
        tokenDiv.style.display = 'block';
        document.getElementById('token_amount').setAttribute('required', 'required');
    } else {
        tokenDiv.style.display = 'none';
        document.getElementById('token_amount').removeAttribute('required');
        document.getElementById('token_amount').value = '';
    }
}
function validateForm() {
    var cat = document.getElementById('item_category').value;
    if (cat === 'OTHER') {
        var otherVal = document.getElementById('other_description').value.trim();
        if (otherVal === '') {
            alert('Please provide a description for "OTHER".');
            return false;
        }
    }
    var type = document.getElementById('payment_type').value;
    if (type === 'token') {
        var total = parseFloat(document.getElementById('total_amount').value) || 0;
        var token = parseFloat(document.getElementById('token_amount').value) || 0;
        if (token >= total) {
            alert('Error: Token amount must be less than the total amount.');
            return false;
        }
        if (token <= 0) {
            alert('Error: Token amount must be greater than zero.');
            return false;
        }
    }
    return true;
}
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

VIEW_RECEIPT_HTML = '''
<!doctype html>
<html>
<head><title>Receipt</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <div class="card">
    <div class="card-header bg-primary text-white">
      <h4>Receipt #{{ receipt.receipt_number }}</h4>
    </div>
    <div class="card-body">
      <p><strong>Customer:</strong> {{ receipt.customer_name }} {% if receipt.customer_email %}({{ receipt.customer_email }}){% endif %}</p>
      <p><strong>Item:</strong> {{ receipt.item_description }}</p>
      <p><strong>Total Amount:</strong> &#8377;{{ "%.2f"|format(receipt.total_amount) }}</p>
      <p><strong>Payment Type:</strong> {{ 'Full' if receipt.payment_type=='full' else 'Token' }}</p>
      {% if receipt.payment_type == 'token' %}
        <p><strong>Token Payment Date:</strong> {{ receipt.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
        <p><strong>Token Paid:</strong> &#8377;{{ "%.2f"|format(receipt.token_amount) }}</p>
        {% if receipt.final_payment_done %}
          <p><strong>Final Payment Date:</strong> {{ receipt.completed_at.strftime('%Y-%m-%d %H:%M') }}</p>
          <p><strong>Balance Paid:</strong> &#8377;{{ "%.2f"|format(receipt.total_amount - receipt.token_amount) }}</p>
        {% else %}
          <p><strong>Remaining:</strong> &#8377;{{ "%.2f"|format(receipt.remaining_balance) }}</p>
        {% endif %}
      {% else %}
        <p><strong>Amount Received:</strong> &#8377;{{ "%.2f"|format(receipt.amount_received) }}</p>
        <p><strong>Payment Date:</strong> {{ receipt.created_at.strftime('%Y-%m-%d %H:%M') }}</p>
      {% endif %}
      <p><strong>Status:</strong> {{ receipt.status }}</p>

      <!-- Delete Request Section -->
      {% if receipt.status == 'token' or receipt.status == 'completed' %}
        {% set dr = receipt.delete_request %}
        {% if dr %}
          {% if dr.status == 'pending' %}
            <div class="alert alert-warning">
              <strong>Deletion requested.</strong> Expires in: 
              <span id="delete-countdown-{{ receipt.id }}" data-expiry="{{ dr.expiry_at.timestamp() }}">--</span>
            </div>
          {% elif dr.status == 'accepted' %}
            <div class="alert alert-success">Receipt deleted by IT.</div>
          {% elif dr.status == 'expired' %}
            <div class="alert alert-secondary">Delete request expired.</div>
          {% endif %}
        {% else %}
          {% if not receipt.final_payment_done or receipt.status == 'completed' %}
          <form method="POST" action="{{ url_for('request_delete', receipt_id=receipt.id) }}"
                onsubmit="return confirm('Request deletion of this receipt?')">
            <button class="btn btn-danger btn-sm">Request Deletion</button>
          </form>
          {% endif %}
        {% endif %}
      {% endif %}

      {% if receipt.status == 'token' %}
        <form method="POST" action="{{ url_for('process_full_payment', receipt_id=receipt.id) }}"
              onsubmit="return confirm('Are you sure you want to process full payment? This will mark the receipt as completed.');">
          <button class="btn btn-warning mt-2">Process Full Payment</button>
        </form>
      {% endif %}
      <a href="javascript:window.print()" class="btn btn-secondary mt-2">Print</a>
      <a href="{{ url_for('em_dashboard') }}" class="btn btn-link">Back</a>
    </div>
  </div>
</div>
<script>
function startCountdowns() {
    document.querySelectorAll('[id^="delete-countdown-"]').forEach(function(el) {
        var expiry = parseFloat(el.getAttribute('data-expiry')) * 1000;
        var timer = setInterval(function() {
            var now = new Date().getTime();
            var distance = expiry - now;
            if (distance < 0) {
                clearInterval(timer);
                el.innerHTML = "Expired";
                return;
            }
            var minutes = Math.floor(distance / (1000 * 60));
            var seconds = Math.floor((distance % (60000)) / 1000);
            el.innerHTML = minutes + "m " + seconds + "s ";
        }, 1000);
    });
}
document.addEventListener('DOMContentLoaded', function() {
    startCountdowns();
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

SEARCH_RECEIPT_HTML = '''
<!doctype html>
<html>
<head><title>Search Receipt</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  <h3>Search Receipt by Number</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST">
    <input type="text" name="receipt_number" class="form-control mb-2" placeholder="Enter receipt number" required>
    <button class="btn btn-primary">Search</button>
    <a href="{{ url_for('em_dashboard') }}" class="btn btn-link">Back</a>
  </form>
  {% if receipt %}
  <hr>
  <table class="table"><tr><th>Receipt #</th><td>{{ receipt.receipt_number }}</tr>
    <tr><th>Customer</th><td>{{ receipt.customer_name }}</tr>
    <tr><th>Total</th><td>&#8377;{{ "%.2f"|format(receipt.total_amount) }}</tr>
    <tr><th>Status</th><td>{{ receipt.status }}</tr>
    {% if receipt.status == 'token' %}
    <tr><td colspan="2">
      <a href="{{ url_for('view_receipt', receipt_id=receipt.id) }}" class="btn btn-warning">View & Process Full Payment</a>
     </tr>
    {% endif %}
  相当
  {% endif %}
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

EM_HISTORY_HTML = '''
<!doctype html>
<html>
<head><title>History</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  <h3>Receipt History</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form>
    <select name="period" class="form-select w-auto d-inline" onchange="this.form.submit()">
      <option value="today" {% if period=='today' %}selected{% endif %}>Today</option>
      <option value="yesterday" {% if period=='yesterday' %}selected{% endif %}>Yesterday</option>
      <option value="week" {% if period=='week' %}selected{% endif %}>1 Week</option>
      <option value="month" {% if period=='month' %}selected{% endif %}>1 Month</option>
      <option value="3months" {% if period=='3months' %}selected{% endif %}>3 Months</option>
      <option value="6months" {% if period=='6months' %}selected{% endif %}>6 Months</option>
      <option value="year" {% if period=='year' %}selected{% endif %}>1 Year</option>
      <option value="all" {% if period=='all' %}selected{% endif %}>All Time</option>
    </select>
  </form>
  <table class="table table-sm mt-3">
    <thead><tr><th>#</th><th>Customer</th><th>Total</th><th>Paid</th><th>Status</th><th>Date</th></tr></thead>
    <tbody>
    {% for r in receipts %}
    <tr>
      <td><a href="{{ url_for('view_receipt', receipt_id=r.id) }}">{{ r.receipt_number[:8] }}</a></td>
      <td>{{ r.customer_name }}</td>
      <td>&#8377;{{ "%.2f"|format(r.total_amount) }}</td>
      <td>&#8377;{{ "%.2f"|format(r.token_amount if r.payment_type=='token' else r.amount_received) }}</td>
      <td>{{ r.status }}</td>
      <td>{{ r.created_at.strftime('%Y-%m-%d') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
  <a href="{{ url_for('em_dashboard') }}" class="btn btn-link">Back</a>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

DAILY_REPORT_HTML = '''
<!doctype html>
<html>
<head><title>Daily Report</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  <h3>Daily Report - {{ today }}</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {% if receipts %}
  <table class="table">
    <tr><th>Receipt No</th><th>Customer</th><th>Total</th><th>Paid</th><th>Status</th></tr>
    {% for r in receipts %}
    <tr>
      <td>{{ r.receipt_number[:8] }}</td>
      <td>{{ r.customer_name }}</td>
      <td>&#8377;{{ "%.2f"|format(r.total_amount) }}</td>
      <td>&#8377;{{ "%.2f"|format(r.token_amount if r.payment_type=='token' else r.amount_received) }}</td>
      <td>{{ r.status }}</td>
    </tr>
    {% endfor %}
  </table>
  <form method="POST" action="{{ url_for('send_daily_report') }}">
    <button class="btn btn-primary">Send Report to IT</button>
  </form>
  {% else %}
    <p>No receipts today.</p>
  {% endif %}
  <a href="{{ url_for('em_dashboard') }}" class="btn btn-link">Back</a>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

EM_PROFILE_HTML = '''
<!doctype html>
<html>
<head><title>Profile</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
  <h3>Employee Profile</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form method="POST" enctype="multipart/form-data">
    <div class="mb-3">
      <label>Full Name</label>
      <input type="text" name="name" value="{{ user.name or '' }}" class="form-control">
    </div>
    <div class="mb-3">
      <label>Email</label>
      <input type="email" name="email" value="{{ user.email or '' }}" class="form-control">
    </div>
    <div class="mb-3">
      <label>Phone</label>
      <input type="text" name="phone" value="{{ user.phone or '' }}" class="form-control">
    </div>
    <div class="mb-3">
      <label>Date of Birth</label>
      <input type="date" name="dob" value="{{ user.dob.strftime('%Y-%m-%d') if user.dob else '' }}" class="form-control">
    </div>
    <div class="mb-3">
      <label>Photo</label>
      {% if user.photo %}
        <img src="{{ url_for('static', filename='uploads/' + user.photo) }}" width="80"><br>
      {% endif %}
      <input type="file" name="photo" class="form-control">
    </div>
    <button class="btn btn-success">Save</button>
    <a href="{{ url_for('em_dashboard') }}" class="btn btn-link">Back</a>
  </form>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

IT_DASHBOARD_HTML = '''
<!doctype html>
<html>
<head><title>IT Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="#">IT Control Panel</a>
    <div class="ms-auto">
      <a href="{{ url_for('it_delete_requests') }}" class="btn btn-outline-light me-2">Delete Requests</a>
      <a href="{{ url_for('logout') }}" class="btn btn-outline-light">Logout</a>
    </div>
  </div>
</nav>
<div class="container mt-4">
  <h3>Receipts Overview</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <form class="row g-2 mb-3">
    <div class="col-auto"><input type="text" name="branch" placeholder="Branch" class="form-control" value="{{ filters.branch }}"></div>
    <div class="col-auto"><select name="em_id" class="form-select"><option value="">All Employees</option>
      {% for e in employees %}<option value="{{ e.id }}" {% if filters.em_id==e.id|string %}selected{% endif %}>{{ e.name }}</option>{% endfor %}
    </select></div>
    <div class="col-auto"><input type="date" name="start_date" class="form-control" value="{{ filters.start_date }}"></div>
    <div class="col-auto"><input type="date" name="end_date" class="form-control" value="{{ filters.end_date }}"></div>
    <div class="col-auto"><button class="btn btn-primary">Filter</button></div>
  </form>
  <p>
    <a href="{{ url_for('it_report_pdf', branch=filters.branch, em_id=filters.em_id, start_date=filters.start_date, end_date=filters.end_date) }}" class="btn btn-outline-danger">Download PDF</a>
    <a href="{{ url_for('it_report_excel', type='filtered', branch=filters.branch, em_id=filters.em_id, start_date=filters.start_date, end_date=filters.end_date) }}" class="btn btn-outline-success">Excel (Filtered)</a>
    <a href="{{ url_for('it_report_excel', type='all') }}" class="btn btn-outline-success">Excel (All Data)</a>
  </p>
  <table class="table table-striped">
    <thead><tr><th>Receipt #</th><th>Customer</th><th>Employee</th><th>Branch</th><th>Total</th><th>Paid</th><th>Status</th><th>Date</th></tr></thead>
    <tbody>
    {% for r in receipts %}
    <tr>
      <td>{{ r.receipt_number[:10] }}</td>
      <td>{{ r.customer_name }}</td>
      <td>{{ r.employee.name }}</td>
      <td>{{ r.branch }}</td>
      <td>&#8377;{{ "%.2f"|format(r.total_amount) }}</td>
      <td>&#8377;{{ "%.2f"|format(r.token_amount if r.payment_type=='token' else r.amount_received) }}</td>
      <td>{{ r.status }}</td>
      <td>{{ r.created_at.strftime('%Y-%m-%d') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script>
document.addEventListener('DOMContentLoaded', function() {
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

IT_DELETE_REQUESTS_HTML = '''
<!doctype html>
<html>
<head><title>Delete Requests</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<nav class="navbar navbar-dark bg-dark">
  <div class="container">
    <a class="navbar-brand" href="#">IT Control Panel</a>
    <a href="{{ url_for('it_dashboard') }}" class="btn btn-outline-light">Back to Dashboard</a>
  </div>
</nav>
<div class="container mt-4">
  <h3>Pending Delete Requests</h3>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}
      {% for category, message in messages %}
        <div class="alert alert-{{category}}">{{ message }}</div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  <table class="table">
    <thead><tr><th>Receipt No</th><th>Customer</th><th>Employee</th><th>Amount</th><th>Requested At</th><th>Time Left</th><th>Action</th></tr></thead>
    <tbody>
    {% for req in requests %}
    <tr>
      <td>{{ req.receipt.receipt_number[:10] }}</td>
      <td>{{ req.receipt.customer_name }}</td>
      <td>{{ req.requested_by.name }}</td>
      <td>&#8377;{{ "%.2f"|format(req.receipt.total_amount) }}</td>
      <td>{{ req.requested_at.strftime('%Y-%m-%d %H:%M') }}</td>
      <td>
        {% if req.status == 'pending' %}
          <span class="countdown-timer" data-expiry="{{ req.expiry_at.timestamp() }}">--</span>
        {% else %}
          {{ req.status }}
        {% endif %}
      </td>
      <td>
        {% if req.status == 'pending' %}
        <form method="POST" action="{{ url_for('accept_delete', request_id=req.id) }}"
              onsubmit="return confirm('Permanently delete this receipt?')">
          <button class="btn btn-danger btn-sm">Accept & Delete</button>
        </form>
        {% endif %}
      </td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
<script>
function startCountdowns() {
    document.querySelectorAll('.countdown-timer').forEach(function(el) {
        var expiry = parseFloat(el.getAttribute('data-expiry')) * 1000;
        var timer = setInterval(function() {
            var now = new Date().getTime();
            var distance = expiry - now;
            if (distance < 0) {
                clearInterval(timer);
                el.innerHTML = "Expired";
                return;
            }
            var minutes = Math.floor(distance / (1000 * 60));
            var seconds = Math.floor((distance % (60000)) / 1000);
            el.innerHTML = minutes + "m " + seconds + "s";
        }, 1000);
    });
}
document.addEventListener('DOMContentLoaded', function() {
    startCountdowns();
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(a => {
            a.style.transition = 'opacity 0.5s';
            a.style.opacity = '0';
            setTimeout(() => a.remove(), 500);
        });
    }, 3000);
});
</script>
</body>
</html>
'''

RECEIPT_EMAIL_HTML = '''
<!doctype html>
<html>
<head><style>body{font-family: Arial, sans-serif;}</style></head>
<body>
  <h2>CP Receipt</h2>
  <p><strong>Receipt No:</strong> {{ receipt.receipt_number }}</p>
  <p><strong>Date:</strong> {{ receipt.created_at.strftime('%Y-%m-%d %H:%M') if receipt.created_at else '' }}</p>
  <p><strong>Customer:</strong> {{ receipt.customer_name }}</p>
  <p><strong>Item:</strong> {{ receipt.item_description }}</p>
  <p><strong>Total:</strong> &#8377;{{ "%.2f"|format(receipt.total_amount) }}</p>
  {% if receipt.payment_type == 'token' %}
    <p><strong>Token Paid:</strong> &#8377;{{ "%.2f"|format(receipt.token_amount) }}</p>
    {% if receipt.final_payment_done %}
      <p><strong>Final Payment:</strong> &#8377;{{ "%.2f"|format(receipt.total_amount - receipt.token_amount) }}</p>
    {% else %}
      <p><strong>Remaining:</strong> &#8377;{{ "%.2f"|format(receipt.remaining_balance) }}</p>
    {% endif %}
  {% else %}
    <p><strong>Amount Received:</strong> &#8377;{{ "%.2f"|format(receipt.amount_received) }}</p>
  {% endif %}
  <p><strong>Status:</strong> {{ receipt.status }}</p>
  <p>Thank you for your business.</p>
</body>
</html>
'''


# ----------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            token = user.get_reset_token()
            user.reset_token = token
            user.reset_token_expiry = datetime.datetime.utcnow() + datetime.timedelta(seconds=1800)
            db.session.commit()
            reset_url = url_for('reset_password', token=token, _external=True)
            subject = "Password Reset Request"
            body = f"<p>Click the link below to reset your password:</p><p><a href='{reset_url}'>{reset_url}</a></p>"
            async_send_email(email, subject, body)
            flash('A password reset link has been sent to your email.', 'info')
        else:
            flash('No account found with that email.', 'danger')
    return render_template_string(FORGOT_PASSWORD_HTML)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('forgot_password'))
    if request.method == 'POST':
        new_password = request.form.get('password')
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password reset successfully. You can now log in.', 'success')
        return redirect(url_for('login'))
    return render_template_string(RESET_PASSWORD_HTML)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            if user.role == 'EM':
                return redirect(url_for('em_dashboard'))
            else:
                return redirect(url_for('it_dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template_string(LOGIN_HTML)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/em/dashboard')
@login_required
def em_dashboard():
    if current_user.role != 'EM': abort(403)
    today = datetime.date.today()
    receipts = Receipt.query.filter(
        Receipt.em_id == current_user.id,
        db.func.date(Receipt.created_at) == today
    ).all()
    token_total = sum(r.token_amount for r in receipts if r.payment_type=='token')
    full_total = sum(r.amount_received for r in receipts if r.payment_type=='full')
    return render_template_string(EM_DASHBOARD_HTML,
                                  receipts=receipts, token_total=token_total, full_total=full_total)

@app.route('/em/new_receipt', methods=['GET', 'POST'])
@login_required
def new_receipt():
    if current_user.role != 'EM': abort(403)
    if request.method == 'POST':
        customer_name = request.form['customer_name']
        customer_email = request.form.get('customer_email')
        customer_phone = request.form.get('customer_phone')
        item_category = request.form['item_category']
        if item_category == 'OTHER':
            item_desc = request.form.get('other_description', '').strip()
            if not item_desc:
                flash('Please provide a description for "OTHER".', 'danger')
                return render_template_string(NEW_RECEIPT_HTML)
        else:
            item_desc = item_category

        total_amount = float(request.form['total_amount'])
        payment_type = request.form['payment_type']

        if payment_type == 'token':
            token_amount = float(request.form.get('token_amount', 0))
            if token_amount >= total_amount:
                flash('Error: Token amount must be less than the total amount.', 'danger')
                return render_template_string(NEW_RECEIPT_HTML)
            if token_amount <= 0:
                flash('Error: Token amount must be greater than zero.', 'danger')
                return render_template_string(NEW_RECEIPT_HTML)
            amount_received = token_amount
            remaining = round(total_amount - token_amount, 2)
            status = 'token'
        else:
            token_amount = 0
            amount_received = total_amount
            remaining = 0.0
            status = 'completed'

        now_ist = ist_now()
        receipt_number = uuid.uuid4().hex[:12].upper()
        receipt = Receipt(
            receipt_number=receipt_number,
            customer_name=customer_name,
            customer_email=customer_email,
            customer_phone=customer_phone,
            item_description=item_desc,
            total_amount=total_amount,
            token_amount=token_amount,
            amount_received=amount_received,
            payment_type=payment_type,
            remaining_balance=remaining,
            status=status,
            em_id=current_user.id,
            branch=current_user.branch,
            created_at=now_ist,
            final_payment_done=(payment_type=='full')
        )
        if payment_type == 'full':
            receipt.completed_at = now_ist

        db.session.add(receipt)
        db.session.commit()

        subject = f"Receipt #{receipt.receipt_number} - {'Full' if payment_type=='full' else 'Token'}"
        html_body = render_template_string(RECEIPT_EMAIL_HTML, receipt=receipt)
        if customer_email:
            async_send_email(customer_email, subject, html_body,
                             generate_receipt_pdf(receipt), f"Receipt_{receipt.receipt_number}.pdf")
        async_send_email(app.config['IT_EMAIL'], f"Copy: {subject}", html_body,
                         generate_receipt_pdf(receipt), f"Receipt_{receipt.receipt_number}.pdf")

        flash('Receipt generated successfully!', 'success')
        return redirect(url_for('view_receipt', receipt_id=receipt.id))
    return render_template_string(NEW_RECEIPT_HTML)

@app.route('/em/receipt/<int:receipt_id>')
@login_required
def view_receipt(receipt_id):
    if current_user.role != 'EM': abort(403)
    receipt = Receipt.query.get_or_404(receipt_id)
    if receipt.em_id != current_user.id: abort(403)
    return render_template_string(VIEW_RECEIPT_HTML, receipt=receipt)

@app.route('/em/search', methods=['GET', 'POST'])
@login_required
def search_receipt():
    if current_user.role != 'EM': abort(403)
    receipt = None
    if request.method == 'POST':
        receipt_number = request.form.get('receipt_number')
        receipt = Receipt.query.filter_by(receipt_number=receipt_number, em_id=current_user.id).first()
        if not receipt:
            flash('Receipt not found.', 'warning')
    return render_template_string(SEARCH_RECEIPT_HTML, receipt=receipt)

@app.route('/em/process_full_payment/<int:receipt_id>', methods=['POST'])
@login_required
def process_full_payment(receipt_id):
    if current_user.role != 'EM': abort(403)
    receipt = Receipt.query.get_or_404(receipt_id)
    if receipt.em_id != current_user.id or receipt.status == 'completed':
        abort(400)

    receipt.amount_received = receipt.total_amount
    receipt.remaining_balance = 0.0
    receipt.status = 'completed'
    receipt.final_payment_done = True
    receipt.completed_at = ist_now()
    db.session.commit()

    subject = f"Final Payment - Receipt #{receipt.receipt_number}"
    html_body = render_template_string(RECEIPT_EMAIL_HTML, receipt=receipt)
    if receipt.customer_email:
        async_send_email(receipt.customer_email, subject, html_body,
                         generate_receipt_pdf(receipt), f"Final_Receipt_{receipt.receipt_number}.pdf")
    async_send_email(app.config['IT_EMAIL'], f"Copy: {subject}", html_body,
                     generate_receipt_pdf(receipt), f"Final_Receipt_{receipt.receipt_number}.pdf")

    flash('Full payment processed successfully!', 'success')
    return redirect(url_for('view_receipt', receipt_id=receipt.id))

@app.route('/em/history')
@login_required
def em_history():
    if current_user.role != 'EM': abort(403)
    period = request.args.get('period', 'today')
    now_ist = ist_now()
    if period == 'today':
        start = now_ist.replace(hour=0, minute=0, second=0, microsecond=0)
        end = now_ist
    elif period == 'yesterday':
        yesterday = now_ist - datetime.timedelta(days=1)
        start = yesterday.replace(hour=0, minute=0, second=0, microsecond=0)
        end = yesterday.replace(hour=23, minute=59, second=59)
    elif period == 'week':
        start = now_ist - datetime.timedelta(days=7)
        end = now_ist
    elif period == 'month':
        start = now_ist - datetime.timedelta(days=30)
        end = now_ist
    elif period == '3months':
        start = now_ist - datetime.timedelta(days=90)
        end = now_ist
    elif period == '6months':
        start = now_ist - datetime.timedelta(days=180)
        end = now_ist
    elif period == 'year':
        start = now_ist - datetime.timedelta(days=365)
        end = now_ist
    else:
        receipts = Receipt.query.filter_by(em_id=current_user.id).order_by(Receipt.created_at.desc()).all()
        return render_template_string(EM_HISTORY_HTML, receipts=receipts, period=period)

    receipts = Receipt.query.filter(
        Receipt.em_id == current_user.id,
        Receipt.created_at >= start,
        Receipt.created_at <= end
    ).order_by(Receipt.created_at.desc()).all()
    return render_template_string(EM_HISTORY_HTML, receipts=receipts, period=period)

@app.route('/em/daily_report')
@login_required
def daily_report():
    if current_user.role != 'EM': abort(403)
    today = datetime.date.today()
    receipts = Receipt.query.filter(
        Receipt.em_id == current_user.id,
        db.func.date(Receipt.created_at) == today
    ).all()
    return render_template_string(DAILY_REPORT_HTML, receipts=receipts, today=today)

@app.route('/em/send_daily_report', methods=['POST'])
@login_required
def send_daily_report():
    if current_user.role != 'EM': abort(403)
    today = datetime.date.today()
    receipts = Receipt.query.filter(
        Receipt.em_id == current_user.id,
        db.func.date(Receipt.created_at) == today
    ).all()
    if not receipts:
        flash('No receipts to report today.', 'info')
        return redirect(url_for('daily_report'))
    pdf_bytes = generate_daily_report_pdf(receipts, current_user, today.strftime('%Y-%m-%d'))
    subject = f"Daily Report - {current_user.name} ({today})"
    body = f"<p>Daily report for {current_user.name}, {current_user.branch}.</p>"
    async_send_email(app.config['IT_EMAIL'], subject, body, pdf_bytes, f"Daily_Report_{today}.pdf")
    flash('Daily report emailed to IT.', 'success')
    return redirect(url_for('daily_report'))

@app.route('/em/profile', methods=['GET', 'POST'])
@login_required
def em_profile():
    if current_user.role != 'EM': abort(403)
    if request.method == 'POST':
        current_user.name = request.form['name']
        current_user.email = request.form['email']
        current_user.phone = request.form['phone']
        dob_str = request.form['dob']
        if dob_str:
            current_user.dob = datetime.datetime.strptime(dob_str, '%Y-%m-%d').date()
        if 'photo' in request.files:
            file = request.files['photo']
            if file.filename:
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.photo = filename
        db.session.commit()
        flash('Profile updated.', 'success')
        return redirect(url_for('em_profile'))
    return render_template_string(EM_PROFILE_HTML, user=current_user)

@app.route('/em/request_delete/<int:receipt_id>', methods=['POST'])
@login_required
def request_delete(receipt_id):
    if current_user.role != 'EM': abort(403)
    receipt = Receipt.query.get_or_404(receipt_id)
    if receipt.em_id != current_user.id:
        abort(403)
    if receipt.delete_request and receipt.delete_request.status == 'pending':
        flash('A deletion request is already pending.', 'warning')
        return redirect(url_for('view_receipt', receipt_id=receipt.id))
    now_ist = ist_now()
    delete_req = DeleteRequest(
        receipt_id=receipt.id,
        em_id=current_user.id,
        requested_at=now_ist,
        expiry_at=now_ist + datetime.timedelta(minutes=5),
        status='pending'
    )
    db.session.add(delete_req)
    db.session.commit()
    flash('Deletion request sent to IT. It will expire in 5 minutes.', 'info')
    return redirect(url_for('view_receipt', receipt_id=receipt.id))

@app.route('/it/dashboard')
@login_required
def it_dashboard():
    if current_user.role != 'IT': abort(403)
    branch = request.args.get('branch', '')
    em_id = request.args.get('em_id', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    query = Receipt.query
    if branch:
        query = query.filter(Receipt.branch == branch)
    if em_id:
        query = query.filter(Receipt.em_id == int(em_id))
    if start_date:
        query = query.filter(Receipt.created_at >= datetime.datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Receipt.created_at <= datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1))
    receipts = query.order_by(Receipt.created_at.desc()).all()
    employees = User.query.filter_by(role='EM').all()
    return render_template_string(IT_DASHBOARD_HTML,
                                  receipts=receipts, employees=employees,
                                  filters={'branch': branch, 'em_id': em_id,
                                           'start_date': start_date, 'end_date': end_date})

@app.route('/it/delete_requests')
@login_required
def it_delete_requests():
    if current_user.role != 'IT': abort(403)
    now_ist = ist_now()
    pending_requests = DeleteRequest.query.filter_by(status='pending').all()
    for req in pending_requests:
        if now_ist > req.expiry_at:
            req.status = 'expired'
    db.session.commit()
    requests = DeleteRequest.query.order_by(DeleteRequest.requested_at.desc()).all()
    return render_template_string(IT_DELETE_REQUESTS_HTML, requests=requests, now=now_ist)

@app.route('/it/accept_delete/<int:request_id>', methods=['POST'])
@login_required
def accept_delete(request_id):
    if current_user.role != 'IT': abort(403)
    delete_req = DeleteRequest.query.get_or_404(request_id)
    if delete_req.status != 'pending':
        flash('Request is no longer pending.', 'danger')
        return redirect(url_for('it_delete_requests'))
    now_ist = ist_now()
    if now_ist > delete_req.expiry_at:
        delete_req.status = 'expired'
        db.session.commit()
        flash('Time expired. Request cancelled.', 'danger')
        return redirect(url_for('it_delete_requests'))

    receipt = delete_req.receipt
    db.session.delete(delete_req)
    db.session.delete(receipt)
    db.session.commit()
    flash('Receipt deleted successfully.', 'success')
    return redirect(url_for('it_delete_requests'))

@app.route('/it/report/pdf')
@login_required
def it_report_pdf():
    if current_user.role != 'IT': abort(403)
    branch = request.args.get('branch', '')
    em_id = request.args.get('em_id', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    query = Receipt.query
    if branch:
        query = query.filter(Receipt.branch == branch)
    if em_id:
        query = query.filter(Receipt.em_id == int(em_id))
    if start_date:
        query = query.filter(Receipt.created_at >= datetime.datetime.strptime(start_date, '%Y-%m-%d'))
    if end_date:
        query = query.filter(Receipt.created_at <= datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1))
    receipts = query.order_by(Receipt.created_at.desc()).all()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(0, 10, "IT RECEIPT REPORT", ln=True, align='C')
    pdf.ln(5)
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 8, f"Filters: branch={branch or 'All'}, from {start_date or 'any'} to {end_date or 'any'}", ln=True)
    pdf.ln(5)
    total_amount = sum(r.total_amount for r in receipts)
    total_token = sum(r.token_amount for r in receipts if r.payment_type=='token')
    total_full = sum(r.amount_received for r in receipts if r.payment_type=='full')
    pdf.cell(0, 8, f"Total value: INR {total_amount:,.2f} | Token: INR {total_token:,.2f} | Full: INR {total_full:,.2f} | Count: {len(receipts)}", ln=True)
    pdf.ln(5)
    col_widths = [25, 25, 25, 30, 30, 30, 25]
    headers = ['Receipt No', 'Customer', 'Employee', 'Branch', 'Total', 'Paid', 'Status']
    pdf.set_font("Arial", 'B', 8)
    for i, h in enumerate(headers):
        pdf.cell(col_widths[i], 7, h, 1)
    pdf.ln()
    pdf.set_font("Arial", '', 8)
    for r in receipts:
        pdf.cell(col_widths[0], 7, r.receipt_number[:10], 1)
        pdf.cell(col_widths[1], 7, r.customer_name[:14], 1)
        pdf.cell(col_widths[2], 7, r.employee.name[:14], 1)
        pdf.cell(col_widths[3], 7, r.branch[:14], 1)
        pdf.cell(col_widths[4], 7, f"INR {r.total_amount:,.0f}", 1)
        paid = r.token_amount if r.payment_type=='token' else r.amount_received
        pdf.cell(col_widths[5], 7, f"INR {paid:,.0f}", 1)
        pdf.cell(col_widths[6], 7, r.status, 1)
        pdf.ln()
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    return send_file(BytesIO(pdf_bytes), mimetype='application/pdf',
                     as_attachment=True, download_name='it_report.pdf')

@app.route('/it/report/excel')
@login_required
def it_report_excel():
    if current_user.role != 'IT': abort(403)
    export_type = request.args.get('type', 'filtered')
    branch = request.args.get('branch', '')
    em_id = request.args.get('em_id', '')
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    if export_type == 'all':
        receipts = Receipt.query.order_by(Receipt.created_at.desc()).all()
    else:
        query = Receipt.query
        if branch:
            query = query.filter(Receipt.branch == branch)
        if em_id:
            query = query.filter(Receipt.em_id == int(em_id))
        if start_date:
            query = query.filter(Receipt.created_at >= datetime.datetime.strptime(start_date, '%Y-%m-%d'))
        if end_date:
            query = query.filter(Receipt.created_at <= datetime.datetime.strptime(end_date, '%Y-%m-%d') + datetime.timedelta(days=1))
        receipts = query.order_by(Receipt.created_at.desc()).all()
    data = [{
        'Receipt No': r.receipt_number,
        'Customer': r.customer_name,
        'Email': r.customer_email,
        'Item': r.item_description,
        'Total': r.total_amount,
        'Payment Type': r.payment_type,
        'Token': r.token_amount,
        'Paid': r.amount_received,
        'Remaining': r.remaining_balance,
        'Status': r.status,
        'Date': r.created_at.strftime('%Y-%m-%d %H:%M'),
        'Employee': r.employee.name,
        'Branch': r.branch
    } for r in receipts]
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Receipts')
    output.seek(0)
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name='receipts_report.xlsx')


# ----------------------------------------------------------------------
# Database initialization (runs once on Vercel cold start)
# ----------------------------------------------------------------------
with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='it@cp.com').first():
        it = User(username='it@cp.com', role='IT', name='IT Admin', email='it@cp.com')
        it.set_password('password')
        db.session.add(it)
    if not User.query.filter_by(username='em1@cp.com').first():
        em = User(username='em1@cp.com', role='EM', name='John Employee',
                  email='em1@cp.com', branch='Main Branch')
        em.set_password('password')
        db.session.add(em)
    db.session.commit()
    print("✅ Database tables ready and demo users created (if missing).")

# ----------------------------------------------------------------------
# Vercel entry point – 'app' is the WSGI callable.
# No if __name__ == '__main__' block needed.
# ----------------------------------------------------------------------
