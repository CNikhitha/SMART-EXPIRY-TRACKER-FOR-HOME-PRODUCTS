from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta 
import bcrypt
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import base64


import io
import os
import re
import secrets
import csv
import hashlib
import logging
import threading
import time
import unicodedata
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from functools import wraps
from sqlalchemy import or_, and_
from PIL import Image
OCR_AVAILABLE = True

try:
    import pytesseract
except ImportError as e:
    print("pytesseract missing:", e)
    OCR_AVAILABLE = False

try:
    import cv2
except ImportError as e:
    print("opencv missing:", e)
    OCR_AVAILABLE = False

try:
    from pdf2image import convert_from_path, convert_from_bytes
except ImportError as e:
    print("pdf2image missing:", e)
    OCR_AVAILABLE = False



app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expiry_products.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Logging (keep simple: logs to stdout)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("smart-expiry")

# Email configuration
# NOTE: For simplicity in your local setup, these are now hard-coded so that
# password reset and notification emails work regardless of how you start the app.
# If you ever deploy this, move these back to environment variables.
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'your-mail@gmail.com'
app.config['MAIL_PASSWORD'] = '16-digit password'  # Gmail app password
app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

# Optional SMS configuration (Twilio REST API via stdlib, no new deps)
app.config['SMS_PROVIDER'] = os.getenv('SMS_PROVIDER', '').lower()  # "twilio" to enable
app.config['TWILIO_ACCOUNT_SID'] = os.getenv('TWILIO_ACCOUNT_SID', '')
app.config['TWILIO_AUTH_TOKEN'] = os.getenv('TWILIO_AUTH_TOKEN', '')
app.config['TWILIO_FROM_NUMBER'] = os.getenv('TWILIO_FROM_NUMBER', '')
app.config['ALERT_SMS_TO_NUMBER'] = os.getenv('ALERT_SMS_TO_NUMBER', '')  # optional global destination

# Notification scheduler toggle
app.config['ENABLE_NOTIFICATION_SCHEDULER'] = os.getenv('ENABLE_NOTIFICATION_SCHEDULER', 'true').lower() == 'true'
app.config['NOTIFICATION_CHECK_INTERVAL_SECONDS'] = int(os.getenv('NOTIFICATION_CHECK_INTERVAL_SECONDS', '3600'))  # hourly
app.config['NOTIFICATION_LOOKAHEAD_DAYS'] = int(os.getenv('NOTIFICATION_LOOKAHEAD_DAYS', '7'))

# File upload configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'pdf', 'gif'}

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reset_token = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    products = db.relationship('Product', backref='user', lazy=True, cascade='all, delete-orphan')

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.String(100), nullable=False)
    product_name = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=True, default='General')
    purchase_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)
    # Ensure that when a User is deleted, all their Products are also removed
    # so that we don't hit "FOREIGN KEY constraint failed" errors.
    user_id = db.Column(
        db.Integer,
        db.ForeignKey('user.id', ondelete='CASCADE'),
        nullable=False,
    )
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_expired(self):
        return datetime.now().date() > self.expiry_date
    
    def days_until_expiry(self):
        delta = self.expiry_date - datetime.now().date()
        return delta.days

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def delete_expired_products():
    """
    Only COUNT expired items so they can still be viewed; no automatic deletion.
    """
    expired = Product.query.filter(Product.expiry_date < datetime.now().date()).count()
    return expired

def _safe_log_exception(prefix: str, exc: Exception):
    # Avoid dumping credentials while still getting actionable errors.
    logger.exception("%s: %s", prefix, str(exc))

def send_email_notification(user, products_expiring):
    """Send email notification for expiring products"""
    try:
        # Ensure we have valid email configuration
        if not app.config.get('MAIL_USERNAME') or app.config.get('MAIL_USERNAME') == 'your-email@gmail.com':
            logger.warning(f"Email not configured for user {user.username}. Please set MAIL_USERNAME and MAIL_PASSWORD environment variables.")
            return False
        
        if not user.email:
            logger.warning(f"User {user.username} has no email address.")
            return False
        
        msg = Message(
            subject='Products Expiring Soon - Smart Expiry',
            recipients=[user.email],
            html=render_template('email_notification.html', 
                               user=user,  
                               products=products_expiring),
            sender=app.config.get('MAIL_DEFAULT_SENDER')
        )
        mail.send(msg)
        logger.info(f"Email notification sent successfully to {user.email} for {len(products_expiring)} products")
        return True
    except Exception as e:
        _safe_log_exception("Email send failed (expiring-products)", e)
        logger.error(f"Failed to send email to {user.email}: {str(e)}")
        return False

def send_sms_notification(to_number: str, body: str) -> bool:
    """
    Send an SMS if configured. Currently supports Twilio via HTTPS using stdlib.
    This keeps DB/project structure unchanged and fails gracefully when not configured.
    """
    provider = (app.config.get('SMS_PROVIDER') or '').lower()
    if provider != 'twilio':
        return False

    sid = app.config.get('TWILIO_ACCOUNT_SID') or ''
    token = app.config.get('TWILIO_AUTH_TOKEN') or ''
    from_num = app.config.get('TWILIO_FROM_NUMBER') or ''
    if not (sid and token and from_num and to_number):
        logger.warning("SMS configured as twilio but missing required settings/number; skipping")
        return False

    try:
        # Twilio Messages API: POST /2010-04-01/Accounts/{AccountSid}/Messages.json
        # Use Basic Auth with sid:token
        import base64 as _b64
        import urllib.parse as _up

        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        data = _up.urlencode({"From": from_num, "To": to_number, "Body": body}).encode("utf-8")
        auth = _b64.b64encode(f"{sid}:{token}".encode("utf-8")).decode("ascii")
        req = Request(url, data=data, method="POST")
        req.add_header("Authorization", f"Basic {auth}")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urlopen(req, timeout=15) as resp:
            return 200 <= getattr(resp, "status", 200) < 300
    except (HTTPError, URLError, Exception) as e:
        _safe_log_exception("SMS send failed", e)
        return False

_last_notified_by_user_and_day = {}  # {user_id: "YYYY-MM-DD"} in-memory (no DB changes)

def check_and_send_notifications():
    """Check for expiring products and send notifications"""
    lookahead = int(app.config.get('NOTIFICATION_LOOKAHEAD_DAYS') or 7)
    today_key = datetime.utcnow().date().isoformat()
    users = User.query.all()
    for user in users:
        # de-dupe per user per day to avoid spamming on frequent scheduler ticks
        if _last_notified_by_user_and_day.get(user.id) == today_key:
            continue
        products = Product.query.filter_by(user_id=user.id).all()
        # "Less than 7 days" -> strictly >0 and <lookahead (default 7)
        expiring_soon = [
            p for p in products
            if (0 < p.days_until_expiry() < lookahead) and not p.is_expired()
        ]
        if expiring_soon:
            ok = send_email_notification(user, expiring_soon)
            # Optional global SMS (no per-user phone numbers in DB)
            sms_to = (app.config.get('ALERT_SMS_TO_NUMBER') or '').strip()
            if sms_to:
                try:
                    names = ", ".join([p.product_name for p in expiring_soon[:5]])
                    more = "" if len(expiring_soon) <= 5 else f" (+{len(expiring_soon) - 5} more)"
                    body = f"Smart Expiry: {len(expiring_soon)} item(s) expiring within {lookahead}d for {user.username}: {names}{more}"
                    send_sms_notification(sms_to, body)
                except Exception as e:
                    _safe_log_exception("SMS compose/send failed", e)
            if ok:
                _last_notified_by_user_and_day[user.id] = today_key

def _notification_loop():
    """Background notification loop (best-effort; no DB/schema changes)."""
    interval = int(app.config.get('NOTIFICATION_CHECK_INTERVAL_SECONDS') or 3600)
    while True:
        try:
            with app.app_context():
                check_and_send_notifications()
        except Exception as e:
            _safe_log_exception("Notification loop error", e)
        time.sleep(max(60, interval))

# Receipt scanning helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def preprocess_image(image):
    """Preprocess image for better OCR results"""
    if not OCR_AVAILABLE:
        return image
    try:
        if len(image.shape) == 3:
            gray = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2GRAY)
        else:
            gray = np.array(image)
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        denoised = cv2.fastNlMeansDenoising(thresh, None, 10, 7, 21)
        return Image.fromarray(denoised)
    except:
        return image

def extract_text_from_image(image_file):
    """Extract text from image using OCR"""
    if not OCR_AVAILABLE:
        flash('OCR libraries not available. Please install pytesseract, opencv-python, and pdf2image.', 'error')
        return None
    try:
        if image_file.filename.lower().endswith('.pdf'):
            image_file.seek(0)
            pdf_bytes = image_file.read()
            # pdf2image may expose convert_from_bytes; fall back to convert_from_path not possible with in-memory upload
            images = convert_from_bytes(pdf_bytes, dpi=300) if OCR_AVAILABLE else []
            if images:
                image = images[0]
            else:
                return None
        else:
            image = Image.open(image_file)
        
        processed_image = preprocess_image(image)
        # Try multiple PSM modes for better results
        configs = [
            r'--oem 3 --psm 6',  # Uniform block of text
            r'--oem 3 --psm 11',  # Sparse text
            r'--oem 3 --psm 4',   # Single column
        ]
        
        text = ""
        for config in configs:
            try:
                extracted = pytesseract.image_to_string(processed_image, config=config)
                if len(extracted) > len(text):
                    text = extracted
            except:
                continue
        
        return text if text else None
    except Exception as e:
        print(f"OCR Error: {e}")
        flash(f'OCR Error: {str(e)}. Please ensure Tesseract OCR is installed.', 'error')
        return None

def parse_receipt_text(text):
    """Parse receipt text to extract product information"""
    if not text:
        return []
    
    products = []
    lines = [line.strip() for line in text.split('\n') if line.strip()]
    
    # Find purchase date - look for "Bill Dt" or date patterns
    date_patterns = [
        r'Bill\s+Dt[:\s]+(\d{1,2}[/-]\d{1,2}[/-]\d{2,4})',  # Bill Dt: DD/MM/YYYY (priority)
        r'(\d{1,2}[/-]\d{1,2}[/-]\d{4})',  # DD/MM/YYYY or MM/DD/YYYY (4-digit year)
        r'(\d{1,2}[/-]\d{1,2}[/-]\d{2})',  # DD/MM/YY (2-digit year)
        r'(\d{4}[/-]\d{1,2}[/-]\d{1,2})',    # YYYY/MM/DD
        r'(\d{1,2}\s+\w+\s+\d{4})',          # DD Month YYYY
    ]
    
    purchase_date = datetime.now().date()
    for line in lines:
        for pattern in date_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                try:
                    date_str = match.group(1) if match.groups() else match.group(0)
                    # Try DD/MM/YYYY first (common in Indian receipts)
                    for fmt in ['%d/%m/%Y', '%d/%m/%y', '%d-%m-%Y', '%d-%m-%y', '%m/%d/%Y', '%m/%d/%y', '%Y/%m/%d', '%Y-%m-%d', '%d %B %Y', '%d %b %Y']:
                        try:
                            parsed_date = datetime.strptime(date_str, fmt).date()
                            # If 2-digit year, assume 2000s if > 50, else 2000s
                            if parsed_date.year < 1950:
                                parsed_date = parsed_date.replace(year=parsed_date.year + 100)
                            purchase_date = parsed_date
                            break
                        except:
                            continue
                    if purchase_date != datetime.now().date():
                        break
                except:
                    pass
        if purchase_date != datetime.now().date():
            break
    
    # Look for table structure (HSN, Particulars, etc.)
    # Pattern 1: Structured invoice with HSN/Particulars columns
    in_product_section = False
    skip_keywords = ['total', 'subtotal', 'tax', 'discount', 'cash', 'change', 'receipt', 'thank', 
                     'store', 'bill no', 'bill dt', 'cashier', 'hsn', 'particulars', 'qty', 'rate', 
                     'value', 'cgst', 'sgst', 'gst', 'invoice', 'amount']
    
    # Category detection keywords
    food_keywords = ['milk', 'butter', 'cheese', 'toned', 'moong', 'dal', 'tur', 'salt', 'sugar', 
                     'wheat', 'flour', 'biscuit', 'chocolate', 'kitkat', 'bournville', 'bread',
                     'heritage', 'aashirvaad', 'amul', 'britannia', 'freedom', 'sunflower', 'oil',
                     'shubhkart', 'cadbury', 'homechef', 'savorit', 'bambino', 'nestle', 'preturdal',
                     'chilly', 'guntur', 'elbow', 'ying', 'plain']
    medicine_keywords = ['tablet', 'capsule', 'medicine', 'syrup', 'cream', 'ointment', 'himalaya']
    cosmetics_keywords = ['soap', 'shampoo', 'cream', 'lotion', 'gel', 'foam', 'neem', 'gillette', 'rin']
    electronics_keywords = ['battery', 'charger', 'cable', 'adapter']
    household_keywords = ['pillow', 'bedsheet', 'cushion', 'cover', 'sheet']
    
    def _norm(s: str) -> str:
        s = unicodedata.normalize("NFKC", s)
        s = s.replace('\u00a0', ' ')
        return re.sub(r'\s+', ' ', s).strip()

    def _looks_like_total_or_footer(s: str) -> bool:
        sl = s.lower()
        return any(k in sl for k in ['total', 'subtotal', 'grand total', 'net', 'round off', 'balance', 'thank', 'visit again'])

    def _strip_trailing_columns(name: str) -> str:
        # Remove trailing qty/rate/amount-like columns and currency symbols.
        name = re.sub(r'[\s\-:]*[₹$€£¥]\s*\d[\d,]*\.?\d*\s*$', '', name)
        name = re.sub(r'\s+\d+\s*[xX*]\s*\d[\d,]*\.?\d*\s*$', '', name)  # "2 x 45.00"
        name = re.sub(r'\s+\d+\.?\d*\s*(kg|g|gm|ml|l|pcs|pc|pack|pkt)\s*$', '', name, flags=re.IGNORECASE)
        name = re.sub(r'\s+\d[\d,]*\.?\d*\s*$', '', name)
        return name.strip(' -:\t')

    def _clean_name(name: str) -> str:
        name = _norm(name)
        # Fix very common OCR confusions in item names (limited, safe substitutions)
        name = name.replace('|', 'I')
        name = re.sub(r'[^0-9A-Za-z&\-\s/\.]', '', name)
        name = re.sub(r'\s+', ' ', name).strip()
        return name

    def _generate_receipt_product_id(purchase_date_obj, product_name: str, index_hint: int) -> str:
        # deterministic, stable id based on date + cleaned name + index hint (no DB changes)
        base = f"{purchase_date_obj.isoformat()}|{product_name.lower()}|{index_hint}"
        digest = hashlib.sha1(base.encode("utf-8")).hexdigest()[:10]
        return f"RCP_{purchase_date_obj.strftime('%Y%m%d')}_{digest}"

    product_count = 0
    seen_products = set()  # To avoid duplicates
    
    for i, line in enumerate(lines):
        line = _norm(line)
        line_lower = line.lower()
        
        # Skip header/footer lines
        if any(keyword in line_lower for keyword in ['bill no', 'bill dt', 'cashier', 'total qty', 'total value']):
            continue
        
        # Detect if we're in product section (after seeing HSN or Particulars header)
        if 'particulars' in line_lower or 'hsn' in line_lower:
            in_product_section = True
            continue

        # Stop when totals/footer start (common receipts)
        if _looks_like_total_or_footer(line):
            if in_product_section:
                break
            continue
        
        # Skip if it's just numbers or totals
        if re.match(r'^[\d\s\.,₹$€£¥]+$', line) or len(line) < 3:
            continue
        
        # Try to extract product name from various formats (be stricter to avoid bogus matches)
        product_name = None
        
        # Format 1: HSN code followed by product name (e.g., "040120 HERITAGE TONED -11t")
        # Match 6-digit HSN code at start, then product name, then optional numbers
        hsn_pattern = r'^(\d{6})\s+(.+?)(?:\s+[\d.,]+)*\s*$'
        match = re.match(hsn_pattern, line)
        if match:
            product_name = match.group(2).strip()
            product_name = _strip_trailing_columns(product_name)
        
        # Format 2: Product name with quantity/rate at end
        if not product_name:
            # Many receipts end a line with amount; only accept if the line has both letters and a trailing amount
            # Example: "KITKAT 3 10.00 30.00" or "AMUL MILK 25.00"
            if re.search(r'[A-Za-z].*[₹$€£¥]?\s*\d[\d,]*\.?\d*\s*$', line) and len(line.split()) >= 2:
                product_name = re.sub(r'\s+[₹$€£¥]?\s*\d[\d,]*\.?\d*\s*$', '', line).strip()
                product_name = _strip_trailing_columns(product_name)
        
        # Format 3: Simple product name extraction
        if not product_name:
            # Remove leading numbers and trailing prices
            cleaned = re.sub(r'^\d+\s+', '', line)
            cleaned = _strip_trailing_columns(cleaned)
            if len(cleaned) > 2:
                product_name = cleaned
        
        # Validate and clean product name
        if product_name:
            product_name = _clean_name(product_name)
            # Remove common prefixes/suffixes
            product_name = re.sub(r'^(HSN|ITEM|PROD)\s*', '', product_name, flags=re.IGNORECASE)
            product_name = re.sub(r'\s+(QTY|KG|G|ML|L|PCS)\s*$', '', product_name, flags=re.IGNORECASE)
            product_name = product_name.strip()
            
            # Skip if too short or is a header
            if len(product_name) < 2:
                continue
            # If we never saw the header, be stricter: require at least 3 letters total
            if not in_product_section and len(re.findall(r'[A-Za-z]', product_name)) < 3:
                continue
            if product_name.lower() in ['item', 'description', 'product', 'particulars', 'hsn', 'qty', 'rate', 'value']:
                continue
            if any(keyword in product_name.lower() for keyword in skip_keywords):
                continue
            # Avoid store/address lines (too many digits or looks like phone/GSTIN)
            if re.search(r'\b(gstin|gstin:|tin|phone|ph:|mob|mobile)\b', product_name, flags=re.IGNORECASE):
                continue
            if len(re.findall(r'\d', product_name)) > max(3, len(product_name) // 4):
                continue
            
            # Skip duplicates
            if product_name.lower() in seen_products:
                continue
            seen_products.add(product_name.lower())
            
            # Determine category
            category = 'General'
            product_lower = product_name.lower()
            if any(keyword in product_lower for keyword in food_keywords):
                category = 'Food'
            elif any(keyword in product_lower for keyword in medicine_keywords):
                category = 'Medicine'
            elif any(keyword in product_lower for keyword in cosmetics_keywords):
                category = 'Cosmetics'
            elif any(keyword in product_lower for keyword in electronics_keywords):
                category = 'Electronics'
            elif any(keyword in product_lower for keyword in household_keywords):
                category = 'Other'
            
            # Set expiry date based on category
            if category == 'Food':
                expiry_days = 7
            elif category == 'Medicine':
                expiry_days = 365  # Medicine typically lasts longer
            elif category == 'Cosmetics':
                expiry_days = 180
            else:
                expiry_days = 30
            
            expiry_date = purchase_date + timedelta(days=expiry_days)
            
            product_id = _generate_receipt_product_id(purchase_date, product_name, product_count + 1)
            
            products.append({
                'product_id': product_id,
                'product_name': product_name,
                'category': category,
                'purchase_date': purchase_date,
                'expiry_date': expiry_date
            })
            
            product_count += 1
            if product_count >= 50:  # Limit to 50 products
                break
    
    return products

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('signup.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('signup.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'error')
            return render_template('signup.html')
        
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        user = User(username=username, email=email, password_hash=password_hash)
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please enter both username and password', 'error')
            return render_template('login.html')
        
        user = User.query.filter_by(username=username).first()
        
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash.encode('utf-8')):
            login_user(user)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token = token
            user.reset_token_expiry = datetime.utcnow() + timedelta(hours=1)
            db.session.commit()
            
            reset_url = url_for('reset_password', token=token, _external=True)
            try:
                # Check if email is configured (basic sanity check only)
                if not app.config.get('MAIL_USERNAME') or not app.config.get('MAIL_PASSWORD'):
                    logger.warning("Email not configured. MAIL_USERNAME or MAIL_PASSWORD is missing.")
                    flash('Email service not configured. Please contact administrator.', 'error')
                    return render_template('forgot_password.html')
                
                msg = Message(
                    subject='Password Reset - Smart Expiry',
                    recipients=[user.email],
                    
                    html=render_template('reset_password_email.html', reset_url=reset_url),
                    sender=app.config.get('MAIL_DEFAULT_SENDER')
                )
                mail.send(msg)
                logger.info(f"Password reset email sent successfully to {user.email}")
                flash('Password reset link sent to your email!', 'success')
            except Exception as e:
                # Log the error with details
                _safe_log_exception("Email send failed (password reset)", e)
                logger.error(f"Failed to send password reset email to {user.email}: {str(e)}")
                # Show user-friendly error message
                flash('Failed to send email. Please check email configuration or try again later.', 'error')
        else:
            flash('Email not found', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.utcnow():
        flash('Invalid or expired reset token', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('reset_password.html', token=token)
        
        user.password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        user.reset_token = None
        user.reset_token_expiry = None
        db.session.commit()
        
        flash('Password reset successfully! Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
@login_required
def dashboard():
    deleted_count = delete_expired_products()
    
    search_query = request.args.get('search', '')
    category_filter = request.args.get('category', '')
    status_filter = request.args.get('status', '')
    date_from = request.args.get('date_from', '')
    date_to = request.args.get('date_to', '')
    
    query = Product.query.filter_by(user_id=current_user.id)
    
    if search_query:
        query = query.filter(or_(
            Product.product_name.ilike(f'%{search_query}%'),
            Product.product_id.ilike(f'%{search_query}%')
        ))
    
    if category_filter:
        query = query.filter(Product.category == category_filter)
    
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            query = query.filter(Product.expiry_date >= date_from_obj)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            query = query.filter(Product.expiry_date <= date_to_obj)
        except ValueError:
            pass
    
    products = query.order_by(Product.expiry_date).all()
    
    if status_filter:
        if status_filter == 'expired':
            products = [p for p in products if p.is_expired()]
        elif status_filter == 'expiring_soon':
            products = [p for p in products if 0 <= p.days_until_expiry() <= 7 and not p.is_expired()]
        elif status_filter == 'active':
            products = [p for p in products if not p.is_expired() and p.days_until_expiry() > 7]
    
    all_products = Product.query.filter_by(user_id=current_user.id).all()
    categories = sorted(set([p.category for p in all_products if p.category]))
    
    total_products = len(all_products)
    expired_count = sum(1 for p in all_products if p.is_expired())
    expiring_soon = sum(1 for p in all_products if 0 <= p.days_until_expiry() <= 7 and not p.is_expired())
    
    return render_template('dashboard.html', 
                         products=products, 
                         total_products=total_products,
                         expired_count=expired_count,
                         expiring_soon=expiring_soon,
                         deleted_count=deleted_count,
                         categories=categories,
                         search_query=search_query,
                         category_filter=category_filter,
                         status_filter=status_filter,
                         date_from=date_from,
                         date_to=date_to)

@app.route('/add_product', methods=['GET', 'POST'])
@login_required
def add_product():
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        product_name = request.form.get('product_name')
        category = request.form.get('category', 'General')
        purchase_date = request.form.get('purchase_date')
        expiry_date = request.form.get('expiry_date')
        
        if not all([product_id, product_name, purchase_date, expiry_date]):
            flash('All fields are required', 'error')
            return render_template('add_product.html')
        
        try:
            purchase_date = datetime.strptime(purchase_date, '%Y-%m-%d').date()
            expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
            
            if expiry_date < purchase_date:
                flash('Expiry date cannot be before purchase date', 'error')
                return render_template('add_product.html')
            
            product = Product(
                product_id=product_id,
                product_name=product_name,
                category=category,
                purchase_date=purchase_date,
                expiry_date=expiry_date,
                user_id=current_user.id
            )
            
            db.session.add(product)
            db.session.commit()
            
            flash('Product added successfully!', 'success')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid date format', 'error')
    
    all_products = Product.query.filter_by(user_id=current_user.id).all()
    categories = sorted(set([p.category for p in all_products if p.category]))
    default_categories = ['General', 'Food', 'Medicine', 'Cosmetics', 'Electronics', 'Other']
    all_categories = sorted(set(default_categories + categories))
    
    return render_template('add_product.html', categories=all_categories)

@app.route('/edit_product/<int:product_id>', methods=['GET', 'POST'])
@login_required
def edit_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        product.product_id = request.form.get('product_id')
        product.product_name = request.form.get('product_name')
        product.category = request.form.get('category', 'General')
        purchase_date = request.form.get('purchase_date')
        expiry_date = request.form.get('expiry_date')
        
        try:
            product.purchase_date = datetime.strptime(purchase_date, '%Y-%m-%d').date()
            product.expiry_date = datetime.strptime(expiry_date, '%Y-%m-%d').date()
            
            if product.expiry_date < product.purchase_date:
                flash('Expiry date cannot be before purchase date', 'error')
                return render_template('edit_product.html', product=product)
            
            db.session.commit()
            flash('Product updated successfully!', 'success')
            return redirect(url_for('dashboard'))
        except ValueError:
            flash('Invalid date format', 'error')
    
    all_products = Product.query.filter_by(user_id=current_user.id).all()
    categories = sorted(set([p.category for p in all_products if p.category]))
    default_categories = ['General', 'Food', 'Medicine', 'Cosmetics', 'Electronics', 'Other']
    all_categories = sorted(set(default_categories + categories))
    
    return render_template('edit_product.html', product=product, categories=all_categories)

@app.route('/delete_product/<int:product_id>', methods=['POST'])
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    
    if product.user_id != current_user.id:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
    
    db.session.delete(product)
    db.session.commit()
    flash('Product deleted successfully!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/calendar')
@login_required
def calendar():
    products = Product.query.filter_by(user_id=current_user.id).all()
    calendar_data = {}
    for product in products:
        expiry_str = product.expiry_date.isoformat()
        if expiry_str not in calendar_data:
            calendar_data[expiry_str] = []
        calendar_data[expiry_str].append(product)
    
    return render_template('calendar.html', calendar_data=calendar_data, products=products)

@app.route('/export')
@login_required
def export_products():
    products = Product.query.filter_by(user_id=current_user.id).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Product ID', 'Product Name', 'Category', 'Purchase Date', 'Expiry Date', 'Days Until Expiry', 'Status'])
    
    for product in products:
        status = 'Expired' if product.is_expired() else ('Expiring Soon' if product.days_until_expiry() <= 7 else 'Active')
        writer.writerow([
            product.product_id,
            product.product_name,
            product.category or 'General',
            product.purchase_date.isoformat(),
            product.expiry_date.isoformat(),
            product.days_until_expiry(),
            status
        ])
    
    output.seek(0)
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = f'attachment; filename=products_{datetime.now().strftime("%Y%m%d")}.csv'
    return response

@app.route('/import', methods=['GET', 'POST'])
@login_required
def import_products():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(url_for('import_products'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(url_for('import_products'))
        
        try:
            df = pd.read_csv(file)
            required_columns = ['Product ID', 'Product Name', 'Purchase Date', 'Expiry Date']
            
            if not all(col in df.columns for col in required_columns):
                flash('CSV must contain: Product ID, Product Name, Purchase Date, Expiry Date', 'error')
                return redirect(url_for('import_products'))
            
            imported = 0
            errors = []
            
            for index, row in df.iterrows():
                try:
                    product_id = str(row['Product ID'])
                    product_name = str(row['Product Name'])
                    category = str(row.get('Category', 'General'))
                    purchase_date = pd.to_datetime(row['Purchase Date']).date()
                    expiry_date = pd.to_datetime(row['Expiry Date']).date()
                    
                    if expiry_date < purchase_date:
                        errors.append(f"Row {index + 2}: Expiry date before purchase date")
                        continue
                    
                    product = Product(
                        product_id=product_id,
                        product_name=product_name,
                        category=category,
                        purchase_date=purchase_date,
                        expiry_date=expiry_date,
                        user_id=current_user.id
                    )
                    
                    db.session.add(product)
                    imported += 1
                except Exception as e:
                    errors.append(f"Row {index + 2}: {str(e)}")
            
            db.session.commit()
            
            if errors:
                flash(f'Imported {imported} products. Errors: {len(errors)}', 'warning')
            else:
                flash(f'Successfully imported {imported} products!', 'success')
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Error importing file: {str(e)}', 'error')
    
    return render_template('import.html')

@app.route('/scan_receipt', methods=['GET', 'POST'])
@login_required
def scan_receipt():
    """
    OCR-based receipt scanning is disabled for now.
    This page simply informs the user that the feature is a future enhancement.
    """
    if request.method == 'POST':
        flash('Scan Receipt is a future enhancement and is currently disabled.', 'info')
    return render_template('scan_receipt.html', ocr_future_enhancement=True)

@app.route('/analytics')
@login_required
def analytics():
    products = Product.query.filter_by(user_id=current_user.id).all()
    
    if not products:
        return render_template('analytics.html', chart_data=None, stats=None)
    
    data = []
    for p in products:
        data.append({
            'product_name': p.product_name,
            'category': p.category or 'General',
            'purchase_date': p.purchase_date,
            'expiry_date': p.expiry_date,
            'days_until_expiry': p.days_until_expiry(),
            'is_expired': p.is_expired()
        })
    
    df = pd.DataFrame(data)
    charts = {}
    
    # Chart 1: Products by expiry status
    fig, ax = plt.subplots(figsize=(8, 6))
    status_counts = df['is_expired'].value_counts()
    labels = ['Active', 'Expired']
    colors = ['#4CAF50', '#F44336']
    ax.pie([status_counts.get(False, 0), status_counts.get(True, 0)], 
           labels=labels, autopct='%1.1f%%', colors=colors, startangle=90)
    ax.set_title('Products by Expiry Status', fontsize=14, fontweight='bold')
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
    img_buffer.seek(0)
    charts['status'] = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close()
    
    # Chart 2: Products by category
    if 'category' in df.columns:
        fig, ax = plt.subplots(figsize=(10, 6))
        category_counts = df['category'].value_counts()
        ax.bar(category_counts.index, category_counts.values, color='#2196F3')
        ax.set_xlabel('Category', fontsize=12)
        ax.set_ylabel('Number of Products', fontsize=12)
        ax.set_title('Products by Category', fontsize=14, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
        img_buffer.seek(0)
        charts['category'] = base64.b64encode(img_buffer.getvalue()).decode()
        plt.close()
    
    # Chart 3: Products expiring in next 30 days
    fig, ax = plt.subplots(figsize=(10, 6))
    expiring_soon = df[(df['days_until_expiry'] >= 0) & (df['days_until_expiry'] <= 30) & (~df['is_expired'])]
    if not expiring_soon.empty:
        expiring_soon = expiring_soon.sort_values('days_until_expiry')
        ax.barh(expiring_soon['product_name'], expiring_soon['days_until_expiry'], color='#FF9800')
        ax.set_xlabel('Days Until Expiry', fontsize=12)
        ax.set_title('Products Expiring in Next 30 Days', fontsize=14, fontweight='bold')
        ax.invert_yaxis()
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
    img_buffer.seek(0)
    charts['expiring'] = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close()
    
    # Chart 4: Monthly trends
    fig, ax = plt.subplots(figsize=(12, 6))
    df['purchase_month'] = pd.to_datetime(df['purchase_date']).dt.to_period('M')
    df['expiry_month'] = pd.to_datetime(df['expiry_date']).dt.to_period('M')
    
    purchase_counts = df['purchase_month'].value_counts().sort_index()
    expiry_counts = df['expiry_month'].value_counts().sort_index()
    
    months = sorted(set(list(purchase_counts.index) + list(expiry_counts.index)))
    purchase_values = [purchase_counts.get(m, 0) for m in months]
    expiry_values = [expiry_counts.get(m, 0) for m in months]
    
    x = range(len(months))
    width = 0.35
    ax.bar([i - width/2 for i in x], purchase_values, width, label='Purchased', color='#2196F3')
    ax.bar([i + width/2 for i in x], expiry_values, width, label='Expiring', color='#FF5722')
    ax.set_xlabel('Month', fontsize=12)
    ax.set_ylabel('Number of Products', fontsize=12)
    ax.set_title('Monthly Purchase and Expiry Trends', fontsize=14, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels([str(m) for m in months], rotation=45, ha='right')
    ax.legend()
    plt.tight_layout()
    
    img_buffer = io.BytesIO()
    plt.savefig(img_buffer, format='png', dpi=100, bbox_inches='tight')
    img_buffer.seek(0)
    charts['trends'] = base64.b64encode(img_buffer.getvalue()).decode()
    plt.close()
    
    stats = {
        'total': len(df),
        'expired': int(df['is_expired'].sum()),
        'active': int((~df['is_expired']).sum()),
        'expiring_soon': int(((df['days_until_expiry'] >= 0) & (df['days_until_expiry'] <= 7) & (~df['is_expired'])).sum()),
        'avg_days_until_expiry': float(df[~df['is_expired']]['days_until_expiry'].mean()) if (~df['is_expired']).any() else 0
    }
    
    return render_template('analytics.html', charts=charts, stats=stats)

@app.route('/api/products')
@login_required
def api_products():
    products = Product.query.filter_by(user_id=current_user.id).all()
    return jsonify([{
        'id': p.id,
        'product_id': p.product_id,
        'product_name': p.product_name,
        'category': p.category,
        'purchase_date': p.purchase_date.isoformat(),
        'expiry_date': p.expiry_date.isoformat(),
        'days_until_expiry': p.days_until_expiry(),
        'is_expired': p.is_expired()
    } for p in products])

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    # Best-effort background notifier (no DB/schema changes). Disable via ENABLE_NOTIFICATION_SCHEDULER=false
    if app.config.get('ENABLE_NOTIFICATION_SCHEDULER', True):
        t = threading.Thread(target=_notification_loop, daemon=True)
        t.start()
    app.run(debug=True, host='0.0.0.0', port=5000)
