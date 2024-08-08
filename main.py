from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file
from flask_socketio import SocketIO
from scapy.all import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
import threading
import json
import os
import smtplib
import logging
from email.mime.text import MIMEText
from flask_migrate import Migrate
import string
import random
from datetime import timedelta
from dotenv import load_dotenv
import tempfile
import plotly.graph_objs as go

# Load environment variables from .env file
load_dotenv()

class Config:
    SECRET_KEY = os.urandom(24).hex()
    PERMANENT_SESSION_LIFETIME = timedelta(minutes=30)
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///network_traffic.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp.mailgun.org')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    SMTP_USERNAME = os.environ.get('SMTP_USERNAME', 'postmaster@sandbox9b4e72ac48bb44c6b11848558d20daa5.mailgun.org')
    SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '75ba2f8ff9de072438dc9ecbab2d237b-0f1db83d-89629a56')

app = Flask(__name__)
app.config.from_object(Config)
socketio = SocketIO(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    otp = db.Column(db.String(6), nullable=True)  # Store OTP for email verification

# Packet model
class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    src_ip = db.Column(db.String(50))
    dst_ip = db.Column(db.String(50))
    protocol = db.Column(db.String(200))
    ethernet_dst = db.Column(db.String(50))
    ethernet_src = db.Column(db.String(50))
    ethernet_type = db.Column(db.String(50))
    ip_version = db.Column(db.Integer)
    ip_ihl = db.Column(db.Integer)
    ip_tos = db.Column(db.Integer)
    ip_len = db.Column(db.Integer)
    ip_id = db.Column(db.Integer)
    ip_flags = db.Column(db.String(50))
    ip_frag = db.Column(db.Integer)
    ip_ttl = db.Column(db.Integer)
    ip_proto = db.Column(db.Integer)
    ip_chksum = db.Column(db.Integer)
    tcp_sport = db.Column(db.Integer)
    tcp_dport = db.Column(db.Integer)
    tcp_seq = db.Column(db.Integer)
    tcp_ack = db.Column(db.Integer)
    tcp_dataofs = db.Column(db.Integer)
    tcp_reserved = db.Column(db.Integer)
    tcp_flags = db.Column(db.String(50))
    tcp_window = db.Column(db.Integer)
    tcp_chksum = db.Column(db.Integer)
    tcp_urgptr = db.Column(db.Integer)
    tcp_options = db.Column(db.String(500))

with app.app_context():
    db.create_all()

# Event to control packet sniffing
sniffing_event = threading.Event()
captured_packets = []

# Global variable to hold the sniffing thread
sniff_thread = None

# Function to handle packet sniffing
def sniff_packets(filter_criteria=None):
    logger.info(f"Starting packet capture with filter: {filter_criteria}")
    while sniffing_event.is_set():
        try:
            packets = sniff(filter=filter_criteria, timeout=1)  # Use a short timeout for responsiveness
            for packet in packets:
                if not sniffing_event.is_set():  # Exit immediately if sniffing event is cleared
                    logger.info("Sniffing event cleared, stopping capture")
                    return
                if packet and IP in packet:
                    packet_info = extract_packet_info(packet)
                    with app.app_context():  # Ensure we're in the Flask application context
                        socketio.emit('packet_data', json.dumps(packet_info))
                        logger.info(f"Packet captured: {packet_info}")
                        store_packet_info(packet_info)
                    captured_packets.append(packet)
        except Exception as e:
            logger.error(f"Error during packet sniffing: {e}")
            sniffing_event.clear()

# Function to extract relevant packet information
def extract_packet_info(packet):
    packet_info = {
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'protocol': packet.summary(),
        'ethernet': {
            'dst': packet[Ether].dst,
            'src': packet[Ether].src,
            'type': str(packet[Ether].type)
        },
        'ip': {
            'version': packet[IP].version,
            'ihl': packet[IP].ihl,
            'tos': packet[IP].tos,
            'len': packet[IP].len,
            'id': packet[IP].id,
            'flags': str(packet[IP].flags),  # Ensure flags are strings
            'frag': packet[IP].frag,
            'ttl': packet[IP].ttl,
            'proto': packet[IP].proto,
            'chksum': packet[IP].chksum,
            'src': packet[IP].src,
            'dst': packet[IP].dst
        }
    }

    if TCP in packet:
        packet_info['tcp'] = {
            'sport': packet[TCP].sport,
            'dport': packet[TCP].dport,
            'seq': packet[TCP].seq,
            'ack': packet[TCP].ack,
            'dataofs': packet[TCP].dataofs,
            'reserved': packet[TCP].reserved,
            'flags': format(packet[TCP].flags, 'x') if isinstance(packet[TCP].flags, int) else str(packet[TCP].flags),
            'window': packet[TCP].window,
            'chksum': packet[TCP].chksum,
            'urgptr': packet[TCP].urgptr,
            'options': [str(option) for option in packet[TCP].options]
        }
    else:
        packet_info['tcp'] = None

    return packet_info

# Function to store packet information in the database
def store_packet_info(packet_info):
    packet = Packet(
        src_ip=packet_info['src_ip'],
        dst_ip=packet_info['dst_ip'],
        protocol=packet_info['protocol'],
        ethernet_dst=packet_info['ethernet']['dst'],
        ethernet_src=packet_info['ethernet']['src'],
        ethernet_type=packet_info['ethernet']['type'],
        ip_version=packet_info['ip']['version'],
        ip_ihl=packet_info['ip']['ihl'],
        ip_tos=packet_info['ip']['tos'],
        ip_len=packet_info['ip']['len'],
        ip_id=packet_info['ip']['id'],
        ip_flags=packet_info['ip']['flags'],
        ip_frag=packet_info['ip']['frag'],
        ip_ttl=packet_info['ip']['ttl'],
        ip_proto=packet_info['ip']['proto'],
        ip_chksum=packet_info['ip']['chksum'],
        tcp_sport=packet_info['tcp']['sport'] if packet_info['tcp'] else None,
        tcp_dport=packet_info['tcp']['dport'] if packet_info['tcp'] else None,
        tcp_seq=packet_info['tcp']['seq'] if packet_info['tcp'] else None,
        tcp_ack=packet_info['tcp']['ack'] if packet_info['tcp'] else None,
        tcp_dataofs=packet_info['tcp']['dataofs'] if packet_info['tcp'] else None,
        tcp_reserved=packet_info['tcp']['reserved'] if packet_info['tcp'] else None,
        tcp_flags=packet_info['tcp']['flags'] if packet_info['tcp'] else None,
        tcp_window=packet_info['tcp']['window'] if packet_info['tcp'] else None,
        tcp_chksum=packet_info['tcp']['chksum'] if packet_info['tcp'] else None,
        tcp_urgptr=packet_info['tcp']['urgptr'] if packet_info['tcp'] else None,
        tcp_options=json.dumps(packet_info['tcp']['options']) if packet_info['tcp'] else None
    )
    db.session.add(packet)
    db.session.commit()

# Function to generate a random OTP
def generate_otp(length=6):
    digits = string.digits
    otp = ''.join(random.choice(digits) for _ in range(length))
    logger.info(f"Generated OTP: {otp}")
    return otp

# Function to send OTP
def send_otp(email, otp):
    try:
        msg = MIMEText(f"Your OTP is: {otp}")
        msg['Subject'] = 'Your OTP Code'
        msg['From'] = app.config['SMTP_USERNAME']
        msg['To'] = email

        with smtplib.SMTP(app.config['SMTP_HOST'], app.config['SMTP_PORT']) as server:
            server.starttls()
            server.login(app.config['SMTP_USERNAME'], app.config['SMTP_PASSWORD'])
            server.send_message(msg)
            logger.info(f"OTP sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Error sending OTP email: {e}")
        return False

@app.route('/send_otp', methods=['POST'])
def send_otp_route():
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'error': 'Email is required.'}), 400

    otp = generate_otp()
    session['otp'] = otp
    session['email'] = email
    if send_otp(email, otp):
        return jsonify({'message': 'OTP sent successfully! Please check your email for the OTP.'})
    else:
        return jsonify({'error': 'Failed to send OTP. Please try again later.'}), 500

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global sniff_thread
    if sniffing_event.is_set():
        # If the event is already set, return that capture is already running
        logger.warning("Capture is already running")
        return jsonify({'message': 'Capture is already running'}), 400

    data = request.get_json()
    filter_criteria = data.get('filter', None)
    logger.info(f"Received filter criteria: {filter_criteria}")

    # Set the event to start sniffing
    sniffing_event.set()
    
    # Start the sniffing thread
    sniff_thread = threading.Thread(target=sniff_packets, args=(filter_criteria,))
    sniff_thread.start()
    logger.info("Packet capture started")
    return jsonify({'message': 'Capture started'})

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global sniff_thread
    if not sniffing_event.is_set():
        # If the event is not set, there's no capture to stop
        logger.warning("No capture to stop")
        return jsonify({'message': 'No capture to stop'}), 400

    # Clear the sniffing event and stop the thread
    sniffing_event.clear()
    if sniff_thread.is_alive():
        sniff_thread.join()
    sniff_thread = None
    logger.info("Packet capture stopped")
    return jsonify({'message': 'Capture stopped'})

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    if 'username' not in session:
        return redirect(url_for('login'))

    if 'pcap_file' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('index'))

    file = request.files['pcap_file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(url_for('index'))

    if file:
        temp_file = tempfile.NamedTemporaryFile(delete=False)
        file.save(temp_file.name)
        temp_file.seek(0)
        packets = rdpcap(temp_file.name)
        
        for packet in packets:
            if IP in packet:
                packet_info = extract_packet_info(packet)
                store_packet_info(packet_info)
        
        flash('PCAP file uploaded and packets stored successfully', 'success')
        return redirect(url_for('summary'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        otp = request.form['otp']
        stored_otp = session.get('otp')

        if otp != stored_otp:
            flash('Invalid OTP', 'danger')
        elif User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
        else:
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password)
            )
            db.session.add(new_user)
            db.session.commit()

            session.pop('otp', None)
            flash('Registration successful!', 'success')
            return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/description')
def description():
    return render_template('description.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/summary')
def summary():
    if 'username' not in session:
        return redirect(url_for('login'))
    page = request.args.get('page', 1, type=int)
    packets_pagination = Packet.query.paginate(page=page, per_page=10)
    packets = packets_pagination.items
    return render_template('summary.html', packets=packets, pagination=packets_pagination)

@app.route('/view_data')
def view_data():
    users = User.query.all()
    packets = Packet.query.all()
    return render_template('view_data.html', users=users, packets=packets)

@app.route('/download_pcap', methods=['GET', 'POST'])
def download_pcap():
    if request.method == 'POST':
        data = request.get_json()
        requested_filename = data.get('filename', 'captured_packets.pcap')
    else:
        requested_filename = request.args.get('filename', 'captured_packets.pcap')

    # Sanitize the filename
    allowed_chars = string.ascii_letters + string.digits + '_-.'
    sanitized_filename = ''.join(c for c in requested_filename if c in allowed_chars)

    if not sanitized_filename.endswith('.pcap'):
        sanitized_filename += '.pcap'

    temp_file = tempfile.NamedTemporaryFile(delete=False)
    wrpcap(temp_file.name, captured_packets)
    temp_file.seek(0)

    return send_file(
        temp_file.name,
        mimetype='application/vnd.tcpdump.pcap',
        as_attachment=True,
        download_name=sanitized_filename
    )

@app.route('/graph')
def graph():
    if 'username' not in session:
        return redirect(url_for('login'))

    # Generate some example data for the graph
    data = [go.Scatter(
        x=[1, 2, 3, 4, 5],
        y=[10, 15, 13, 17, 19],
        mode='lines+markers',
        name='Example Data'
    )]
    
    graph_data = json.dumps(data, cls=plotly.utils.PlotlyJSONEncoder)
    return render_template('graph.html', graph_data=graph_data)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    socketio.run(app, debug=True)
