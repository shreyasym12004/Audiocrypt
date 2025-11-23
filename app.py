import os
import time
from flask import Flask, render_template, request, redirect, url_for, session, send_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from pymongo import MongoClient

# Flask app setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# MongoDB setup
client = MongoClient('mongodb://localhost:27017/')
db = client['audio_encryptor']
users_collection = db['users']

# Directories
UPLOAD_FOLDER = 'uploads'
DECRYPTED_FOLDER = 'decrypted'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Utility functions
def generate_symmetric_key():
    """Generate a symmetric key using ECDH."""
    private_key_a = ec.generate_private_key(ec.SECP256R1())
    private_key_b = ec.generate_private_key(ec.SECP256R1())
    shared_secret = private_key_a.exchange(ec.ECDH(), private_key_b.public_key())
    symmetric_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"encryption-key"
    ).derive(shared_secret)
    return symmetric_key

def derive_chaotic_key(symmetric_key):
    """Derive a chaotic key for additional encryption."""
    chaotic_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"chaotic-key"
    ).derive(symmetric_key)
    return chaotic_key

def generate_salt():
    """Generate a random salt for password hashing."""
    return os.urandom(16)


def hash_password(password, salt):
    """Hash a password using PBKDF2 with SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # Adjust iterations for security needs
        backend=default_backend()
    )
    return kdf.derive(password.encode()) + salt


def verify_password(hashed_password, salt, password):
    """Verify a password against a stored hash."""
    password_to_check = hash_password(password.encode(), salt)
    return password_to_check == hashed_password


def encrypt_data(data, key):
    """Encrypt data using AES in CBC mode."""
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data


def decrypt_data(encrypted_data, key):
    """Decrypt data using AES in CBC mode."""
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


def read_file(file_path):
    """Read the contents of a file."""
    with open(file_path, "rb") as f:
        return f.read()


def write_file(file_path, data):
    """Write data to a file."""
    with open(file_path, "wb") as f:
        f.write(data)



# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username already exists in the database
        if users_collection.find_one({'username': username}):
            return render_template('signup.html', alert_message='Username already exists!')

        # Generate a random salt
        salt = generate_salt()

        # Hash the password using PBKDF2 with SHA256
        hashed_password = hash_password(password, salt)

        # Store the username and hashed password
        users_collection.insert_one({'username': username, 'hashed_password': hashed_password, 'salt': salt})
        alert_message = 'Account created successfully! Please login.'
        time.sleep(2)  # Simulate a delay for security (optional)
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Load the user from the database
        user = users_collection.find_one({'username': username})
        
        if user and user['password'] == password:
            session['username'] = username
            alert_message = 'Login successful!'
            return redirect(url_for('audio_options'))
        else:
            return render_template('login.html', alert_message='Invalid username or password!')
    return render_template('login.html')

@app.route('/options')
def audio_options():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('options.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/audio_encryption', methods=['GET', 'POST'])
def audio_encryption():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('audio_file')
        if file and file.filename.endswith('.mp3'):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            original_data = read_file(file_path)
            symmetric_key = generate_symmetric_key()
            chaotic_key = derive_chaotic_key(symmetric_key)

            encrypted_data = encrypt_data(original_data, symmetric_key, chaotic_key)
            encrypted_file = os.path.splitext(filename)[0] + ".enc"
            encrypted_file_path = os.path.join(UPLOAD_FOLDER, encrypted_file)
            write_file(encrypted_file_path, encrypted_data)

            # Save the symmetric_key to session or a secure storage for later decryption
            session['symmetric_key'] = symmetric_key.hex()

            return render_template('audio_encryption.html', message="File encrypted successfully!", encrypted_file=encrypted_file)
        else:
            return render_template('audio_encryption.html', message="Please upload a valid MP3 file!")
    return render_template('audio_encryption.html')

@app.route('/audio_decryption', methods=['GET', 'POST'])
def audio_decryption():
    if 'username' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('encrypted_file')
        if file and file.filename.endswith('.enc'):
            filename = secure_filename(file.filename)
            file_path = os.path.join(UPLOAD_FOLDER, filename)
            file.save(file_path)

            encrypted_data = read_file(file_path)

            # Retrieve the symmetric key from session (assuming it's saved during encryption)
            symmetric_key = bytes.fromhex(session.get('symmetric_key'))

            chaotic_key = derive_chaotic_key(symmetric_key)

            try:
                decrypted_data = decrypt_data(encrypted_data, symmetric_key, chaotic_key)
                decrypted_file = filename.replace('.enc', '.mp3')
                decrypted_path = os.path.join(DECRYPTED_FOLDER, decrypted_file)
                write_file(decrypted_path, decrypted_data)
                return render_template('audio_decryption.html', message="File decrypted successfully!", decrypted_file=decrypted_file)
            except ValueError as e:
                return render_template('audio_decryption.html', message=f"Decryption failed: {e}")
        else:
            return render_template('audio_decryption.html', message="Please upload a valid encrypted file!")
    return render_template('audio_decryption.html')
@app.route('/download/uploads/<filename>')
def download_upload_file(filename):
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    print(f"Looking for file at: {file_path}")  # Debugging line
    if not os.path.exists(file_path):
        return "File not found!", 404
    return send_file(file_path, as_attachment=True, mimetype='audio/mp3')


@app.route('/download/<filename>')
def download_file(filename):
    file_path = os.path.join(DECRYPTED_FOLDER, filename)
    if not os.path.exists(file_path):
        return "File not found!", 404
    return send_file(file_path, as_attachment=True, mimetype='audio/mp3')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('home'))

# Run the app
if __name__ == '__main__':
    app.run(debug=True)
