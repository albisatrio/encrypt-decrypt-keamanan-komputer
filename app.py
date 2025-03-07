import logging
from flask import Flask, request, render_template, send_file, jsonify, redirect, url_for, session
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib
import base64
import secrets
import random

# Initialize Flask app
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)  # Key untuk session

# Set up logging
log_filename = 'app.log'  # Nama file log
logging.basicConfig(
    level=logging.DEBUG,  # Set level log
    format='%(asctime)s - %(levelname)s - %(message)s',  # Format log
    handlers=[
        logging.StreamHandler(),  # Untuk menampilkan log di konsol
        logging.FileHandler(log_filename)  # Untuk menyimpan log ke file
    ]
)

# Directory to store uploads
UPLOAD_FOLDER = 'uploads'
PRIVATE_KEY_FOLDER = 'keys'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PRIVATE_KEY_FOLDER, exist_ok=True)

# Utility to clean up keys folder
def clear_keys_folder():
    logging.info('Memulai pembersihan folder kunci...')
    for filename in os.listdir(PRIVATE_KEY_FOLDER):
        file_path = os.path.join(PRIVATE_KEY_FOLDER, filename)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
                logging.info(f'Menghapus file: {file_path}')
        except Exception as e:
            logging.error(f'Gagal menghapus {file_path}: {e}')

# Generate a new RSA key pair and save it to a file with a unique name
def generate_private_key_file():
    logging.info('Membuat pasangan kunci RSA baru...')
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    random_suffix = str(random.randint(10**9, 10**10 - 1))  # Generate 10-digit random number
    key_path = os.path.join(PRIVATE_KEY_FOLDER, f'private_key_{random_suffix}.pem')
    with open(key_path, 'wb') as f:
        f.write(private_pem)
    return private_key, key_path

def aes_encrypt(data, key, filename=""):
    logging.info('Melakukan enkripsi AES')
    
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = iv + encryptor.update(data) + encryptor.finalize()
    
    logging.debug('Enkripsi AES selesai.')
    return encrypted_data

def aes_decrypt(data, key, filename=""):
    logging.info('Melakukan dekripsi AES')
    
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(data[16:]) + decryptor.finalize()
    
    logging.debug('Dekripsi AES selesai.')
    return decrypted_data

# Hash password helper
def hash_password(password):
    logging.info('Melakukan hash pada password...')
    hashed = hashlib.sha256(password.encode()).hexdigest()
    logging.debug('Password berhasil di-hash')
    return hashed

# RSA encryption helper
def rsa_encrypt(secret_key, public_key):
    logging.info('Melakukan enkripsi RSA untuk secret key...')
    encrypted_secret_key = public_key.encrypt(
        secret_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.debug('Enkripsi RSA selesai.')
    return encrypted_secret_key

# RSA decryption helper
def rsa_decrypt(encrypted_key, private_key):
    logging.info('Melakukan dekripsi RSA untuk secret key...')
    decrypted_secret_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    logging.debug('Dekripsi RSA selesai.')
    return decrypted_secret_key

KEY_ENCRYPTION_KEY = hashlib.sha256(b"static_key_for_keys").digest()  # Kunci AES untuk mengenkripsi file .key


@app.route('/')
def index():
    logging.info('Mengakses halaman utama.')
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    password = request.form['password']
    secret_key = secrets.token_bytes(32)  # Generate AES key

    # Tambahkan 7 digit kode random ke nama file
    random_suffix = ''.join(random.choices('0123456789abcdefghijklmnopqrstuvwxyzQWERTYUIOPLKJHGFDSAZXCVBNM', k=7))
    filename, file_extension = os.path.splitext(file.filename)
    new_filename = f"{filename}{random_suffix}{file_extension}"
    encrypted_path = os.path.join(UPLOAD_FOLDER, new_filename)

    logging.info(f'Nama file baru yang dihasilkan: {new_filename}')

    # Log sebelum mengenkripsi file pengguna
    logging.info('Memulai enkripsi file pengguna menggunakan AES...')
    encrypted_data = aes_encrypt(file.read(), secret_key)

    # Save encrypted file
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)
    logging.info(f'File terenkripsi disimpan di: {encrypted_path}')

    # Generate RSA key pair for the file
    private_key, private_key_path = generate_private_key_file()
    public_key = private_key.public_key()

    # Encrypt the AES key with the RSA public key
    encrypted_secret_key = rsa_encrypt(secret_key, public_key)

    # Encode data to base64
    encrypted_secret_key_b64 = base64.b64encode(encrypted_secret_key).decode('utf-8')
    hashed_password = hash_password(password)

    # Gabungkan data untuk file .key
    key_data = '\n'.join([
        encrypted_secret_key_b64,
        hashed_password,
        new_filename
    ]).encode('utf-8')

    # Log sebelum mengenkripsi key data (file .key)
    logging.info('Memulai enkripsi data kunci (.key) menggunakan AES...')
    encrypted_key_data = aes_encrypt(key_data, KEY_ENCRYPTION_KEY)

    # Save encrypted key data to file
    secret_key_path = os.path.join(UPLOAD_FOLDER, f'{new_filename}.key')
    with open(secret_key_path, 'wb') as f:
        f.write(encrypted_key_data)
    logging.info(f'File .key terenkripsi disimpan di: {secret_key_path}')

    # Simpan informasi file di session
    session['private_key_path'] = private_key_path
    session['new_filename'] = new_filename

    # Redirect ke halaman sukses
    logging.info('File berhasil di-upload dan terenkripsi.')
    return redirect(url_for('success'))

@app.route('/success')
def success():
    logging.info('Menampilkan halaman sukses.')
    if 'private_key_path' not in session:
        return redirect(url_for('index'))  # Jika tidak ada data di session, kembali ke index
    return render_template('success.html', new_filename=session['new_filename'])

@app.route('/download_key', methods=['POST'])
def download_key():
    logging.info('Mengunduh private key...')
    if 'private_key_path' not in session:
        return redirect(url_for('index'))
    private_key_path = session.pop('private_key_path', None)  # Hapus dari sesi setelah diakses
    if private_key_path and os.path.exists(private_key_path):
        logging.info(f'Private key ditemukan, mengirimkan file')
        return send_file(private_key_path, as_attachment=True)
    logging.error('File private key tidak ditemukan.')
    return "File private key tidak ditemukan.", 404

@app.route('/aes')
def aes():
    logging.info('Mengakses halaman AES.')
    return render_template('aes.html')

@app.route('/download', methods=['POST'])
def download_file():
    try:
        filename = request.form['filename']
        password = request.form['password']
        private_key_file = request.files['private_key']

        # Load private key
        private_key = serialization.load_pem_private_key(
            private_key_file.read(),
            password=None
        )

        # Hash password
        hashed_password = hash_password(password)

        # Load encrypted key data from file
        secret_key_path = os.path.join(UPLOAD_FOLDER, f'{filename}.key')
        if not os.path.exists(secret_key_path):
            logging.error(f'Key file {filename}.key tidak ditemukan.')
            return render_template('gagal.html')

        with open(secret_key_path, 'rb') as f:
            encrypted_key_data = f.read()

        # Log sebelum dekripsi key data (.key)
        logging.info('Memulai dekripsi file .key menggunakan AES...')
        key_data = aes_decrypt(encrypted_key_data, KEY_ENCRYPTION_KEY).decode('utf-8').split('\n')

        # Validasi format file .key
        if len(key_data) != 3:
            logging.error(f'Format file .key salah untuk file {filename}.')
            return render_template('gagal.html')

        encrypted_secret_key_b64 = key_data[0]
        stored_hashed_password = key_data[1]
        encrypted_filename = key_data[2]

        # Verifikasi password
        if hashed_password != stored_hashed_password:
            logging.error(f'Password tidak cocok untuk file {filename}.')
            return render_template('gagal.html')

        # Decode dan dekripsi secret key
        encrypted_secret_key = base64.b64decode(encrypted_secret_key_b64)
        secret_key = rsa_decrypt(encrypted_secret_key, private_key)

        # Load dan decrypt file terenkripsi tanpa menyimpan ke server
        encrypted_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
        if not os.path.exists(encrypted_path):
            logging.error(f'File terenkripsi {encrypted_filename} tidak ditemukan.')
            return render_template('gagal.html')

        # Log sebelum mendekripsi file pengguna
        logging.info('Memulai dekripsi file pengguna menggunakan AES...')
        with open(encrypted_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = aes_decrypt(encrypted_data, secret_key)

        # Kirim file hasil dekripsi ke pengguna tanpa menyimpannya
        return (
            decrypted_data,
            200,
            {
                'Content-Type': 'application/octet-stream',
                'Content-Disposition': f'attachment; filename="decrypted_{filename}"'
            }
        )

    except UnicodeDecodeError:
        logging.error(f'Error dalam mendekripsi file {filename} - UnicodeDecodeError.')
        return render_template('gagal.html')
    except Exception as e:
        logging.error(f'Error: {e}')
        return render_template('gagal.html')

if __name__ == '__main__':
    app.run(debug=True)
