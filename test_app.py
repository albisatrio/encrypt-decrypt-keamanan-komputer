import pytest
import os
from app import app, aes_encrypt, aes_decrypt, hash_password
from flask import Flask, request, render_template, send_file, jsonify, redirect, url_for, session

# Menggunakan fixture untuk mengatur aplikasi Flask untuk pengujian
@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client

def test_aes_encryption_decryption():
    key = os.urandom(32)  # Kunci AES 256-bit
    data = b'Test data untuk enkripsi'
    
    # Enkripsi data
    encrypted_data = aes_encrypt(data, key)
    
    # Dekripsi data
    decrypted_data = aes_decrypt(encrypted_data, key)

    assert decrypted_data == data  # Memastikan data yang didekripsi sama dengan data asli

def test_hash_password():
    password = 'password123'
    hashed = hash_password(password)

    # Memastikan hash berbeda dengan password asli
    assert hashed != password
    # Memastikan hash tetap sama untuk password yang sama
    assert hashed == hash_password(password)

def test_success(client):
    response = client.get('/success')
    assert response.status_code == 302  # Cek apakah redirect ke halaman lain