from flask import Flask, render_template, request, redirect, url_for, session
from PIL import Image
import os
from io import BytesIO
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# App setup
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Image upload folder
UPLOAD_FOLDER = 'static/uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create keys if they don't exist
if not os.path.exists("private_key.pem") or not os.path.exists("public_key.pem"):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
else:
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

# ----------------------
# Hide and Extract functions

def hide_data_in_image(image_file, message):
    try:
        img = Image.open(image_file)
        img = img.convert('RGB')
        encoded = img.copy()
        width, height = img.size

        # Encrypt the message
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        data = encrypted_message.hex() + '====='
        data_index = 0

        for x in range(width):
            for y in range(height):
                pixel = list(img.getpixel((x, y)))
                for n in range(3):
                    if data_index < len(data):
                        ascii_val = ord(data[data_index])
                        for bit in range(8):
                            pixel[n] = (pixel[n] & ~(1 << bit)) | ((ascii_val >> bit) & 1) << bit
                        data_index += 1
                encoded.putpixel((x, y), tuple(pixel))
                if data_index >= len(data):
                    break
            if data_index >= len(data):
                break

        image_name = f"hidden_{os.urandom(8).hex()}.png"
        save_path = os.path.join(UPLOAD_FOLDER, image_name)
        encoded.save(save_path)

        return image_name, "✅ Message successfully hidden!"
    except Exception as e:
        return None, f"❌ Error while hiding: {str(e)}"

def extract_hidden_data(image_file):
    try:
        img = Image.open(BytesIO(image_file.read()))
        img = img.convert('RGB')
        width, height = img.size
        data_bits = []

        for x in range(width):
            for y in range(height):
                pixel = img.getpixel((x, y))
                for color in pixel:
                    for bit in range(8):
                        data_bits.append((color >> bit) & 1)

        chars = []
        for i in range(0, len(data_bits), 8):
            byte = 0
            for bit_index in range(8):
                if i + bit_index < len(data_bits):
                    byte |= (data_bits[i + bit_index] << bit_index)
            chars.append(chr(byte))

        data = ''.join(chars)

        if '=====' not in data:
            return "❌ No hidden message found."

        encrypted_hex = data.split('=====')[0]

        encrypted_bytes = bytes.fromhex(encrypted_hex)
        decrypted = private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return "✅ Extracted message: " + decrypted.decode()
    except Exception as e:
        return f"❌ Failed to extract message: {str(e)}"

def detect_hidden_data(image_file):
    try:
        img = Image.open(BytesIO(image_file.read()))
        img = img.convert('RGB')
        width, height = img.size
        data_bits = []

        for x in range(width):
            for y in range(height):
                pixel = img.getpixel((x, y))
                for color in pixel:
                    for bit in range(8):
                        data_bits.append((color >> bit) & 1)

        chars = []
        for i in range(0, len(data_bits), 8):
            byte = 0
            for bit_index in range(8):
                if i + bit_index < len(data_bits):
                    byte |= (data_bits[i + bit_index] << bit_index)
            chars.append(chr(byte))

        data = ''.join(chars)

        if '=====' in data:
            return "✅ Hidden message detected!"
        else:
            return "❌ No hidden message found."
    except Exception as e:
        return f"❌ Failed to detect hidden message: {str(e)}"

# ----------------------
# Routes

@app.route('/')
def home():
    if 'logged_in' in session:
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/do_login', methods=['POST'])
def do_login():
    session['logged_in'] = True
    return redirect(url_for('home'))

@app.route('/hide', methods=['POST'])
def hide():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if 'image' not in request.files or 'message' not in request.form:
        return redirect(url_for('home'))

    image = request.files['image']
    message = request.form['message']

    if image.filename == '':
        return redirect(url_for('home'))

    image_name, hide_message = hide_data_in_image(image, message)
    if image_name is None:
        return render_template('home.html', hide_result=f"❌ {hide_message}")

    return render_template('home.html', hide_result=hide_message, image_url=url_for('static', filename=f'uploads/{image_name}'))

@app.route('/extract', methods=['POST'])
def extract():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if 'image' not in request.files:
        return redirect(url_for('home'))

    image = request.files['image']

    if image.filename == '':
        return redirect(url_for('home'))

    message = extract_hidden_data(image)

    return render_template('home.html', extract_result=message)

@app.route('/check', methods=['POST'])
def check():
    if 'logged_in' not in session:
        return redirect(url_for('login'))

    if 'image' not in request.files:
        return redirect(url_for('home'))

    image = request.files['image']

    if image.filename == '':
        return redirect(url_for('home'))

    result = detect_hidden_data(image)

    return render_template('home.html', check_result=result)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ----------------------
if __name__ == '__main__':
    app.run(debug=True)