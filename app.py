from flask import Flask, render_template, request, jsonify, send_file
from io import BytesIO
from PIL import Image
import numpy as np
import os
from werkzeug.utils import secure_filename
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def encrypt_message(message, password):
    """Encrypt a message using AES-256-CBC with PBKDF2 key derivation"""
    # Generate a random salt
    salt = os.urandom(16)
    
    # Derive a key from the password using PBKDF2
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # Number of iterations
        dklen=32  # Desired key length
    )
    
    # Generate a random IV
    iv = os.urandom(16)
    
    # Create cipher object and encrypt the data
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_message = pad(message.encode('utf-8'), AES.block_size)
    encrypted = cipher.encrypt(padded_message)
    
    # Combine salt + iv + ciphertext
    result = salt + iv + encrypted
    return base64.b64encode(result).decode('utf-8')

def decrypt_message(encrypted_message, password):
    """Decrypt a message using AES-256-CBC with PBKDF2 key derivation"""
    try:
        # Decode the base64 message
        decoded = base64.b64decode(encrypted_message)
        
        # Extract components
        salt = decoded[:16]
        iv = decoded[16:32]
        ciphertext = decoded[32:]
        
        # Derive the key using the same parameters
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,
            dklen=32
        )
        
        # Create cipher object and decrypt the data
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        raise ValueError("Incorrect password or corrupted message")

def encode_image(img, message):
    """Encode a message into an image using LSB steganography"""
    # Convert image to RGBA if it's not already
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    # Create a copy of the image to avoid modifying the original
    img = img.copy()
    width, height = img.size
    array = np.array(img)
    
    # Add end of message marker
    message += '\0'
    
    # Convert message to binary
    binary_message = ''.join(format(ord(char), '08b') for char in message)
    
    # Check if message is too large
    if len(binary_message) > (width * height * 3):
        raise ValueError("Message is too large for the image")
    
    # Encode the message in the image
    data_index = 0
    for i in range(height):
        for j in range(width):
            r, g, b, a = array[i, j]
            
            # Encode in RGB channels, skip alpha channel
            for k, color in enumerate([r, g, b]):
                if data_index < len(binary_message):
                    # Clear the least significant bit and set it to the message bit
                    array[i, j, k] = (color & 0xFE) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break
            
            if data_index >= len(binary_message):
                break
        
        if data_index >= len(binary_message):
            break
    
    # Create a new image from the modified array
    return Image.fromarray(array, 'RGBA')

def decode_image(img):
    """Decode a message from an image using LSB steganography"""
    # Convert image to RGBA if it's not already
    if img.mode != 'RGBA':
        img = img.convert('RGBA')
    
    width, height = img.size
    array = np.array(img)
    
    binary_message = ''
    message = ''
    
    # Extract LSBs from the image
    for i in range(height):
        for j in range(width):
            r, g, b, a = array[i, j]
            
            # Extract LSB from each color channel (skip alpha channel)
            for color in [r, g, b]:
                binary_message += str(color & 1)
                
                # Check if we've read a full byte
                if len(binary_message) == 8:
                    byte = binary_message
                    binary_message = ''
                    
                    # Convert binary to character
                    try:
                        char = chr(int(byte, 2))
                    except ValueError:
                        continue
                    
                    # Check for end of message
                    if char == '\0':
                        return message
                    
                    message += char
    
    return message

@app.route('/')
def index():
    return render_template('base.html')

@app.route('/encode', methods=['POST'])
def encode():
    try:
        if 'image' not in request.files:
            return jsonify({'error': 'No image file provided'}), 400
        
        file = request.files['image']
        message = request.form.get('message', '').strip()
        password = request.form.get('password', '').strip()
        
        if not message:
            return jsonify({'error': 'No message provided'}), 400
        
        if not file or file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        # Read the file data first
        file_data = file.read()
        if not file_data:
            return jsonify({'error': 'Empty file provided'}), 400
            
        try:
            # Open image from bytes
            img = Image.open(BytesIO(file_data))
            # Convert to RGBA to handle transparency
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
                
        except Exception as e:
            return jsonify({'error': f'Invalid image file: {str(e)}'}), 400
        
        # Encrypt the message if password is provided
        if password:
            try:
                message = encrypt_message(message, password)
            except Exception as e:
                return jsonify({'error': 'Failed to encrypt message'}), 400
        
        # Check if image is large enough for the message
        max_bits = img.size[0] * img.size[1] * 3  # 3 channels (RGB)
        required_bits = (len(message) + 1) * 8  # +1 for null terminator
        
        if required_bits > max_bits:
            return jsonify({
                'error': f'Message too large for the image. Maximum message length is approximately {max_bits // 8 - 1} characters.'
            }), 400
        
        # Encode the message
        try:
            encoded_img = encode_image(img, message)
        except Exception as e:
            return jsonify({'error': f'Encoding failed: {str(e)}'}), 400
        
        # Save to bytes
        img_io = BytesIO()
        try:
            # Save as PNG to preserve transparency
            encoded_img.save(img_io, format='PNG')
            img_io.seek(0)
        except Exception as e:
            return jsonify({'error': f'Failed to process the image: {str(e)}'}), 500
        
        # Return the image directly as binary data
        return send_file(
            img_io,
            mimetype='image/png',
            as_attachment=True,
            download_name='encoded_image.png'
        )
    except Exception as e:
        app.logger.error(f'Error in encode: {str(e)}')
        return jsonify({'error': 'An error occurred while processing your request'}), 500

@app.route('/decode', methods=['POST'])
def decode():
    app.logger.info('Decode request received')
    
    # Check if file was provided
    if 'image' not in request.files:
        app.logger.warning('No image file provided in request')
        return jsonify({'error': 'No image file provided'}), 400
    
    file = request.files['image']
    password = request.form.get('password', '').strip()
    
    # Validate file
    if not file or file.filename == '':
        app.logger.warning('Empty file provided')
        return jsonify({'error': 'No file selected'}), 400
    
    try:
        app.logger.info(f'Processing file: {file.filename}, size: {file.content_length} bytes')
        
        # Open and validate image
        try:
            img = Image.open(file.stream)
            app.logger.info(f'Image opened successfully. Format: {img.format}, Size: {img.size}, Mode: {img.mode}')
        except Exception as e:
            app.logger.error(f'Error opening image: {str(e)}')
            return jsonify({'error': 'Invalid image file. Please upload a valid image.'}), 400
        
        # Convert to RGB if needed
        if img.mode != 'RGB':
            app.logger.info(f'Converting image from {img.mode} to RGB')
            img = img.convert('RGB')
        
        # Decode the message
        try:
            app.logger.info('Starting message extraction...')
            message = decode_image(img)
            
            if not message:
                app.logger.warning('No message found in the image')
                return jsonify({
                    'error': 'No hidden message found or the image is not encoded with this tool'
                }), 404
            
            app.logger.info(f'Message extracted. Length: {len(message)} characters')
            
            # Try to decrypt if password is provided
            if password:
                app.logger.info('Password provided, attempting decryption...')
                try:
                    message = decrypt_message(message, password)
                    app.logger.info('Message successfully decrypted')
                except ValueError as e:
                    app.logger.warning(f'Decryption failed: {str(e)}')
                    return jsonify({'error': str(e) or 'Incorrect password or corrupted message'}), 401
                except Exception as e:
                    app.logger.error(f'Error during decryption: {str(e)}')
                    return jsonify({'error': 'Failed to decrypt message. The password might be incorrect.'}), 401
            
            return jsonify({
                'message': message,
                'was_encrypted': bool(password)
            })
            
        except Exception as e:
            app.logger.error(f'Error in decode_image: {str(e)}', exc_info=True)
            return jsonify({
                'error': 'Failed to extract message from image. The image might be corrupted or not encoded with this tool.'
            }), 400
            
    except Exception as e:
        app.logger.error(f'Unexpected error in decode: {str(e)}', exc_info=True)
        return jsonify({
            'error': 'An unexpected error occurred while processing your request. Please try again.'
        }), 500

if __name__ == '__main__':
    app.run(debug=True)
