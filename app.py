from flask import Flask, request, jsonify
from flask_mysqldb import MySQL
import bcrypt
import jwt
import datetime
import pyotp
import qrcode
import io
import base64
from functools import wraps

app = Flask(__name__)

# MySQL Config
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'db'

mysql = MySQL(app)

# Secret key for JWT
app.config['SECRET_KEY'] = 'your_secret_key'

# Helper function for token verification
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            data = jwt.decode(token.split(" ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])
            cursor = mysql.connection.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s", (data['user_id'],))
            user = cursor.fetchone()
            cursor.close()
            if not user:
                return jsonify({'message': 'Invalid Token'}), 403
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        return f(*args, **kwargs)
    return decorated

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data['username']
    password = data['password']
    
    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    totp = pyotp.TOTP(pyotp.random_base32())
    secret = totp.secret

    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO users (username, password, twofa_secret) VALUES (%s, %s, %s)", 
                   (username, hashed_pw, secret))
    mysql.connection.commit()
    cursor.close()
    
    return jsonify({'message': 'User registered successfully', '2fa_secret': secret})

# Generate 2FA QR Code
@app.route('/generate_qr/<username>', methods=['GET'])
def generate_qr(username):
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        return jsonify({'message': 'User not found'}), 404

    secret = user[0]
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureApp")
    
    qr = qrcode.make(uri)
    img_bytes = io.BytesIO()
    qr.save(img_bytes, format="PNG")
    img_bytes.seek(0)

    return jsonify({'qr_code': base64.b64encode(img_bytes.read()).decode('utf-8')})

# User Login
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']
    otp_code = data['otp']

    cursor = mysql.connection.cursor()
    cursor.execute("SELECT id, password, twofa_secret FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        return jsonify({'message': 'Invalid username or password'}), 401

    user_id, stored_password, secret = user
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        return jsonify({'message': 'Invalid username or password'}), 401

    totp = pyotp.TOTP(secret)
    if not totp.verify(otp_code):
        return jsonify({'message': 'Invalid 2FA code'}), 401

    token = jwt.encode({'user_id': user_id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
                       app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token})

# Create Product (Protected)
@app.route('/products', methods=['POST'])
@token_required
def create_product():
    data = request.json
    name = data['name']
    description = data['description']
    price = data['price']
    quantity = data['quantity']

    cursor = mysql.connection.cursor()
    cursor.execute("INSERT INTO products (name, description, price, quantity) VALUES (%s, %s, %s, %s)", 
                   (name, description, price, quantity))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Product added successfully'})

# Read Products (Protected)
@app.route('/products', methods=['GET'])
@token_required
def get_products():
    cursor = mysql.connection.cursor()
    cursor.execute("SELECT * FROM products")
    products = cursor.fetchall()
    cursor.close()

    product_list = [{'id': p[0], 'name': p[1], 'description': p[2], 'price': float(p[3]), 'quantity': p[4]} for p in products]
    
    return jsonify({'products': product_list})

# Update Product (Protected)
@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(product_id):
    data = request.json
    name = data['name']
    description = data['description']
    price = data['price']
    quantity = data['quantity']

    cursor = mysql.connection.cursor()
    cursor.execute("UPDATE products SET name = %s, description = %s, price = %s, quantity = %s WHERE id = %s",
                   (name, description, price, quantity, product_id))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Product updated successfully'})

# Delete Product (Protected)
@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(product_id):
    cursor = mysql.connection.cursor()
    cursor.execute("DELETE FROM products WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cursor.close()

    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    app.run(debug=True)