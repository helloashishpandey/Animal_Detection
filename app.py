import os
from flask import Flask, request, render_template, send_from_directory, jsonify, redirect, url_for, session
from flask_jwt_extended import JWTManager, create_access_token, jwt_required
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import img_to_array, load_img
import numpy as np
import json
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.getenv('UPLOAD_FOLDER', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('MAX_CONTENT_LENGTH', 7 * 1024 * 1024))  # Default to 7MB
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", 'vhudhjdjfodjihuisdnbcjsihevbb')
app.config['SECRET_KEY'] = os.getenv("SECRET_KEY", 'your_secret_key')

# Initialize PyMongo and JWTManager
mongo = PyMongo(app)
jwt = JWTManager(app)

users_collection = mongo.db.users
uploads_collection = mongo.db.uploads  # Collection to store uploads

# Load the trained model
model = load_model('animal_detector.h5')

# Load class indices
with open('class_indices.json', 'r') as f:
    class_indices = json.load(f)
class_labels = {v: k for k, v in class_indices.items()}

# Load animal details
with open('animal_details.json', 'r') as f:
    animal_details = json.load(f)

@app.route('/')
def root():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if users_collection.find_one({'email': email}):
            error = 'User already exists'
        else:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
            users_collection.insert_one({
                'username': username,
                'email': email,
                'password': hashed_password,
                'uploads_count': 0  # Initialize uploads count for new user
            })
            return redirect('/login')
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        data = request.form
        username = data.get('username')
        password = data.get('password')

        user = users_collection.find_one({'username': username})
        if not user or not check_password_hash(user['password'], password):
            error = 'Invalid credentials'
        else:
            access_token = create_access_token(identity=username)
            session['logged_in_user'] = username
            response = redirect(url_for('home_page'))
            response.headers['Authorization'] = f'Bearer {access_token}'
            return response
    return render_template('login.html', error=error)

@app.route('/home')
def home_page():
    logged_in_user = session.get('logged_in_user')
    return render_template('home.html', logged_in_user=logged_in_user)

@app.route('/index')
def index_page():
    logged_in_user = session.get('logged_in_user')
    return render_template('index.html', logged_in_user=logged_in_user)

@app.route('/submit', methods=['POST'])
def detect_animal():
    if 'my_image' not in request.files:
        return render_template('index.html', error='No file part', background_image_url=url_for('static', filename='images/tiger2.jpg'))

    file = request.files['my_image']
    if file.filename == '':
        return render_template('index.html', error='No selected file', background_image_url=url_for('static', filename='images/tiger2.jpg'))

    if file:
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Update uploads count for the logged-in user
        logged_in_user = session.get('logged_in_user')
        user = users_collection.find_one({'username': logged_in_user})
        if user:
            uploads_count = user.get('uploads_count', 0)
            uploads_count += 1
            users_collection.update_one({'username': logged_in_user}, {'$set': {'uploads_count': uploads_count}})

        # Preprocess the image
        img = load_img(file_path, target_size=(150, 150))
        img_array = img_to_array(img)
        img_array = np.expand_dims(img_array, axis=0) / 255.0

        # Predict the class
        predictions = model.predict(img_array)
        predicted_class_idx = np.argmax(predictions[0])  # Get index of the highest probability
        predicted_class = class_labels[predicted_class_idx]  # Map index to class label

        # Get animal details
        details = animal_details.get(predicted_class, "No details available for this animal.")

        return render_template('index.html', prediction=predicted_class, details=details, background_image_url=url_for('uploaded_file', filename=filename))

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/logout', methods=['POST'])
# @jwt_required()
def logout():
    session.pop('logged_in_user', None)
    return redirect(url_for('login'))

@app.route('/rewards')
def rewards():
    logged_in_user = session.get('logged_in_user')
    user = users_collection.find_one({'username': logged_in_user})
    
    if user:
        uploads_count = user.get('uploads_count', 0)
        print(uploads_count)
    else:
        uploads_count = 0
    
    return render_template('rewards.html', uploads_count=uploads_count,logged_in_user=logged_in_user)


if __name__ == '__main__':
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    app.run(debug=True)
