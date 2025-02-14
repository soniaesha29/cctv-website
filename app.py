import os
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import get_jwt_identity, JWTManager, create_access_token, jwt_required, create_refresh_token
from pymongo import MongoClient
from bson import json_util
from datetime import datetime
import json
import re
import cloudinary
import cloudinary.api
import cloudinary.uploader
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Cloudinary configuration using env variables
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET")
)

# Configuration for JWT
app.config['JWT_SECRET_KEY'] = os.getenv("JWT_SECRET_KEY")

jwt = JWTManager(app)
CORS(app, supports_credentials=True)

# Connect to MongoDB using env variable
client = MongoClient(os.getenv("MONGO_URI"))
db = client["CCTV"]  # Database name
collection = db["activity_log"]  # Collection name
users_collection = db["users"]  # Users collection name

# history_collection = db["history"]  # Users collection name

def extract_name(full_name):
    """
    Extracts the name portion before any space and numeric value.
    Example: "aesha (22)" -> "aesha"
    """
    match = re.match(r'^([^\s\(]+)', full_name)
    return match.group(1) if match else full_name

# Route for the homepage
@app.route('/')
def index():
    try:
        records = list(collection.find())
        return render_template("index.html", records=records)
    except Exception as e:
        return f"An error occurred: {e}", 500

@app.route('/check-name', methods=['GET'])
def check_name():
    try:
        name = request.args.get('name')
        
        # Search for resources with the given name
        result = cloudinary.Search().expression(f"folder:uploads AND context.name:{name}").execute()
        
        return jsonify({"exists": len(result['resources']) > 0})
    except Exception as error:
        print('Error checking name:', error)
        return jsonify({"error": 'Failed to check name'}), 500

@app.route('/upload_folder_images', methods=['POST'])
def upload_folder_images():
    try:
        data = request.json
        name = data.get("name")
        folder = data.get("folder")  # Folder path

        if not name or not folder:
            return jsonify({"error": "Name and folder are required"}), 400

        # Fetch all images from the Cloudinary folder
        response = cloudinary.api.resources(type="upload", prefix=folder, max_results=50)
        images = [item["secure_url"] for item in response.get("resources", [])]

        if not images:
            return jsonify({"error": "No images found in the folder"}), 404

        # Save images in MongoDB
        user_data = {"name": name, "images": images, "role": "user"}
        result = users_collection.insert_one(user_data)
        user_data["_id"] = str(result.inserted_id)
        return jsonify({"message": "Images stored In mongoDB", "data": user_data}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500



# API to upload user image data
@app.route('/upload_images', methods=['POST'])
def upload_images():
    try:
        # Get data from request
        data = request.json
        name = data.get("name")
        images = data.get("images")  # List of image URLs

        # Validate input
        if not name or not images or not isinstance(images, list):
            return jsonify({"error": "Name and an array of image URLs are required"}), 400

        # Insert into MongoDB
        user_data = {"name": name, "images": images, "role": "user"}
        result = users_collection.insert_one(user_data)

        # Convert MongoDB ObjectId to string
        user_data["_id"] = str(result.inserted_id)

        return jsonify({"message": "User images uploaded successfully", "data": user_data}), 201

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to fetch data with optional filters for name, emotion, and date
@app.route('/data', methods=['GET'])
@jwt_required()
def data():
    try:
        name = request.args.get('name')
        emotion = request.args.get('emotion')
        date = request.args.get('date')

        query = {}
        if name:
            query["name"] = {"$regex": f"^{name}\\s*", "$options": "i"}  
        if emotion:
            query["emotion"] = emotion
        if date:
            query["timestamp"] = date

        results = list(collection.find(query))

        for record in results:
            if "name" in record:
                record["name"] = extract_name(record["name"])

        return jsonify(json.loads(json_util.dumps(results)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# API to get uploaded user images where role is "user"
@app.route('/get_user_images_history', methods=['GET'])
@jwt_required()
def get_user_images():
    try:
        # Fetch only the users who have role as "user"
        user_images = list(users_collection.find({"role": "user"}))

        # Convert ObjectId to string
        for user in user_images:
            user["_id"] = str(user["_id"])  # Convert ObjectId to string

        if not user_images:
            return jsonify({"message": "No user images found"}), 404

        return jsonify({"data": user_images}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500




# Route to get all records filtered by emotion
@app.route('/emotion-data', methods=['GET'])
@jwt_required()
def emotion_data():
    try:
        emotion = request.args.get('emotion')
        if not emotion:
            return jsonify({"error": "Please provide an emotion"}), 400

        results = []
        for record in collection.find({"emotion": emotion}):
            results.append({
                "name": extract_name(record.get("name")),
                "emotion": record.get("emotion"),
                "timestamp": record.get("timestamp")
            })

        if results:
            return jsonify(json.loads(json_util.dumps(results)))
        else:
            return jsonify({"message": "No records found for the given emotion"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to get all records filtered by date
@app.route('/date-data', methods=['GET'])
@jwt_required()
def date_data():
    try:
        date = request.args.get('date')
        if not date:
            return jsonify({"error": "Please provide a date"}), 400
        
        # Try different formats
        possible_formats = ["%Y-%m-%d", "%d-%m-%Y", "%Y/%m/%d", "%m-%d-%Y"]
        for fmt in possible_formats:
            try:
                formatted_date = datetime.strptime(date, fmt).strftime("%Y-%m-%d")
                break
            except ValueError:
                formatted_date = None
        
        if not formatted_date:
            return jsonify({"error": "Invalid date format"}), 400

        # Query MongoDB for the matching date
        query = {
            "$expr": {
                "$eq": [
                    { "$dateToString": { "format": "%Y-%m-%d", "date": "$timestamp" } },
                    formatted_date
                ]
            }
        }

        results = list(collection.find(query))

        if results:
            return jsonify(json.loads(json_util.dumps(results)))
        else:
            return jsonify({"message": "No records found for the given date"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for user signup
@app.route('/signup', methods=['POST'])
def signup():
    try:
        username = request.json.get("username")
        password = request.json.get("password")
        role = request.json.get("role", "user")  # Default role is "user"

        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400

        # Check if the user already exists
        existing_user = users_collection.find_one({"username": username})
        if existing_user:
            return jsonify({"error": "User already exists"}), 400

        # Create a new user with role
        users_collection.insert_one({"username": username, "password": password, "role": role})
        
        return jsonify({"message": "User created successfully", "role": role}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Route for user login
@app.route('/login', methods=['POST'])
def login():
    try:
        username = request.json.get("username")
        password = request.json.get("password")
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        # Check if the user exists
        user = users_collection.find_one({"username": username, "password": password})
        if not user:
            return jsonify({"error": "Invalid credentials"}), 401

        # Create JWT tokens
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        return jsonify(access_token=access_token, refresh_token=refresh_token), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route to refresh access token
@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    try:
        access_token = create_access_token(identity=request.jwt_identity)
        return jsonify(access_token=access_token), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Route for protected endpoint
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    return jsonify(message="This is a protected route"), 200

# Route to logout (just an example)
@app.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    return jsonify(message="You have been logged out"), 200



# Entry Data API
@app.route('/entry-data', methods=['GET'])
@jwt_required()
def entry_data():
    try:
        results = list(collection.find({"activity": "entering"}))
        return jsonify(json.loads(json_util.dumps(results)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Exit Data API
@app.route('/exit-data', methods=['GET'])
@jwt_required()
def exit_data():
    try:
        results = list(collection.find({"activity": "exiting"}))
        return jsonify(json.loads(json_util.dumps(results)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Superadmin API - Add another admin
@app.route('/superadmin/add-admin', methods=['POST'])
@jwt_required()
def add_admin():
    try:
        current_user = get_jwt_identity()
        user = users_collection.find_one({"username": current_user})

        if not user or user.get("role") != "superadmin":
            return jsonify({"error": "Access denied. Only superadmin can add admins"}), 403

        new_admin = request.json.get("username")
        password = request.json.get("password")

        if not new_admin or not password:
            return jsonify({"error": "Username and password are required"}), 400

        existing_admin = users_collection.find_one({"username": new_admin})
        if existing_admin:
            return jsonify({"error": "Admin already exists"}), 400

        users_collection.insert_one({"username": new_admin, "password": password, "role": "admin"})
        return jsonify({"message": "Admin added successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# HR API - HR functionalities (without permission to add admin)
@app.route('/admin/manage-admin', methods=['GET'])
@jwt_required()
def manage_admin():
    try:
        current_user = get_jwt_identity()
        user = users_collection.find_one({"username": current_user})

        if not user or user.get("role") != "admin":
            return jsonify({"error": "Access denied. Only HR can access this"}), 403

        hr_data = list(users_collection.find({"role": "admin"}))
        return jsonify(json.loads(json_util.dumps(hr_data)))
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/create-admin', methods=['POST'])
@jwt_required()
def create_admin():
    try:
        current_user = get_jwt_identity()
        user = users_collection.find_one({"username": current_user})
        
        if not user or user.get("role") != "superadmin":
            return jsonify({"error": "Access denied. Only superadmin can create admins"}), 403
        
        new_admin_username = request.json.get("username")
        password = request.json.get("password")
        
        if not new_admin_username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        
        existing_admin = users_collection.find_one({"username": new_admin_username})
        if existing_admin:
            return jsonify({"error": "Admin already exists"}), 400
        
        users_collection.insert_one({"username": new_admin_username, "password": password, "role": "admin"})
        return jsonify({"message": "Admin created successfully"}), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))  # Default port 10000
    app.run(host="0.0.0.0", port=port, debug=True)

