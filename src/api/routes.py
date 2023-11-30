"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint, current_app
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
import json
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
# from flask_jwt_extended import JWTManager

api = Blueprint('api', __name__)

# api.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
# jwt = JWTManager(api)

# Allow CORS requests to this API
CORS(api)


@api.route('/signup', methods=['POST'])
def create_one_user():
    # body = json.loads(request.data)

    email = request.json.get('email')
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
            return jsonify({'error': 'Email already exists.'}), 409
    
    body = request.json
    new_user = User(
        email = body["email"],
        username = body["username"],
        name = body["name"],
        address = body["address"],
        phone = body["phone"],
        password = body["password"],
        is_admin = body["is_admin"]
    )
    db.session.add(new_user)
    db.session.commit()

    user_ok = {
        "email" : body["email"],
        "username" : body["username"],
        "name" : body["name"],
        "address" : body["address"],
        "phone" : body["phone"],
        "password" : body["password"],
        "is_admin" : body["is_admin"]
    }

    return jsonify({"msg": "user created succesfull", "user_added": user_ok }), 200




@api.route("/login", methods=["POST"])
def login():
    email = request.json.get("email", None)
    password = request.json.get("password", None)
    if email != "test" or password != "test":
        return jsonify({"msg": "Bad email or password"}), 401

    access_token = create_access_token(identity=email)
    return jsonify(access_token=access_token)