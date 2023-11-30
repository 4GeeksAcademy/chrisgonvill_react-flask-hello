"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
from flask import Flask, request, jsonify, url_for, Blueprint
from api.models import db, User
from api.utils import generate_sitemap, APIException
from flask_cors import CORS
import json

api = Blueprint('api', __name__)

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
