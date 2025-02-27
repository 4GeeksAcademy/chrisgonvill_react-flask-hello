from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    username = db.Column(db.String(120),  nullable=False)
    name = db.Column(db.String(120),  nullable=False)
    address = db.Column(db.String(120),  nullable=False)
    phone = db.Column(db.String(120),  nullable=False)
    password = db.Column(db.String(80),  nullable=False)
    is_admin = db.Column(db.Boolean, unique=False, nullable=False)
    
    
    def __repr__(self):
        return f'<User {self.email}>'

    def serialize(self):
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "name": self.name,
            "address": self.address,
            "phone": self.phone,
            "is_admin": self.is_admin
            

            # do not serialize the password, its a security breach
        }