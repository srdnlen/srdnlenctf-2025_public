from flask_login import UserMixin
from app import db

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(300), nullable=False, unique=True)
    color = db.Column(db.String(10), nullable=True)
    is_playing = db.Column(db.Boolean, nullable=True)