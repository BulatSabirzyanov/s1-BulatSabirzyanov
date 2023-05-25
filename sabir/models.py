
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
class BucketList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    is_private = db.Column(db.Boolean)
    is_done = db.Column(db.Boolean)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    likes = db.relationship('Like', backref='bucketlist', lazy=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)

    password = db.Column(db.String(100))
    bucketlists = db.relationship('BucketList', backref='user', lazy=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bucketlist_id = db.Column(db.Integer, db.ForeignKey('bucket_list.id'))

