from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# Define BucketList model
from sabir import db
class BucketList(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100))
    description = db.Column(db.String(255))
    file_path = db.Column(db.String(255))
    is_private = db.Column(db.Boolean)
    is_done = db.Column(db.Boolean)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    likes = db.relationship('Like', backref='bucketlist', lazy=True)

    @classmethod
    def get_total_wishes(cls, user_id):
        return cls.query.filter_by(user_id=user_id).count()

    @classmethod
    def get_completed_wishes(cls, user_id):
        return cls.query.filter_by(user_id=user_id, is_done=True).count()

    @classmethod
    def get_pending_wishes(cls, user_id):
        return cls.query.filter_by(user_id=user_id, is_done=False).count()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    photo = db.Column(db.String(255), default = "default_user.jpeg")
    password = db.Column(db.String(100))
    bucketlists = db.relationship('BucketList', backref='user', lazy=True)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bucketlist_id = db.Column(db.Integer, db.ForeignKey('bucket_list.id'))

