
from flask import Flask
from flask_sqlalchemy import SQLAlchemy


def init_database(app: Flask, db: SQLAlchemy):
    with app.app_context():
        db.create_all()