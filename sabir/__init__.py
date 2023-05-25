from flask import Flask
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.secret_key = 'why would I tell you my secret key?'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'C:/Users/sabir/PycharmProjects/s1-BulatSabirzyanov'
db = SQLAlchemy(app)

pageLimit = 5


from sabir.models import User,BucketList,Like
from sabir.routes import *



with app.app_context():
    db.create_all()

