from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .database import basedir
from os.path import join, dirname, realpath

app = Flask(__name__)
app.secret_key = 'why would I tell you my secret key?'


app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{basedir}/app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['IMAGE_UPLOADS'] = join(dirname(realpath(__file__)), 'static/imgs/')
app.config['UPLOAD_FOLDER'] = join(dirname(realpath(__file__)), 'static/upload_user')
db = SQLAlchemy(app)

pageLimit = 5


from sabir.models import User,BucketList,Like
from sabir.routes import *



with app.app_context():
    db.create_all()