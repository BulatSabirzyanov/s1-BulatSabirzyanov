from .models import db
from .routes import app

from .utils import init_database
from .database import basedir
from os.path import join, dirname, realpath

app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{basedir}/app.db'

app.secret_key = 'your_secret_key_here'
app.config['IMAGE_UPLOADS'] = join(dirname(realpath(__file__)), 'static/imgs/')
app.config['UPLOAD_FOLDER'] = join(dirname(realpath(__file__)), 'static/upload_user')



db.init_app(app)

init_database(app, db)
