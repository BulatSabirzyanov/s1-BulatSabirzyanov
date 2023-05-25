from .models import db
from .routes import app

from .utils import init_database
from .database import basedir

app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{basedir}/app.db'
app.secret_key = 'your_secret_key_here'

db.init_app(app)

init_database(app, db)
