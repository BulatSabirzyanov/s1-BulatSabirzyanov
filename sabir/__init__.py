from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from .database import basedir
from os.path import join, dirname, realpath




app = Flask(__name__)
"""Класс Flask представляет веб-приложение Flask.

    Атрибуты:
        secret_key (str): Секретный ключ для сессий и других функций безопасности.

    """
app.secret_key = 'why would I tell you my secret key?'

"""Объект app.config представляет конфигурацию Flask приложения.

    Атрибуты:
        SQLALCHEMY_DATABASE_URI (str): URI (Uniform Resource Identifier) для подключения к базе данных SQLite.
        SQLALCHEMY_TRACK_MODIFICATIONS (bool): Флаг, указывающий на отключение отслеживания изменений.
        IMAGE_UPLOADS (str): Путь к директории для загрузки изображений.
        UPLOAD_FOLDER (str): Путь к директории для загрузки файлов пользователей.
    """
app.config["SQLALCHEMY_DATABASE_URI"] = f'sqlite:///{basedir}/app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['IMAGE_UPLOADS'] = join(dirname(realpath(__file__)), 'static/imgs/')
app.config['UPLOAD_FOLDER'] = join(dirname(realpath(__file__)), 'static/upload_user')
db = SQLAlchemy(app)

pageLimit = 5


from sabir.models import User,BucketList,Like
from sabir.routes import *



with app.app_context():
    """Метод db.create_all() создает все таблицы базы данных, определенные в моделях.

        Примечание:
            Этот метод должен вызываться в контексте приложения.
        """
    db.create_all()