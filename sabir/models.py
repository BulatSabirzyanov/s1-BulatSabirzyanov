from time import time

from flask import Flask, render_template, request, redirect, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# Define BucketList model
from sabir import db, app
import jwt
class BucketList(db.Model):
    """Модель для списка желаний (BucketList).

        Атрибуты:
            id (int): Уникальный идентификатор списка желаний.
            title (str): Название списка желаний.
            description (str): Описание списка желаний.
            file_path (str): Путь к файлу, связанному со списком желаний.
            is_private (bool): Флаг, указывающий на приватность списка желаний.
            is_done (bool): Флаг, указывающий на завершенность списка желаний.
            date (datetime): Дата создания списка желаний.
            user_id (int): Идентификатор пользователя, связанного со списком желаний.
            likes (Like[]): Связь с моделью Like через отношение "один ко многим".

        Методы:
            get_total_wishes(cls, user_id): Возвращает общее количество желаний для указанного пользователя.
            get_completed_wishes(cls, user_id): Возвращает количество завершенных желаний для указанного пользователя.
            get_pending_wishes(cls, user_id): Возвращает количество незавершенных желаний для указанного пользователя.
        """
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
        """Статический метод для получения общего количества желаний для указанного пользователя.

                Аргументы:
                    user_id (int): Идентификатор пользователя.

                Возвращает:
                    int: Общее количество желаний для пользователя.
                """
        return cls.query.filter_by(user_id=user_id).count()

    @classmethod
    def get_completed_wishes(cls, user_id):
        """Статический метод для получения количества завершенных желаний для указанного пользователя.

                Аргументы:
                    user_id (int): Идентификатор пользователя.

                Возвращает:
                    int: Количество завершенных желаний для пользователя.
                """
        return cls.query.filter_by(user_id=user_id, is_done=True).count()

    @classmethod
    def get_pending_wishes(cls, user_id):
        """Статический метод для получения количества незавершенных желаний для указанного пользователя.

                Аргументы:
                    user_id (int): Идентификатор пользователя.

                Возвращает:
                    int: Количество незавершенных желаний для пользователя.
                """
        return cls.query.filter_by(user_id=user_id, is_done=False).count()

class User(db.Model):
    """Модель для пользователя (User).

        Атрибуты:
            id (int): Уникальный идентификатор пользователя.
            name (str): Имя пользователя.
            email (str): Электронная почта пользователя (уникальное значение).
            photo (str): Путь к фотографии пользователя.
            password (str): Хэшированный пароль пользователя.
            bucketlists (BucketList[]): Связь с моделью BucketList через отношение "один ко многим".
        """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(100), unique=True)
    photo = db.Column(db.String(255), default = "default_user.jpeg")
    password = db.Column(db.String(100))
    bucketlists = db.relationship('BucketList', backref='user', lazy=True)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'],
                            algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Like(db.Model):
    """Модель для лайка (Like).

        Атрибуты:
            id (int): Уникальный идентификатор лайка.
            user_id (int): Идентификатор пользователя, связанного с лайком.
            bucketlist_id (int): Идентификатор списка желаний, связанного с лайком.
        """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    bucketlist_id = db.Column(db.Integer, db.ForeignKey('bucket_list.id'))

