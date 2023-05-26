from flask_wtf import FlaskForm
from wtforms import PasswordField, SubmitField, StringField
from wtforms.validators import DataRequired, EqualTo


class ResetPasswordForm(FlaskForm):
    """Форма для сброса пароля пользователя.

    Атрибуты:
        email (StringField): Поле для ввода адреса электронной почты пользователя.
        submit (SubmitField): Кнопка для отправки формы.
    """

    email = StringField('Email', validators=[DataRequired()])
    submit = SubmitField('Сбросить пароль')


class ResetPasswordForm_2(FlaskForm):
    """Форма для изменения пароля пользователя.

    Атрибуты:
        password (PasswordField): Поле для ввода нового пароля.
        confirm_password (PasswordField): Поле для подтверждения нового пароля.
        submit (SubmitField): Кнопка для отправки формы.

    Примечание:
        Поле `confirm_password` должно совпадать со значением, введенным в поле `password`.
    """

    password = PasswordField('Новый пароль', validators=[DataRequired()])
    confirm_password = PasswordField('Подтвердите новый пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Изменить пароль')