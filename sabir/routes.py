from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sabir import app, db
from sabir.forms import ResetPasswordRequestForm, ResetPasswordForm
from sabir.models import User, BucketList, Like




"""Объект app.config представляет конфигурацию Flask приложения.

    Атрибуты:
        MAIL_SERVER (str): Адрес сервера электронной почты для отправки писем.
        MAIL_PORT (int): Порт сервера электронной почты.
        MAIL_USE_TLS (bool): Флаг, указывающий на использование TLS (Transport Layer Security).
        MAIL_USE_SSL (bool): Флаг, указывающий на использование SSL (Secure Sockets Layer).
        MAIL_USERNAME (str): Имя пользователя для аутентификации на сервере электронной почты.
        MAIL_PASSWORD (str): Пароль для аутентификации на сервере электронной почты.
        MAIL_DEFAULT_SENDER (str): Электронный адрес отправителя по умолчанию для писем.
        MAIL_USE_MANAGEMENT_COMMANDS (bool): Флаг, указывающий на использование асинхронной отправки.

    Примечание:
        Для работы с электронной почтой необходимо настроить соответствующий почтовый сервер.
    """
app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'sabirzyanov427@mail.ru'
app.config['MAIL_PASSWORD'] = 'MuXPHsf9W2wHHe3p5dk2'
app.config['ADMINS'] = ['sabirzyanov427@mail.ru']
# RZHI1u1taet^
app.config['MAIL_DEFAULT_SENDER'] = 'sabirzyanov427@mail.ru'
app.config['MAIL_USE_MANAGEMENT_COMMANDS'] = True  # Включение поддержки асинхронной отправки




"""Объект mail представляет почтовое расширение Flask - Flask-Mail.

   Атрибуты:
       app (Flask): Экземпляр класса Flask, связанный с почтовым расширением.

   Примечание:
       Для использования Flask-Mail необходимо установить соответствующий пакет.
   """
mail = Mail(app)





"""Объект serializer представляет сериализатор URLSafeTimedSerializer.

   Атрибуты:
       app.config['SECRET_KEY'] (str): Секретный ключ, используемый для подписи и шифрования данных.

   Примечание:
       URLSafeTimedSerializer обычно используется для создания защищенных токенов и временных ссылок.
   """
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])


def allowed_file(filename):
    """Проверяет, является ли расширение файла допустимым.

        Аргументы:
            filename (str): Имя файла.

        Возвращает:
            bool: True, если расширение файла допустимо, False в противном случае.
        """
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in allowed_extensions


@app.route('/')
def main():
    """Обрабатывает запрос на главную страницу.

        Возвращает:
            str: HTML-шаблон для главной страницы.
        """
    return render_template('index.html')


@app.route('/profile')
def profile():
    """Обрабатывает запрос на страницу профиля.

        Возвращает:
            str: HTML-шаблон для страницы профиля, если пользователь авторизован.
            str: HTML-шаблон с сообщением об ошибке, если доступ запрещен.
        """
    if 'user' in session:
        user_name = session['user']
        user = User.query.filter_by(name=user_name).first()
        if user:
            return render_template('profile.html', user=user)
    return render_template('error.html', error='Unauthorized Access')


@app.route("/upload", methods=["POST"])
def upload():
    """
        Обработчик запроса на загрузку файла.

        Методы:
            - POST: Загружает файл и обновляет аватар пользователя в базе данных.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            Редирект на страницу профиля пользователя.

        """
    if 'file' not in request.files:
        flash('Файл не найден', 'error')
        return redirect(url_for('profile'))

    file = request.files['file']

    if file.filename == '':
        flash('Не выбран файл', 'error')
        return redirect(url_for('profile'))

    # Здесь добавьте код для сохранения и обновления аватара пользователя в базе данных
    if file:
        # Генерируем уникальное имя файла
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['IMAGE_UPLOADS'], filename))

        # Обновляем поле image_file у пользователя
        user_name = session['user']
        user = User.query.filter_by(name=user_name).first()

        if user is None:
            flash('Пользователь не найден', 'error')
            return redirect(url_for('profile'))

        user.photo = filename
        db.session.commit()

        flash('Аватар успешно изменен', 'success')
    else:
        flash('Ошибка при загрузке файла', 'error')

    return redirect(url_for('profile'))


@app.route('/showSignUp')
def showSignUp():
    """
        Отображает страницу регистрации.

        Методы:
            - GET: Отображает страницу регистрации.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон страницы регистрации.

        """
    return render_template('signup.html')


@app.route('/showAddWish')
def showAddWish():
    """
        Отображает страницу добавления пожелания.

        Методы:
            - GET: Отображает страницу добавления пожелания.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон страницы добавления пожелания.

        """
    return render_template('addWish.html')


@app.route('/addUpdateLike', methods=['POST'])
def addUpdateLike():
    """
        Обработчик запроса на добавление или обновление лайка.

        Методы:
            - POST: Добавляет или обновляет лайк для указанного пожелания.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ с информацией о статусе операции и общем количестве лайков.

        """
    try:
        if 'user' in session:
            wish_id = request.form['wish']
            like = request.form['like']
            user_id = session['user']

            bucketlist = BucketList.query.get(wish_id)
            if not bucketlist:
                return jsonify({'error': 'Wish not found.'})

            existing_like = Like.query.filter_by(user_id=user_id, bucketlist_id=wish_id).first()
            if existing_like:
                existing_like.like = like
            else:
                new_like = Like(user_id=user_id, bucketlist_id=wish_id, like=like)
                db.session.add(new_like)
            db.session.commit()

            total_likes = Like.query.filter_by(bucketlist_id=wish_id, like=True).count()
            user_like = Like.query.filter_by(user_id=user_id, bucketlist_id=wish_id).first()

            return jsonify({'status': 'OK', 'total': total_likes, 'likeStatus': user_like.like if user_like else False})
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/getAllWishes')
def getAllWishes():
    """
        Обработчик запроса на получение всех пожеланий.

        Методы:
            - GET: Возвращает информацию о всех пожеланиях.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ со списком пожеланий и связанной информацией.

        """
    try:
        if 'user' in session:
            user_id = session['user']
            wishes = BucketList.query.filter_by(is_private=False)
            wishes_dict = []
            for wish in wishes:
                wish_dict = {
                    'Id': wish.id,
                    'Title': wish.title,
                    'Description': wish.description,
                    'FilePath': wish.file_path,
                    'Like': len(wish.likes),
                    'HasLiked': Like.query.filter_by(user_id=user_id, bucketlist_id=wish.id).first() is not None
                }
                wishes_dict.append(wish_dict)

            print(wishes_dict)
            return jsonify(wishes_dict)
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/showDashboard')
def showDashboard():
    """
        Отображает страницу панели управления.

        Методы:
            - GET: Отображает страницу панели управления, если пользователь авторизован.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон страницы панели управления или редирект на страницу входа.

        """
    if 'user' in session:
        return render_template('dashboard.html')


@app.route('/dashboard')
def dashboard():
    """
        Отображает панель управления пользователя.

        Методы:
            - GET: Отображает панель управления пользователя, если пользователь авторизован.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон панели управления пользователя с информацией о количестве пожеланий.

        """
    if 'user' not in session:
        return redirect(url_for('login'))  # redirect to login page if user is not logged in

    user_id = session['user']
    total_wishes = BucketList.get_total_wishes(user_id)
    completed_wishes = BucketList.get_completed_wishes(user_id)
    pending_wishes = BucketList.get_pending_wishes(user_id)

    return render_template('dashboard.html',
                           total_wishes=total_wishes,
                           completed_wishes=completed_wishes,
                           pending_wishes=pending_wishes)


@app.route('/showSignin')
def showSignin():
    """
        Отображает страницу входа.

        Методы:
            - GET: Отображает страницу входа.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон страницы входа или страницы ошибки, если пользователь уже авторизован.

        """
    if 'user' in session:
        return render_template('userHome.html')
    else:
        return render_template('signin.html')


@app.route('/userHome')
def userHome():
    """
        Отображает домашнюю страницу пользователя.

        Методы:
            - GET: Отображает домашнюю страницу пользователя, если пользователь авторизован.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            HTML-шаблон домашней страницы пользователя или страницы ошибки, если пользователь не авторизован.

        """
    if 'user' in session:
        return render_template('userHome.html')
    else:
        return render_template('error.html', error='Unauthorized Access')


@app.route('/logout')
def logout():
    """
        Выход из системы.

        Методы:
            - GET: Выходит из системы и перенаправляет на главную страницу.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            Редирект на главную страницу.

        """
    session.pop('user', None)
    return redirect('/')


@app.route('/deleteWish', methods=['POST'])
def deleteWish():
    """
        Обработчик запроса на удаление пожелания.

        Методы:
            - POST: Удаляет указанное пожелание, если пользователь авторизован и имеет соответствующие права доступа.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ с информацией о статусе операции.

        """
    try:
        if 'user' in session:
            wish_id = request.form['id']
            user_id = session['user']

            bucketlist = BucketList.query.get(wish_id)
            if not bucketlist or bucketlist.user_id != user_id:
                return jsonify({'error': 'Unauthorized Access'})

            db.session.delete(bucketlist)
            db.session.commit()

            return jsonify({'status': 'OK'})
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/getWishById', methods=['POST'])
def getWishById():
    """
        Обработчик запроса на получение пожелания по его идентификатору.

        Методы:
            - POST: Возвращает информацию о пожелании с указанным идентификатором, если пользователь авторизован и имеет соответствующие права доступа.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ с информацией о пожелании.

        """
    try:
        if 'user' in session:
            wish_id = request.form['id']
            user_id = session['user']

            bucketlist = BucketList.query.get(wish_id)
            if not bucketlist or bucketlist.user_id != user_id:
                return jsonify({'error': 'Unauthorized Access'})

            wish = {
                'Id': bucketlist.id,
                'Title': bucketlist.title,
                'Description': bucketlist.description,
                'FilePath': bucketlist.file_path,
                'Private': bucketlist.is_private,
                'Done': bucketlist.is_done
            }
            return jsonify(wish)
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/getWish', methods=['GET'])
def getWish():
    """
        Обработчик запроса на получение списка пожеланий пользователя.

        Методы:
            - GET: Возвращает список пожеланий пользователя, если пользователь авторизован.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ со списком пожеланий пользователя и общим количеством пожеланий.

        """
    try:
        if 'user' in session:
            user_id = session['user']

            offset = request.args.get('offset')
            total_records = 0
            wishes = BucketList.query.filter_by(user_id=user_id).paginate(page=int(offset), per_page=5,
                                                                          error_out=False).items
            print(wishes)
            total_records = BucketList.query.filter_by(user_id=user_id).count()

            wishes_list = []
            for wish in wishes:
                wish_dict = {
                    'Id': wish.id,
                    'Title': wish.title,
                    'Description': wish.description,
                    'Date': wish.date.strftime('%Y-%m-%d')
                }
                wishes_list.append(wish_dict)
            response = [wishes_list, {'total': total_records}]
            return jsonify(response)
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/addWish', methods=['POST'])
def addWish():
    """
        Обработчик запроса на добавление нового пожелания.

        Методы:
            - POST: Добавляет новое пожелание пользователя, если пользователь авторизован.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            Редирект на домашнюю страницу пользователя.

        """
    try:
        if 'user' in session:
            title = request.form['inputTitle']
            description = request.form['inputDescription']
            user_id = session['user']
            file_path = request.form.get('filePath')
            is_private = request.form.get('private') is not None
            is_done = request.form.get('done') is not None

            new_wish = BucketList(title=title, description=description, user_id=user_id,
                                  file_path=file_path, is_private=is_private, is_done=is_done)
            db.session.add(new_wish)
            db.session.commit()

            return redirect('/userHome')
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/updateWish', methods=['POST'])
def updateWish():
    """
        Обработчик запроса на обновление информации о пожелании.

        Методы:
            - POST: Обновляет информацию о пожелании пользователя, если пользователь авторизован и имеет соответствующие права доступа.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            JSON-ответ с информацией о статусе операции.

        """
    try:
        if 'user' in session:
            user_id = session['user']
            title = request.form['title']
            description = request.form['description']
            is_private = request.form.get('is_private') == 'true'
            is_done = request.form.get('is_done') == 'true'
            wish_id = request.form['id']

            bucketlist = BucketList.query.get(wish_id)
            if not bucketlist or bucketlist.user_id != user_id:
                return jsonify({'status': 'Unauthorized access'})

            bucketlist.title = title
            bucketlist.description = description
            bucketlist.is_private = is_private
            bucketlist.is_done = is_done
            db.session.commit()

            return jsonify({'status': 'OK'})
    except Exception as e:
        return jsonify({'status': 'Unauthorized access'})


from flask_dance.contrib.github import make_github_blueprint, github
from flask_oauthlib.client import OAuth

oauth = OAuth(app)
github = oauth.remote_app(
    'github',
    consumer_key='12ea6cacbc7059441b13',
    consumer_secret='3955a2b891285d834027562b4ea2ef6fbe586430',
    request_token_params={'scope': 'user:email'},
    base_url='https://api.github.com/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://github.com/login/oauth/access_token',
    authorize_url='https://github.com/login/oauth/authorize'
)


@github.tokengetter
def get_github_token():
    return session.get('github_token')


@app.route('/login/github')
def login_github():
    """
        Обработчик запроса на аутентификацию через GitHub.

        Методы:
            - GET: Инициирует процесс аутентификации пользователя через GitHub.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            Редирект на страницу авторизации GitHub.

        """
    return github.authorize(callback=url_for('github_authorized', _external=True))


from flask_dance.consumer import oauth_authorized





@app.route('/login/github/callback')
@github.authorized_handler
def github_authorized(resp):
    """
        Обработчик коллбэка аутентификации через GitHub.

        Методы:
            - GET: Получает информацию об аутентификации пользователя через GitHub и производит соответствующие действия.

        Входные параметры:
            - resp: Ответ от GitHub содержащий информацию об аутентификации.

        Возвращаемое значение:
            Редирект на профиль пользователя или на страницу авторизации с сообщением об ошибке.

        """
    next_page = url_for('dashboard')
    if resp is None:
        flash('Authorization failed.', 'danger')
        return redirect(next_page)

    access_token = resp['access_token']
    session['github_token'] = access_token

    user_info = github.get('user').data
    email = user_info['login'] + '@mail.ru'

    # Check if the user with the given email already exists in the database
    user = User.query.filter_by(email=email).first()

    if user is None:
        # User doesn't exist, create a new user with the GitHub information
        new_user = User(name=user_info['name'],
                        email=email,
                        password=access_token)  # Set a dummy password for GitHub users
        db.session.add(new_user)
        db.session.commit()
        session['user'] = user_info['name']
        flash('Successfully logged in via GitHub!', 'success')
        return redirect(url_for('profile'))

    session['user'] = user_info['name']
    flash('Successfully logged in via GitHub!', 'success')
    return redirect(url_for('profile'))


@app.route('/validateLogin', methods=['GET', 'POST'])
def validateLogin():
    """
        Обработчик запроса на валидацию входа пользователя.

        Методы:
            - GET: Отображает страницу входа пользователя.
            - POST: Проверяет введенные данные пользователя и осуществляет вход.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - Если введенные данные верны, происходит перенаправление на страницу панели управления (dashboard).
            - Если введенные данные неверны, происходит перенаправление на страницу входа (signin) с сообщением об ошибке.

        """
    email = request.form['inputEmail']
    password = request.form['inputPassword']

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session['user'] = user.name
        return redirect('/showDashboard')

    return render_template('signin.html')


def send_email(subject: str, sender: str, recipients: list, html_body: str):
    """
    Формирует и отправляет электронное письмо с использованием предоставленных параметров.

    Аргументы:
        subject (str): Тема электронного письма.
        sender (str): Адрес электронной почты отправителя.
        recipients (list): Список адресов электронной почты получателей.
        html_body (str): Тело электронного письма в формате HTML.
    Возвращает:
        None
    """
    msg = Message(subject, sender=sender, recipients=recipients)
    msg.html = html_body
    mail.send(msg)


def send_password_reset_email(user):
    """
    Отправляет пользователю электронное письмо для сброса пароля.

    Аргументы:
        user (User): Пользователь, запросивший сброс пароля.
    Возвращает:
        None
    """
    token = user.get_reset_password_token()
    send_email('[BucketList Reset Your Password',
               sender=app.config['ADMINS'][0],
               recipients=[user.email],
               html_body=render_template('email_message.html', token=token))


@app.route('/reset_password_request', methods=['GET', 'POST'])
def reset_password_request():
    """
    Маршрут для запроса на сброс пароля. Если пользователь уже вошел в систему, перенаправляет на главную страницу.

    Возвращает:
        Отображение страницы reset_password_request.html или перенаправляет на страницу входа.
    """
    if 'user_id' in session:
        return redirect(url_for('main'))
    form = ResetPasswordRequestForm()
    user = User.query.filter_by(email=form.email.data).first()
    if user:
        send_password_reset_email(user)
        flash('Check your email for the instructions to reset your password')
        return redirect(url_for('main'))
    else:
        flash('There is no user with this email')
    return render_template('confirm_reset_password.html',
                           title='Reset Password', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token: str):
    """
    Маршрут для сброса пароля с действующим токеном. Если пользователь уже вошел в систему, перенаправляет на главную страницу.

    Аргументы:
        token (str): Токен для сброса пароля.
    Возвращает:
        Отображение страницы reset_password.html или перенаправляет на страницу входа.
    """
    if 'user_id' in session:
        return redirect(url_for('main'))
    user = User.verify_reset_password_token(token)
    if not user:
        flash('Invalid or expired token')
        return redirect(url_for('main'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been reset.')
        return redirect(url_for('showSignin'))
    return render_template('reset_password.html', form=form)

@app.route('/signUp', methods=['POST', 'GET'])
def signUp():
    """
        Обработчик запроса на регистрацию нового пользователя.

        Методы:
            - GET: Отображает страницу регистрации пользователя.
            - POST: Создает нового пользователя на основе введенных данных.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - Если все обязательные поля заполнены, новый пользователь создается в базе данных и возвращается сообщение об успешной регистрации.
            - Если не все обязательные поля заполнены, возвращается HTML-сообщение о необходимости заполнения обязательных полей.
            - В случае возникновения ошибки, возвращается сообщение об ошибке.

        """
    try:
        name = request.form['inputName']
        email = request.form['inputEmail']
        password = request.form['inputPassword']

        if name and email and password:

            hashed_password = generate_password_hash(password)
            new_user = User(name=name, email=email, password=hashed_password)

            db.session.add(new_user)
            db.session.commit()
            return jsonify({'message': 'User created successfully!'})
        else:
            return jsonify({'html': '<span>Enter the required fields</span>'})

    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/update_profile', methods=['POST'])
def update_profile():
    """
        Обработчик запроса на обновление профиля пользователя.

        Методы:
            - POST: Обновляет имя и адрес электронной почты пользователя на основе введенных данных.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - После успешного обновления профиля происходит перенаправление на страницу профиля пользователя.

        """
    user_id = session['user']
    user = User.query.get(user_id)
    user.name = request.form['name']
    user.email = request.form['email']
    db.session.commit()
    return redirect(url_for('profile'))


# Маршрут для загрузки фотографии пользователя
@app.route('/upload_photo', methods=['POST'])
def upload_photo():
    """
        Обработчик запроса на загрузку фотографии пользователя.

        Методы:
            - POST: Загружает выбранное пользователем фото и связывает его с профилем пользователя.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - После успешной загрузки фотографии происходит перенаправление на страницу профиля пользователя.

        """
    user_name = session['user']
    user = User.query.filter_by(name=user_name).first()
    if 'photo' in request.files:
        file = request.files['photo']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.photo = filename
            db.session.commit()
    return redirect(url_for('profile'))


@app.route('/editWish/<int:wish_id>', methods=['GET', 'POST'])
def editWish(wish_id):
    """
        Обработчик запроса на редактирование желания в списке.

        Методы:
            - GET: Отображает страницу редактирования желания с предварительно заполненными данными желания.
            - POST: Сохраняет внесенные изменения в желании.

        Входные параметры:
            - wish_id (int): Идентификатор желания, которое требуется отредактировать.

        Возвращаемое значение:
            - Если желание с указанным идентификатором не найдено, происходит перенаправление на домашнюю страницу пользователя.
            - При успешном сохранении изменений в желании происходит перенаправление на домашнюю страницу пользователя.

        """
    wish = BucketList.query.get(wish_id)
    if not wish:
        flash('Wish not found')
        return redirect(url_for('userHome'))

    if request.method == 'POST':
        title = request.form['editTitle']
        description = request.form['editDescription']
        file_path = request.form['editFilePath']
        is_private = request.form.get('editIsPrivate') == 'on'
        is_done = request.form.get('editIsDone') == 'on'

        wish.title = title
        wish.description = description
        wish.file_path = file_path
        wish.is_private = is_private
        wish.is_done = is_done
        db.session.commit()

        flash('Wish updated successfully')
        return redirect(url_for('userHome'))

    return render_template('editWish.html', wish=wish)


@app.route('/forgotPassword', methods=['GET', 'POST'])
def forgot_password():
    """
        Обработчик запроса на восстановление пароля.

        Методы:
            - GET: Отображает страницу восстановления пароля.
            - POST: Отправляет инструкции по восстановлению пароля на указанный электронный адрес.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - При успешной отправке инструкций по восстановлению пароля происходит перенаправление на страницу входа.

        """
    if request.method == 'POST':
        email = request.form['inputEmail']
        # Logic to send password recovery instructions to the provided email
        flash('Password recovery instructions have been sent to your email.')
        return redirect(url_for('signin'))  # Redirect to the sign-in page after submitting the email form

    return render_template('forgot_password.html')  # Create a new template for the password recovery page


def check_current_password(user, current_password):
    """
        Проверяет, совпадает ли текущий пароль пользователя с предоставленным паролем.

        Входные параметры:
            - user: Объект пользователя, для которого выполняется проверка пароля.
            - current_password: Текущий пароль, который нужно проверить.

        Возвращаемое значение:
            - True, если текущий пароль совпадает с предоставленным паролем.
            - False, если текущий пароль не совпадает с предоставленным паролем.

        """
    return check_password_hash(user.password, current_password)


def update_password(user, new_password):
    """
        Обновляет пароль пользователя.

        Входные параметры:
            - user: Объект пользователя, для которого требуется обновить пароль.
            - new_password: Новый пароль, который нужно установить для пользователя.

        Возвращаемое значение:
            Нет.

        """
    user.password = generate_password_hash(new_password)
    db.session.commit()


@app.route('/change_password', methods=['POST'])
def change_password():
    """
        Обработчик запроса на изменение пароля пользователя.

        Метод:
            - POST: Обрабатывает введенные данные и изменяет пароль пользователя.

        Входные параметры:
            Нет.

        Возвращаемое значение:
            - При успешном изменении пароля происходит перенаправление на страницу профиля пользователя.

        """
    current_password = request.form['current_password']
    new_password = request.form['new_password']
    confirm_password = request.form['confirm_password']

    user_name = session['user']
    print(f"user_id {user_name}")  # Проверка значения идентификатора пользователя

    user = user = User.query.filter_by(name=user_name).first()
    print(f"user{user}")

    # Проверяем, что текущий пароль пользователя соответствует введенному текущему паролю
    if check_current_password(user, current_password):
        # Проверяем, что новый пароль и его подтверждение совпадают
        if new_password == confirm_password:
            # Обновляем пароль пользователя в базе данных
            update_password(user, new_password)
            flash('Password successfully changed', 'success')
        else:
            flash('New password and confirm password do not match', 'error')
    else:
        flash('Invalid current password', 'error')

    return redirect(url_for('profile'))
