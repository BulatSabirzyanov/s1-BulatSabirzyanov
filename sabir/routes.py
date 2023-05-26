from flask import Flask, render_template, request, redirect, session, jsonify, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from sabir import app, db
from sabir.forms import ResetPasswordForm_2, ResetPasswordForm
from sabir.models import User,BucketList,Like


app.config['MAIL_SERVER'] = 'smtp.mail.ru'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'sabirzyanov427@mail.ru'
app.config['MAIL_PASSWORD'] = 'MuXPHsf9W2wHHe3p5dk2'
# RZHI1u1taet^
app.config['MAIL_DEFAULT_SENDER'] = 'sabirzyanov427@mail.ru'
app.config['MAIL_USE_MANAGEMENT_COMMANDS'] = True  # Включение поддержки асинхронной отправки

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])




def allowed_file(filename):
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
@app.route('/')
def main():
    return render_template('index.html')
@app.route('/profile')
def profile():
    if 'user' in session:
        user_name = session['user']
        user = User.query.filter_by(name=user_name).first()
        if user:
            return render_template('profile.html', user=user)
    return render_template('error.html', error='Unauthorized Access')

@app.route("/upload", methods=["POST"])
def upload():
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
    return render_template('signup.html')

@app.route('/showAddWish')
def showAddWish():
    return render_template('addWish.html')

@app.route('/addUpdateLike', methods=['POST'])
def addUpdateLike():
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
    try:
        if 'user' in session:
            user_id = session['user']
            wishes = BucketList.query.all()
            wishes_dict = []
            for wish in wishes:
                wish_dict = {
                    'Id': wish.id,
                    'Title': wish.title,
                    'Description': wish.description,
                    'FilePath': wish.file_path,
                    'Like': wish.likes.count(),
                    'HasLiked': Like.query.filter_by(user_id=user_id, bucketlist_id=wish.id).first() is not None
                }
                wishes_dict.append(wish_dict)

            return jsonify(wishes_dict)
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/showDashboard')
def showDashboard():
    if 'user' in session:
        return render_template('dashboard.html')

@app.route('/dashboard')
def dashboard():
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
    if 'user' in session:
        return render_template('userHome.html')
    else:
        return render_template('signin.html')


@app.route('/userHome')
def userHome():
    if 'user' in session:
        return render_template('userHome.html')
    else:
        return render_template('error.html', error='Unauthorized Access')


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')


@app.route('/deleteWish', methods=['POST'])
def deleteWish():
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
    try:
        if 'user' in session:
            user_id = session['user']

            offset = request.args.get('offset')
            total_records = 0
            wishes = BucketList.query.filter_by(user_id=user_id).paginate(page=int(offset), per_page=5, error_out=False).items
            print(wishes)
            total_records = BucketList.query.filter_by(user_id=user_id).count()

            wishes_list = []
            for wish in wishes:
                wish_dict  = {
                    'Id': wish.id,
                    'Title': wish.title,
                    'Description': wish.description,
                    'Date': wish.date.strftime('%Y-%m-%d')
                }
                wishes_list.append(wish_dict )
            response = [wishes_list, {'total': total_records}]
            return jsonify(response)
        else:
            return jsonify({'error': 'Unauthorized Access'})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/addWish', methods=['POST'])
def addWish():
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
    return github.authorize(callback=url_for('github_authorized', _external=True))

from flask_dance.consumer import oauth_authorized

@app.route('/login/github/callback')
@github.authorized_handler
def github_authorized(resp):

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

    email = request.form['inputEmail']
    password = request.form['inputPassword']

    user = User.query.filter_by(email=email).first()

    if user and check_password_hash(user.password, password):
        session['user'] = user.name
        return redirect('/showDashboard')


    return render_template('signin.html')



@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            token = serializer.dumps(email, salt='reset-password')
            reset_link = url_for('confirm_reset_password', token=token, _external=True)
            message = Message('Сброс пароля', recipients=[email])
            message.body = f'Для сброса пароля пройдите по ссылке: {reset_link}'
            mail.send(message)  # Отправка асинхронного письма
            flash('Инструкции по сбросу пароля были отправлены на вашу почту.', 'info')
            return redirect(url_for('login'))
        flash('Адрес электронной почты не найден.', 'error')
    return render_template('reset_password.html', form=form, title='Сброс пароля')



@app.route('/confirm_reset_password/<token>', methods=['GET', 'POST'])
def confirm_reset_password(token):
    form = ResetPasswordForm_2()
    if form.validate_on_submit():
        email = serializer.loads(token, salt='reset-password', max_age=3600)
        user = User.query.filter_by(email=email).first()
        if user:
            # Обновление пароля пользователя
            user.password = generate_password_hash(form.password.data)  # Hash the password

            db.session.commit()
            flash('Пароль успешно изменен.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Пользователь не найден.', 'error')
            return redirect(url_for('login'))

    return render_template('confirm_reset_password.html', form=form, token=token, title='Подтверждение сброса пароля')
@app.route('/signUp', methods=['POST', 'GET'])
def signUp():
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
    user_id = session['user']
    user = User.query.get(user_id)
    user.name = request.form['name']
    user.email = request.form['email']
    db.session.commit()
    return redirect(url_for('profile'))

# Маршрут для загрузки фотографии пользователя
@app.route('/upload_photo', methods=['POST'])
def upload_photo():
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
    if request.method == 'POST':
        email = request.form['inputEmail']
        # Logic to send password recovery instructions to the provided email
        flash('Password recovery instructions have been sent to your email.')
        return redirect(url_for('signin'))  # Redirect to the sign-in page after submitting the email form

    return render_template('forgot_password.html')  # Create a new template for the password recovery page

def check_current_password(user, current_password):
    return check_password_hash(user.password, current_password)

def update_password(user, new_password):
    user.password = generate_password_hash(new_password)
    db.session.commit()


@app.route('/change_password', methods=['POST'])
def change_password():
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


