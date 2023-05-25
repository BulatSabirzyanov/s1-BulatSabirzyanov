from flask import Flask, render_template, request, redirect, session, jsonify, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import uuid
from werkzeug.utils import secure_filename
from .models import User,BucketList,Like, db


app = Flask(__name__)
def allowed_file(filename):
    allowed_extensions = {'jpg', 'jpeg', 'png', 'gif'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions
@app.route('/')
def main():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' in request.files:
        file = request.files['file']
        if file.filename != '':
            extension = os.path.splitext(file.filename)[1]
            f_name = str(uuid.uuid4()) + extension
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], f_name))
            return jsonify({'filename': f_name})
    return jsonify({'error': 'File upload failed.'})

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
            wishes = BucketList.query.filter_by(user_id=user_id).all()

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
    return render_template('dashboard.html')


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


@app.route('/getWish', methods=['POST'])
def getWish():
    try:
        if 'user' in session:
            user_id = session['user']

            offset = request.form['offset']
            total_records = 0

            wishes = BucketList.query.filter_by(user_id=user_id).paginate(int(offset), False).items
            total_records = BucketList.query.filter_by(user_id=user_id).count()

            wishes_dict = []
            for wish in wishes:
                wish_dict = {
                    'Id': wish.id,
                    'Title': wish.title,
                    'Description': wish.description,
                    'Date': wish.date.strftime('%Y-%m-%d')
                }
                wishes_dict.append(wish_dict)

            response = [wishes_dict, {'total': total_records}]
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
            wish_id = request.form['id']
            file_path = request.form['filePath']
            is_private = request.form['isPrivate']
            is_done = request.form['isDone']

            bucketlist = BucketList.query.get(wish_id)
            if not bucketlist or bucketlist.user_id != user_id:
                return jsonify({'status': 'Unauthorized access'})

            bucketlist.title = title
            bucketlist.description = description
            bucketlist.file_path = file_path
            bucketlist.is_private = is_private
            bucketlist.is_done = is_done
            db.session.commit()

            return jsonify({'status': 'OK'})
    except Exception as e:
        return jsonify({'status': 'Unauthorized access'})


@app.route('/validateLogin', methods=['POST'])
def validateLogin():
    try:
        email = request.form['inputEmail']
        password = request.form['inputPassword']

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password, password):
            session['user'] = user.id
            return redirect('/showDashboard')
        else:
            return render_template('error.html', error='Wrong Email address or Password.')

    except Exception as e:
        return render_template('error.html', error=str(e))


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


@app.route('/profile')
def profile():
    if 'user' in session:
        user_id = session['user']
        user = User.query.filter_by(id=user_id).first()
        if user:
            return render_template('profile.html', user=user)
    return render_template('error.html', error='Unauthorized Access')

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
    user_id = session['user']
    user = User.query.get(user_id)
    if 'photo' in request.files:
        file = request.files['photo']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            user.photo = filename
            db.session.commit()
    return redirect(url_for('profile'))



