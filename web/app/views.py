import secrets
import string
from flask import (jsonify, render_template,
                   request, url_for, flash, redirect, current_app, session)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.urls import url_parse
from werkzeug.utils import secure_filename
from sqlalchemy.sql import text
from flask_login import login_user, login_required, logout_user, current_user
from flask_mail import Message as Messages


import os
from app import app
from app import db
from app import login_manager
from app import oauth
from app import mail
from requests import get
from datetime import datetime, timedelta
import random

from app.models.authuser import AuthUser, PrivateMood, PrivateMessage
from app.models.moods import Moody
from app.models.message import Message


@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our
    # user table, use it in the query for the user
    return AuthUser.query.get(int(user_id))


@app.route('/crash')
def crash():
    return 1/0


@app.route('/db')
def db_connection():
    try:
        with db.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return '<h1>db works.</h1>'
    except Exception as e:
        return '<h1>db is broken.</h1>' + str(e)

# ---------------- About us Page ------------------------------------------------------------------
@app.route('/about')
def about():
    return app.send_static_file('about.html')

# ---------------- Index Page ------------------------------------------------------------------
@app.route('/diary', methods=('GET', 'POST'))
def diary_index():
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        validated = True
        validated_dict = dict()
        valid_keys = ['privacy', 'messages']
        app.logger.debug('validated dict: ' + str(result))

        for key in result:
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()

            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value

        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            # if there is no id: create a new messages entry
            if not id_:
                validated_dict['owner_id'] = current_user.id
                entry = PrivateMessage(**validated_dict)
                app.logger.debug(str(entry))
                db.session.add(entry)
            # if there is an id already: update the messages entry
            else:
                messages = PrivateMessage.query.get(id_)
                app.logger.debug('validated dict: ' + str(result))
                if messages.owner_id == current_user.id:
                    app.logger.debug('validated dict: ' + str(result))
                    messages.update(**validated_dict)

            db.session.commit()
            return diary_data_mess_public()

    return render_template('diary/index.html')

# ---------------- Profile Page ------------------------------------------------------------------
@app.route('/diary/profile', methods=('GET', 'POST'))
@login_required
def diary_profile():
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        validated = True
        validated_dict = dict()
        valid_keys = ['privacy', 'messages']
        app.logger.debug('validated dict: ' + str(result))

        for key in result:
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()

            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value

        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            # if there is no id: create a new messages entry
            if not id_:
                validated_dict['owner_id'] = current_user.id
                entry = PrivateMessage(**validated_dict)
                app.logger.debug(str(entry))
                db.session.add(entry)
            # if there is an id already: update the messages entry
            else:
                messages = PrivateMessage.query.get(id_)
                app.logger.debug('validated dict: ' + str(result))
                if messages.owner_id == current_user.id:
                    app.logger.debug('validated dict: ' + str(result))
                    messages.update(**validated_dict)

            db.session.commit()
            return diary_data_mess_profile()

    return render_template('diary/profile.html')

# ---------------- Login Page ------------------------------------------------------------------
@app.route('/diary/login', methods=('GET', 'POST'))
def diary_login():
    if request.method == 'POST':
        # login code goes here
        login_id = request.form.get('login_id')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        user = AuthUser.query.filter((AuthUser.username == login_id) | (
            AuthUser.email == login_id)).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the
        # hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            # if the user doesn't exist or password is wrong, reload the page
            return redirect(url_for('diary_login'))

        # if the above check passes, then we know the user has the right
        # credentials
        session.pop('authenticated', None)
        session.pop('otp', None)
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('diary_index')
        return redirect(next_page)

    return render_template('diary/login.html')

# ---------------- Signup Page ------------------------------------------------------------------
@app.route('/diary/signup', methods=('GET', 'POST'))
def diary_signup():

    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))

        validated = True
        validated_dict = {}
        valid_keys = ['email', 'username', 'name', 'password']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            username = validated_dict['username']
            name = validated_dict['name']
            password = validated_dict['password']
            # if this returns a user, then the email already exists in database
            user_email = AuthUser.query.filter_by(email=email).first()
            user_username = AuthUser.query.filter_by(username=username).first()

            if user_email:
                # if a user is found, we want to redirect back to signup
                # page so user can try again
                flash('Email address already exists')
                return redirect(url_for('diary_signup'))

            if user_username:
                # if a user is found, we want to redirect back to signup
                # page so user can try again
                flash('Username already exists')
                return redirect(url_for('diary_signup'))

            app.logger.debug("preparing to add")
            avatar_url = '/static/img/account.png'
            new_user = AuthUser(email=email, username=username, name=name,
                                password=generate_password_hash(
                                    password, method='sha256'),
                                avatar_url=avatar_url)
            # add the new user to the database
            db.session.add(new_user)
            db.session.commit()

        return redirect(url_for('diary_login'))
    return render_template('diary/signup.html')

# ---------------- Logout Page ----------------------------------------------------------------------------
@app.route('/diary/logout')
@login_required
def diary_logout():
    session.pop('authenticated', None)
    session.pop('otp', None)
    logout_user()
    return redirect(url_for('diary_index'))

# ---------------- Verify Email Page ------------------------------------------------------------------
@app.route('/diary/verify', methods=['GET', 'POST'])
@login_required
def verify():
    if request.method == 'POST':
        
        # Check if the "resend" button was clicked
        if 'resend' in request.form:
            # Generate a new OTP and store it in the session
            otp = generate_otp()  # Your function to generate OTP
            otp_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            session['otp'] = otp
            session['otp_time'] = otp_time
            return render_template('diary/verify.html')

        # Get the submitted OTP from the form
        submitted_otp = ''.join([request.form.get(f'num{i+1}') for i in range(6)])

        # Get the OTP from the session
        stored_otp = session.get('otp')
        otp_time = session.get('otp_time')

        # Calculate the time difference between the OTP creation time and the current time
        time_diff = datetime.now() - datetime.strptime(otp_time, '%Y-%m-%d %H:%M:%S.%f')

        # Check if the submitted OTP matches the one in the session
        if submitted_otp == stored_otp and time_diff <= timedelta(minutes=5):
            # Clear the OTP from the session
            session.pop('otp', None)
            session.pop('otp_time', None)

            # Add the user to the authenticated users list in the session
            session['authenticated'] = True

            # Allow the user to access the protected page
            return redirect(url_for('diary_account_setting'))

        # If the OTP doesn't match, show an error message
        flash("Invalid OTP. Please try again.")
        return render_template('diary/verify.html')

    # Generate a new OTP and store it in the session
    otp = generate_otp()  # Your function to generate OTP
    otp_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
    session['otp'] = otp
    session['otp_time'] = otp_time

    # Display the form with the OTP field
    return render_template('diary/verify.html')

# ---------------- Generate OTP ------------------------------------------------------------------
def generate_otp():
    email = current_user.email
    if email:
        # generate a 6-digit OTP
        otp = str(random.randint(100000, 999999))

        # send the OTP to the user's email address
        msg = Messages('Verify your email address',
                      sender='kritsadi_th@hotmail.com', recipients=[email])
        msg.body = f'OTP request\n\nโปรดนำรหัสยืนยัน (Verification Code) นี้ไประบุในหน้ายืนยันรหัส OTP\n{otp}\n\nรหัสยืนยันนี้จะหมดอายุภายใน 5 นาที\nห้ามนำรหัสยืนยันนี้ให้กับบุคคลอื่นเด็ดขาด'
        mail.send(msg)
        return(otp)

# ---------------- Edit Profile Page ------------------------------------------------------------------
@app.route('/diary/edit_profile', methods=('GET', 'POST'))
@login_required
def diary_edit_profile():

    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
        id_ = current_user.id

        validated = True
        validated_dict = {}
        valid_keys = ['name', 'tel', 'gender', 'birthday', 'age']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if value == 'undefined':
                validated = False
                break
            
            if not value:
                validated_dict[key] = None
                continue
            
            validated_dict[key] = value
            # code to validate and edit user info goes here
        app.logger.debug("validation done")
        # handle the image upload
        app.logger.debug(request.files)
        avatar = request.files.get('image')
        avatar_url = None
        if avatar:
            # validate the file type
            if not avatar.filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif')):
                flash('Invalid file type. Please upload an image file.')
                return redirect(url_for('diary_edit_profile'))
    
            # save the file to disk
            photos_folder = os.path.join(current_app.root_path, 'static', 'img')
            
            # Get the original file extension in lowercase
            file_extension = avatar.filename.split('.')[-1].lower()

            # Generate the new filename using current user ID and file extension
            filename = secure_filename(f"user_{current_user.id}.{file_extension}")
            
            avatar_path = os.path.join(photos_folder, filename)
            avatar.save(avatar_path)
            
            # Set the avatar_url to the photo path
            avatar_url = os.path.join('/static', 'img', filename)
            validated_dict['avatar_url'] = avatar_url

        app.logger.debug(avatar)
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            name = validated_dict['name']
            tel = validated_dict['tel']
            gender = validated_dict['gender']
            birthday = validated_dict['birthday']
            age = validated_dict['age']

            app.logger.debug("preparing to edit")
            authUser = AuthUser.query.get(id_)
            authUser.update(name=name, tel=tel, gender=gender, birthday=birthday, age=age, avatar_url=avatar_url)
            db.session.commit()
            flash('Profile updated.')

        return redirect(url_for('diary_edit_profile'))
    return render_template('diary/edit_profile.html')


# ---------------- Edit Account Page ------------------------------------------------------------------
@app.route('/diary/account_setting', methods=('GET', 'POST'))
@login_required
def diary_account_setting():
    # Check if the user is authenticated in the session
    authenticated = session.get('authenticated')

    if not authenticated:
        # If the user is not authenticated, redirect to the OTP verification page
        return redirect(url_for('verify'))
    
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
        id_ = current_user.id
 
        validated = True
        validated_dict = {}
        valid_keys = ['email', 'username']

        # validate the input
        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and edit user info goes here
            
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            username = validated_dict['username']
        
            # if this returns a user, then the email already exists in database
            user = AuthUser.query.filter_by(email=email).first()
            if user and (email != current_user.email):
                # if a user is found, reload the page so user can try again
                flash('Email address already exists.')
                return redirect(url_for('diary_account_setting'))
            
            # if this returns a user, then the email already exists in database
            user_username = AuthUser.query.filter_by(username=username).first()
            if user_username and (username != current_user.username):
                # if a user is found, reload the page so user can try again
                flash('Username already exists.')
                return redirect(url_for('diary_account_setting'))
        
            app.logger.debug("preparing to edit account")
            authUser = AuthUser.query.get(id_)
            authUser.update(email=email, username=username)
            db.session.commit()
            flash('Account updated.')

        return redirect(url_for('diary_account_setting'))
    return render_template('diary/account_setting.html')


# ---------------- Table Form Page ------------------------------------------------------------------
@app.route('/diary/form', methods=('GET', 'POST'))
@login_required
def diary_mood():
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
        validated = True
        validated_dict = dict()
        valid_keys = ['sleep', 'meditation', 'mind', 'boring', 'social']

        # validate the input
        for key in result:
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value

        cal_mood = int(validated_dict['sleep']) + int(validated_dict['meditation']) + int(
            validated_dict['mind']) + int(validated_dict['social']) + int(validated_dict['boring'])
        validated_dict['sum_mood'] = cal_mood

        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            # if there is no id: create a new messages entry
            validated_dict['owner_id'] = current_user.id
            entry = PrivateMood(**validated_dict)
            app.logger.debug(str(entry))
            db.session.add(entry)
            db.session.commit()
            return redirect(url_for('diary_mood_sum'))

    return render_template('diary/mood.html')

# ---------------- Summary Graph Page ------------------------------------------------------------------
@app.route('/diary/look')
@login_required
def diary_mood_sum():
    return render_template('diary/moodday.html')

# ------------------- Data for Form Page and Summary Graph Page --------------------------------------------------
@app.route("/diary/data-mood")
@login_required
def diary_data_mood():
    messages = []
    # https://stackoverflow.com/questions/15791760/how-can-i-do-multiple-order-by-in-flask-sqlalchemy
    db_messages = PrivateMood.query.order_by(Moody.date_created.desc()).all()
    messages = list(map(lambda x: x.to_dict(), db_messages))
    app.logger.debug("DB message: " + str(messages))

    return jsonify(messages)

# ------------ Data for Profile Page -----------------------------------------------------------------
@app.route("/diary/data-mess-profile")
@login_required
def diary_data_mess_profile():
    message = []
    # https://stackoverflow.com/questions/15791760/how-can-i-do-multiple-order-by-in-flask-sqlalchemy
    id_ = current_user.id
    db_message = PrivateMessage.query.filter_by(
        owner_id=id_).order_by(Message.date_created.desc()).all()
    message = list(map(lambda x: x.to_dict(), db_message))
    app.logger.debug("DB message: " + str(message))

    return jsonify(message)

# ------------ Data for Index Page -----------------------------------------------------------------
@app.route("/diary/data-mess-public")
def diary_data_mess_public():
    messages = []
    if current_user.is_authenticated:
        db_messages = PrivateMessage.query.filter_by(privacy='Public').union_all(
            PrivateMessage.query.filter_by(owner_id=current_user.id)).order_by(Message.date_created.desc()).all()
    else:
        db_messages = PrivateMessage.query.filter_by(
            privacy='Public').order_by(Message.date_created.desc()).all()
    messages = list(map(lambda x: x.to_dict(), db_messages))
    # Get all user data except for password and session_token
    authUser = []
    db_authUser = AuthUser.query.all()
    authUser = list(map(lambda x: {"id": x.id, "username": x.username,
                    "name": x.name, "avatar_url": x.avatar_url}, db_authUser))
    # Pair up user and message data using owner_id from PrivateMessage
    for message in messages:
        for user in authUser:
            if user["id"] == message["owner_id"]:
                message["user"] = user
                break
    return jsonify(messages)

# ------------ Remove Mesasages Route -----------------------------------------------------------------
@app.route('/diary/remove-mess-public', methods=('GET', 'POST'))
@login_required
def diary_remove_mess_public():
    app.logger.debug("DIARY - REMOVE")
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        try:
            message = PrivateMessage.query.get(id_)
            if message.owner_id == current_user.id:
                db.session.delete(message)
                db.session.commit()

        except Exception as ex:
            app.logger.debug(ex)
            raise

    return diary_data_mess_public()

# ------------ Remove Mesasages Route ------------------------------------------------------------------
@app.route('/diary/remove-mess-profile', methods=('GET', 'POST'))
@login_required
def diary_remove_mess_profile():
    app.logger.debug("DIARY - REMOVE")
    if request.method == 'POST':
        result = request.form.to_dict()
        id_ = result.get('id', '')
        try:
            message = PrivateMessage.query.get(id_)
            if message.owner_id == current_user.id:
                db.session.delete(message)
                db.session.commit()

        except Exception as ex:
            app.logger.debug(ex)
            raise

    return diary_data_mess_profile()

# ---------------- Google Oauth ------------------------------------------------------------------
@app.route('/google/')
def google():

    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile'
        }
    )

    # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, access_type='offline', prompt='consent')


@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()

    userinfo = token['userinfo']
    app.logger.debug(" Google User " + str(userinfo))
    email = userinfo['email']
    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        if 'family_name' in userinfo:
            name = userinfo['given_name'] + " " + userinfo['family_name']
        else:
            name = userinfo['given_name']
        username = userinfo['given_name']
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                           for i in range(random_pass_len))

        picture_url = userinfo['picture'].replace('=s96-c', '=s512')
        # picture_url = userinfo['picture'].replace('=s96-c', '')
        picture_data = get(picture_url).content

        # Save the photo to disk
        photos_folder = os.path.join(current_app.root_path, 'static', 'img')
        filename = f'{username}.jpg'
        filepath = os.path.join(photos_folder, filename)
        with open(filepath, 'wb') as f:
            f.write(picture_data)

        # Set the avatar_url to the photo path
        avatar_url = os.path.join('/static', 'img', filename)

        new_user = AuthUser(email=email, name=name, username=username,
                            password=generate_password_hash(
                                password, method='sha256'),
                            avatar_url=avatar_url)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()

    login_user(user)
    return redirect('/diary')

# ---------------- Facebook Oauth -----------------------------------------------------------------
@app.route('/facebook/')
def facebook():

    oauth.register(
        name='facebook',
        client_id=app.config['FACEBOOK_CLIENT_ID'],
        client_secret=app.config['FACEBOOK_CLIENT_SECRET'],
        access_token_url='https://graph.facebook.com/oauth/access_token',
        access_token_params=None,
        authorize_url='https://www.facebook.com/dialog/oauth',
        authorize_params=None,
        api_base_url='https://graph.facebook.com/',
        client_kwargs={'scope': 'email'},
    )
    redirect_uri = url_for('facebook_auth', _external=True)
    return oauth.facebook.authorize_redirect(redirect_uri)


@app.route('/facebook/auth/')
def facebook_auth():
    token = oauth.facebook.authorize_access_token()

    response = oauth.facebook.get(
        'me?fields=id,email,first_name,last_name,picture', token=token)
    userinfo = response.json()
    app.logger.debug(" Facebook User " + str(userinfo))
    email = userinfo['email']
    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        name = userinfo['first_name'] + " " + userinfo['last_name']
        username = userinfo['first_name']
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                           for i in range(random_pass_len))
        picture = userinfo['picture']['data']['url']
        picture_data = get(picture).content

        # Save the photo to disk
        photos_folder = os.path.join(current_app.root_path, 'static', 'img')
        filename = f'{username}.jpg'
        filepath = os.path.join(photos_folder, filename)
        with open(filepath, 'wb') as f:
            f.write(picture_data)

        # Set the avatar_url to the photo path
        avatar_url = os.path.join('/static', 'img', filename)

        new_user = AuthUser(email=email, name=name, username=username,
                            password=generate_password_hash(
                                password, method='sha256'),
                            avatar_url=avatar_url)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()
    login_user(user)
    return redirect('/diary')

# ---------------- GitHub Oauth ------------------------------------------------------------------
@app.route('/github/')
def github():

    oauth.register(
        name='github',
        client_id=app.config['GITHUB_CLIENT_ID'],
        client_secret=app.config['GITHUB_CLIENT_SECRET'],
        access_token_url='https://github.com/login/oauth/access_token',
        access_token_params=None,
        authorize_url='https://github.com/login/oauth/authorize',
        authorize_params=None,
        api_base_url='https://api.github.com/',
        client_kwargs={'scope': 'user:email'},
    )
    redirect_uri = url_for('github_auth', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@app.route('/github/auth/')
def github_auth():
    token = oauth.github.authorize_access_token()

    # Get user info
    response = oauth.github.get('user', token=token)
    userinfo = response.json()
    app.logger.debug(" Github User " + str(userinfo))

    # Get email address
    email = userinfo.get('email')
    if not email:
        response = oauth.github.get('user/emails', token=token)
        email_list = response.json()
        email = next(
            (item for item in email_list if item["primary"]), {}).get("email")

    # Find or create user
    user = AuthUser.query.filter_by(email=email).first()
    if not user:
        name = userinfo.get('name') or userinfo['login']
        username = userinfo['login']
        password = secrets.token_urlsafe(16)
        picture = userinfo['avatar_url']
        picture_data = get(picture).content

        # Save the photo to disk
        photos_folder = os.path.join(current_app.root_path, 'static', 'img')
        filename = f'{username}.jpg'
        filepath = os.path.join(photos_folder, filename)
        with open(filepath, 'wb') as f:
            f.write(picture_data)

        # Set the avatar_url to the photo path
        avatar_url = os.path.join('/static', 'img', filename)

        new_user = AuthUser(email=email, name=name, username=username,
                            password=generate_password_hash(
                                password, method='sha256'),
                            avatar_url=avatar_url)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()

    # Log in user and redirect
    login_user(user)
    return redirect('/diary')
