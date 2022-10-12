import functools
import random
from select import select
from tkinter import INSERT
import flask
from . import utils

from email.message import EmailMessage
import smtplib

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from app.db import get_db

bp = Blueprint('auth', __name__, url_prefix='/auth')

@bp.route('/activate', methods=('GET', 'POST'))
def activate():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': #if request.method == ?:
            number = request.args['auth'] 
            
            db = get_db()   #db = ?
            attempt = db.execute(
                'SELECT * FROM activationlink WHERE challenge = ? AND state = ? AND CURRENT_TIMESTAMP between created and validuntil', (number, utils.U_UNCONFIRMED) #QUERY, (number, utils.U_UNCONFIRMED) #error / para poder activar la cuenta, debes tomar tambien el current_timestamp  e indicarle entre que variables lo puede encontrar en la tabla activationlink (and CURRENT_TIMESTAMP BETWEEN created AND validuntil) ok
            ).fetchone()

            if attempt is not None:
                db.execute(
                    'UPDATE activationlink SET state = ? WHERE id = ?', (utils.U_CONFIRMED, attempt['id']) #QUERY, (utils.U_CONFIRMED, attempt['id'])
                )
                db.execute(
                    'INSERT INTO user (username, password, salt, email) VALUES (?, ?, ?, ?)', (attempt['username'], attempt['password'], attempt['salt'], attempt['email']) #QUERY, (attempt['username'], attempt['password'], attempt['salt'], attempt['email'])
                )
                db.commit()

        return redirect(url_for('auth.login'))
    except Exception as e:
        print(e)
        return redirect(url_for('auth.login'))


@bp.route('/register', methods=('GET', 'POST')) #@bp.route('/register', methods=?)
def register():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
      
        if request.method == 'POST': #if request.method == ?:    
            username = request.form['username'] #username = ?
            password = request.form['password'] #password = ? 
            email = request.form['email'] #email = ?
            
            db = get_db() #db = ?
            error = None

            if not username: #if ?:
                error = 'Username is required.'
                flash(error)
                return render_template('auth/register.html') #return render_template(TEMP)
            
            if not utils.isUsernameValid(username):
                error = "Username should be alphanumeric plus '.','_','-'"
                flash(error)
                return render_template('auth/register.html') #return render_template(TEMP)

            if not password: #if ?:
                error = 'Password is required.'
                flash(error)
                return render_template('auth/register.html')

            if db.execute('SELECT id FROM user WHERE username = ?', (username,)).fetchone() is not None: #if db.execute(QUERY, (username,)).fetchone() is not None:
                error = 'User {} is already registered.'.format(username)
                flash(error)
                return render_template('auth/register.html') #return render_template(TEMP)
            
            if ((not email) or (not utils.isEmailValid(email))): #if (? or (not utils.isEmailValid(email))):
                error =  'Email address invalid.'
                flash(error)
                return render_template('auth/register.html')
            
            if db.execute('SELECT id FROM user WHERE email = ?', (email,)).fetchone() is not None:
                error =  'Email {} is already registered.'.format(email)
                flash(error)
                return render_template('auth/register.html') #return render_template(TEMP)
            
            if (not utils.isPasswordValid(password)):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long'
                flash(error)
                return render_template('auth/register.html')

            salt = hex(random.getrandbits(128))[2:]
            hashP = generate_password_hash(password + salt)
            number = hex(random.getrandbits(512))[2:]

            db.execute(
                'INSERT INTO activationlink (challenge, state, username, password, salt, email)  Values(?,?,?,?,?,?)', #QUERY,
                (number, utils.U_UNCONFIRMED, username, hashP, salt, email)
            )
            db.commit()

            credentials = db.execute(
                'Select user,password from credentials where name=?', (utils.EMAIL_APP,)
            ).fetchone()

            content = 'Hello there, to activate your account, please click on this link ' + flask.url_for('auth.activate', _external=True) + '?auth=' + number
            
            send_email(credentials, receiver=email, subject='Activate your account', message=content)
            
            flash('Please check in your registered email to activate your account')
            return render_template('auth/login.html') 

        return render_template('auth/register.html') #return render_template(TEMP) 
    except:
        return render_template('auth/register.html')

    
@bp.route('/confirm', methods=('GET', 'POST')) #@bp.route('/confirm', methods=?)
def confirm():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': #if request.method == ?: 
            password = request.form['password'] #password = ? 
            password1 = request.form['password1'] #password1 = ?   ???
            authid = request.form['authid']

            if not authid:
                flash('Invalid')
                return render_template('auth/forgot.html')

            if not password: #if ?:
                flash('Password required')
                return render_template('auth/change.html', number=authid)

            if not password1:
                flash('Password confirmation required')
                return render_template('auth/change.html', number=authid) #return render_template(TEMP, number=authid)

            if password1 != password: #if ? != password:   ???
                flash('Both values should be the same')
                return render_template('auth/change.html', number=authid)

            if not utils.isPasswordValid(password):
                error = 'Password should contain at least a lowercase letter, an uppercase letter and a number with 8 characters long.'
                flash(error)
                return render_template('auth/change.html', number=authid)

            db = get_db() #db = ?
            attempt = db.execute(
                'select * from forgotlink where challenge = ? AND state = ? AND CURRENT_TIMESTAMP between created and validuntil', (authid, utils.F_ACTIVE) #QUERY, (authid, utils.F_ACTIVE) / al igual que en la linea 31 debes tomar el CURRENT_TIMESTAMP y mostrar entre que variables la encuentra en la tabla forgotlink ok
            ).fetchone()
            
            if attempt is not None:
                db.execute(
                    'UPDATE forgotlink Set state = ? Where id = ?', (utils.F_INACTIVE, attempt['id']) #QUERY, (utils.F_INACTIVE, attempt['id'])
                )
                salt = hex(random.getrandbits(128))[2:]
                hashP = generate_password_hash(password + salt)   
                db.execute(
                    'UPDATE user Set password = ?, salt = ? Where id = ?', (hashP, salt, attempt['userid']) #QUERY, (hashP, salt, attempt['userid'])
                )
                db.commit()
                return redirect(url_for('auth.login'))
            else:
                flash('Invalid')
                return render_template('auth/forgot.html')

        return render_template('auth/forgot.html') #return render_template(TEMP) #error / debes redireccionar a auth/forgot ok
    except:
        return render_template('auth/forgot.html')


@bp.route('/change', methods=('GET', 'POST'))
def change():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'GET': #if request.method == ?:
            number = request.args['auth'] 
            
            db = get_db() #db = ? #error / get_db es una funcion, no olvides los parentesis ok
            attempt = db.execute(
                'select * from forgotlink where challenge = ? AND state = ? AND CURRENT_TIMESTAMP between created and validuntil', (number, utils.F_ACTIVE) #QUERY, (number, utils.F_ACTIVE) #error / al igual que en las lineas 31 y 158 debes tomar el CURRENT_TIMESTAMP y mostrar entre que variables la encuentra en la tabla forgotlink ok
            ).fetchone()
            
            if attempt is not None:
                return render_template('auth/change.html', number=number)
        
        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html') #return render_template(TEMP)


@bp.route('/forgot', methods=('GET', 'POST'))
def forgot():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))
        
        if request.method == 'POST':
            email = request.form['email'] #email = ?
            
            if ((not email) or (not utils.isEmailValid(email))): #if (? or (not utils.isEmailValid(email))):
                error = 'Email Address Invalid'
                flash(error)
                return render_template('auth/forgot.html')

            db = get_db()
            user = db.execute(
                'Select * from user Where email = ?', (email,) #QUERY, (email,)
            ).fetchone()

            if user is not None:
                number = hex(random.getrandbits(512))[2:]
                
                db.execute(
                    'Update forgotlink Set state = ? Where userid = ?', #QUERY,
                    (utils.F_INACTIVE, user['id'])
                )
                db.execute(
                    'Insert into forgotlink (userid, challenge, state) Values (?,?,?)', #QUERY,
                    (user['id'], number, utils.F_ACTIVE)
                )
                db.commit()
                
                credentials = db.execute(
                    'Select user,password from credentials where name=?',(utils.EMAIL_APP,)
                ).fetchone()
                
                content = 'Hello there, to change your password, please click on this link ' + flask.url_for('auth.change', _external=True) + '?auth=' + number
                
                send_email(credentials, receiver=email, subject='New Password', message=content)
                
                flash('Please check in your registered email')
            else:
                error = 'Email is not registered'
                flash(error)            

        return render_template('auth/forgot.html')
    except:
        return render_template('auth/forgot.html') #return render_template(TEMP)


@bp.route('/login', methods=('GET', 'POST')) #@bp.route('/login', methods=?)
def login():
    try:
        if g.user:
            return redirect(url_for('inbox.show'))

        if request.method == 'POST': #if request.method == ?:
            username = request.form['username'] #username = ?
            password = request.form['password'] #password = ?

            if not username : #if ?: #error / aqui estas diciendo si nombre de usuario en ninguno ¿¿?? / lo correcto es decir 'si no es nombre de usuario:' ok
                error = 'Username Field Required'
                flash(error)
                return render_template('auth/login.html')

            if not password : #if ?: #error / aqui estas diciendo si password en ninguno ¿¿?? / lo correcto es decir 'si no es password:' ok
                error = 'Password Field Required'
                flash(error)
                return render_template('auth/login.html') #return render_template(TEMP)

            db = get_db() #db = ?
            error = None
            user = db.execute(
                'SELECT * FROM user WHERE username = ?', (username,)
            ).fetchone()
            
            if not user or not password: #if ?: #error / aqui estas diciendo si user en ninguno ¿¿?? / lo correcto es decir 'si no es usuario o no es password:' (uso de if, not y or) ok
                error = 'Incorrect username or password'
            elif not check_password_hash(user['password'], password + user['salt']):
                error = 'Incorrect username or password'   

            if error is None:
                session.clear()
                session['user_id'] = user['id'] #session['user_id'] = user[?]
                return redirect(url_for('inbox.show'))

            flash(error)

        return render_template('auth/login.html') #return render_template(TEMP)
    except:
        return render_template('auth/login.html')
        

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id') #user_id = session.get(?)

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'Select * From User Where id = ?', (user_id,) #QUERY, (user_id,)
        ).fetchone()

        
@bp.route('/logout')
def logout():
    session.clear() #session.?
    return redirect(url_for('auth.login'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))
        return view(**kwargs)
    return wrapped_view


def send_email(credentials, receiver, subject, message):
    # Create Email
    email = EmailMessage()
    email["From"] = credentials['user']
    email["To"] = receiver
    email["Subject"] = subject
    email.set_content(message)

    # Send Email
    smtp = smtplib.SMTP("smtp-mail.outlook.com", port=587)
    smtp.starttls()
    smtp.login(credentials['user'], credentials['password'])
    smtp.sendmail(credentials['user'], receiver, email.as_string())
    smtp.quit()