from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for, current_app, send_file
)

from app.auth import login_required
from app.db import get_db

bp = Blueprint('inbox', __name__, url_prefix='/inbox')

@bp.route("/getDB")
@login_required
def getDB():
    return send_file(current_app.config['DATABASE'], as_attachment=True)


@bp.route('/show')
@login_required
def show():
    db = get_db() #db = ?
    userId = g.user['id'] #Aqui te creé esta variable por que si no aparece un error en el  Query de la linea 22 ok
    messages = db.execute(
        'SELECT * FROM message WHERE from_id = ? OR to_id = ?', (userId, userId) #QUERY, # en este query debes decirle: seleccione todos los campos de message donde from_id o to_id, (userId,UserId)
    ).fetchall()

    return render_template('inbox/show.html', messages=messages) #return render_template(TEMP, messages=messages) / debes direccionar a inbox/show.html


@bp.route('/send', methods=('GET', 'POST'))
@login_required
def send():
    if request.method == 'POST':        
        from_id = g.user['id']
        to_username = request.form['to'] #to_username = ? / en el formulario se llama ['to'] ok
        subject = request.form['subject'] #subject = ?
        body = request.form['body'] #body = ?

        db = get_db() #db = ?
       
        if not to_username:
            flash('To field is required')
            return render_template('inbox/send.html') #return render_template(TEMP) / debes direccionar a inbox/send ok
        
        if not subject: #if ?:
            flash('Subject field is required')
            return render_template('inbox/send.html')
        
        if not body: #if ?:
            flash('Body field is required')
            return render_template('inbox/send.html') #return render_template(TEMP) / debes direccionar a inbox/send ok
        
        error = None    
        userto = None 
        
        userto = db.execute(
            'SELECT * FROM user WHERE username = ?', (to_username) #QUERY, (to_username,) / la sentencia es: selecciones todos los campos de user donde username = ? ok
        ).fetchone()
        
        if userto is None:
            error = 'Recipient does not exist'
     
        if error is not None:
            flash(error)
        else:
            db = get_db() #db = ? # get_db es funcion no olvides los parentesis ok
            db.execute(
                'Insert INTO message (from_id, to_id, subject, body) VALUES (?, ?, ?,?)', # QUERY, / la sentencia es: inserte dentro de message (from_id, to_id, subject, body) values (?,?,?,?)
                (g.user['id'], userto['id'], subject, body)
            )
            db.commit()

            return redirect(url_for('inbox.show'))

    return render_template('inbox/send.html')