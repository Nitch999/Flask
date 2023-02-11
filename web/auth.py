from flask import Blueprint, render_template, request, flash, redirect, url_for
from .model import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db   
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint('auth', __name__)

@auth.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash('connexion reussi!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Mot de pass incorrect, reesayer svp.', category='error')
        else:
            flash('l\'adresse Email n\'existe pas .', category='error')

    return render_template("log.html", user=current_user)

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))



@auth.route('/sign', methods=['GET','POST'])
def sign():
    if request.method == 'POST' :
        email =request.form.get('email')
        nom =request.form.get('nom')
        prenom =request.form.get('prenom')
        password1 =request.form.get('password1')
        password2 =request.form.get('password2')

        if len(email) < 4:
            flash('Email doit etre supperieur a 4 caractere.', category='error')
        elif len(nom) < 2:
            flash('le nom doit etre supperieur a 2 caractere.', category='error')
        elif len(prenom) < 2:
            flash('le prenom doit etre supperieur a 2 caractere.', category='error')
        elif password1 != password2:
            flash('veillez verifier le mot de pass', category='error')
        elif len(password1) < 7:
            flash('le mot de pass doit etresupperieur a 7 caractere.', category='error')
        else:
            new_user = User(email=email, nom=nom, prenom=prenom,  password=generate_password_hash(
                password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user, remember=True)
            flash('compte creer avec succes', category='success')
            return redirect(url_for('views.home'))
            
    return render_template("conn.html", user=current_user)
