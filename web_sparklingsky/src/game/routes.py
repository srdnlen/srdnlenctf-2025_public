from flask import render_template, redirect, url_for, request, flash
from flask_login import login_user, logout_user, login_required, current_user
from . import bp
from .models import *
from app import login_manager
from .utils import *
from random import randint

@login_manager.user_loader
def load_user(user_id):
    user = User.query.get(int(user_id))
    return user

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')


@bp.route('/')
@login_required
def home():
    return render_template('home.html')


@bp.route('/play')
@login_required
def play():
    current_players = User.query.filter_by(is_playing=True).with_entities(User.id).all()
    current_players = [user_id[0] for user_id in current_players]
    userID = int(current_user.get_id())
    if userID in current_players:
        return render_template('play.html')
    else:
        return render_template("spectate.html", position=randint(1, 300))
    

@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter(User.username == username).first()
        if user is None:
            return redirect(url_for('game.login'))
        if user.password == password:
            login_user(user)
            return redirect(url_for('game.home'))
        
        return redirect(url_for('game.login'))
    
    return render_template('login.html')

@bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!')
    return redirect(url_for('game.login'))
