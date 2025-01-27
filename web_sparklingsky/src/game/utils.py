from .models import db, User
import secrets
import string
from uuid import uuid4 as userID

def init_db():
    if User.query.first() is None:
        for i in range(10):
            username = 'user' + str(userID())
            password = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(16))
            user = User(username=username, password=password, color=secrets.choice(['black', 'blue', 'white', 'green', 'red', 'grey', 'yellow', 'cyan', 'orange', 'pink']), is_playing=True)
            db.session.add(user)
            db.session.commit()
        user = User(username='user1337', password='user1337', color=secrets.choice(['black', 'blue', 'white', 'green', 'red', 'grey', 'yellow', 'cyan', 'orange', 'pink']))
        db.session.add(user)
        db.session.commit()

def get_players():
    current_players = User.query.filter_by(is_playing=True).with_entities(User.id).all()
    current_players = [user_id[0] for user_id in current_players]
    return current_players

from random import randint, uniform

def update_birds_from_db():
    players = {}
    current_players = get_players()
    for user_id in current_players:
        players[user_id] = {
            'x': randint(0,500),
            'y': randint(0,500),
            'color': 'black', # TODO: implement color from db
            'angle': uniform(0,6)
        }
    return players
