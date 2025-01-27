from flask_socketio import emit
from flask_login import current_user, login_required
from threading import Lock
from .models import *
from anticheat import log_action, analyze_movement
lock = Lock()

def init_socket_events(socketio, players):
    @socketio.on('connect')
    @login_required
    def handle_connect():
        user_id = int(current_user.get_id())
        log_action(user_id, "is connecting")
        
        if user_id in players.keys():
            # Player already exists, send their current position
            emit('connected', {'user_id': user_id, 'x': players[user_id]['x'], 'y': players[user_id]['y'], 'angle': players[user_id]['angle']})
        else:
            # TODO: Check if the lobby is full and add the player to the queue
            log_action(user_id, f"is spectating")
        emit('update_bird_positions', players, broadcast=True)

    @socketio.on('move_bird')
    @login_required
    def handle_bird_movement(data):
        user_id = data.get('user_id')
        if user_id in players:
            del data['user_id']
            if players[user_id] != data:
                with lock:
                    players[user_id] = {
                        'x': data['x'],
                        'y': data['y'],
                        'color': 'black',
                        'angle': data.get('angle', 0)
                    }
                    if analyze_movement(user_id, data['x'], data['y'], data.get('angle', 0)):
                        log_action(user_id, f"was cheating with final position ({data['x']}, {data['y']}) and final angle: {data['angle']}")
                        # del players[user_id] # Remove the player from the game - we are in beta so idc
                    emit('update_bird_positions', players, broadcast=True)

    @socketio.on('disconnect')
    @login_required
    def handle_disconnect(data):
        user_id = current_user.get_id()
        if user_id in players:
            del players[user_id]
        emit('update_bird_positions', players, broadcast=True)
