from flask import Flask
from flask_socketio import SocketIO
from flask_login import LoginManager
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

socketio = SocketIO()
login_manager = LoginManager()
db = SQLAlchemy()
def create_app():

    app = Flask(__name__)
    app.config.from_object('config.Config')

    socketio.init_app(app, cors_allowed_origins="*")
    login_manager.init_app(app)
    db.init_app(app)

    from game.models import User
    with app.app_context():
        db.create_all()

    from game.utils import init_db
    # Prepopulate the db
    with app.app_context():
        init_db()

    from game.routes import bp as game_bp
    app.register_blueprint(game_bp)

    # Import the socket events after the app is created
    from game.socket import init_socket_events
    from game.utils import update_birds_from_db
    with app.app_context():
        players = update_birds_from_db()
    init_socket_events(socketio, players)

    return app
