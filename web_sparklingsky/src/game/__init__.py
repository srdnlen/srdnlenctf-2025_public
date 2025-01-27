from flask import Blueprint

bp = Blueprint('game', __name__)

from . import routes, socket  # Import routes and socket modules
