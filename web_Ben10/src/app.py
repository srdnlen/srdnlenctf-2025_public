import secrets
import sqlite3
import os
from flask import Flask, render_template, request, redirect, url_for, flash, session

app = Flask(__name__)
app.secret_key = 'your_secret_key'

DATABASE = 'database.db'
FLAG = os.getenv('FLAG', 'srdnlen{TESTFLAG}')


def init_db():
    """Initialize the SQLite database."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT,
                        admin_username TEXT,
                        reset_token TEXT
                      )''')
    conn.commit()
    conn.close()


def get_user_by_username(username):
    """Helper function to fetch user by username."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user


def get_reset_token_for_user(username):
    """Helper function to fetch reset token for a user."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("SELECT reset_token FROM users WHERE username = ?", (username,))
    token = cursor.fetchone()
    conn.close()
    return token


def update_reset_token(username, reset_token):
    """Helper function to update reset token."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET reset_token = ? WHERE username = ?", (reset_token, username))
    conn.commit()
    conn.close()


def update_password(username, new_password):
    """Helper function to update the password."""
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ?, reset_token = NULL WHERE username = ?", (new_password, username))
    conn.commit()
    conn.close()


@app.route('/')
def index():
    """Redirect to /home if user is logged in, otherwise to /login."""
    if 'username' in session:
        return redirect(url_for('home'))
    return redirect(url_for('login'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Handle user registration."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if username.startswith('admin') or '^' in username:
            flash("I don't like admins", "error")
            return render_template('register.html')

        if not username or not password:
            flash("Both fields are required.", "error")
            return render_template('register.html')

        admin_username = f"admin^{username}^{secrets.token_hex(5)}"
        admin_password = secrets.token_hex(8)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",
                           (username, password, admin_username))
            cursor.execute("INSERT INTO users (username, password, admin_username) VALUES (?, ?, ?)",
                           (admin_username, admin_password, None))
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists!", "error")
            return render_template('register.html')
        finally:
            conn.close()

        flash("Registration successful!", "success")
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = get_user_by_username(username)

        if user and user[2] == password:
            session['username'] = username
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password.", "error")

    return render_template('login.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    """Handle reset password request."""
    if request.method == 'POST':
        username = request.form['username']

        if username.startswith('admin'):
            flash("Admin users cannot request a reset token.", "error")
            return render_template('reset_password.html')

        if not get_user_by_username(username):
            flash("Username not found.", "error")
            return render_template('reset_password.html')

        reset_token = secrets.token_urlsafe(16)
        update_reset_token(username, reset_token)

        flash("Reset token generated!", "success")
        return render_template('reset_password.html', reset_token=reset_token)

    return render_template('reset_password.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Handle password reset."""
    if request.method == 'POST':
        username = request.form['username']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('forgot_password.html', reset_token=reset_token)

        user = get_user_by_username(username)
        if not user:
            flash("User not found.", "error")
            return render_template('forgot_password.html', reset_token=reset_token)

        if not username.startswith('admin'):
            token = get_reset_token_for_user(username)
            if token and token[0] == reset_token:
                update_password(username, new_password)
                flash(f"Password reset successfully.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid reset token for user.", "error")
        else:
            username = username.split('^')[1]
            token = get_reset_token_for_user(username)
            if token and token[0] == reset_token:
                update_password(request.form['username'], new_password)
                flash(f"Password reset successfully.", "success")
                return redirect(url_for('login'))
            else:
                flash("Invalid reset token for user.", "error")

    return render_template('forgot_password.html', reset_token=request.args.get('token'))


@app.route('/home')
def home():
    """Display home page with images."""
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    user = get_user_by_username(username)
    admin_username = user[3] if user else None

    image_names = ['ben1', 'ben2', 'ben3', 'ben4', 'ben5', 'ben6', 'ben7', 'ben8', 'ben9', 'ben10']
    return render_template('home.html', username=username, admin_username=admin_username, image_names=image_names)


@app.route('/image/<image_id>')
def image(image_id):
    """Display the image if user is admin or redirect with missing permissions."""
    if 'username' not in session:
        return redirect(url_for('login'))

    username = session['username']

    if image_id == 'ben10' and not username.startswith('admin'):
        return redirect(url_for('missing_permissions'))

    flag = None
    if username.startswith('admin') and image_id == 'ben10':
        flag = FLAG

    return render_template('image_viewer.html', image_name=image_id, flag=flag)


@app.route('/missing_permissions')
def missing_permissions():
    """Show a message when the user tries to access a restricted image."""
    return render_template('missing_permissions.html')


@app.route('/logout')
def logout():
    """Log the user out and clear the session."""
    session.clear()
    flash("You have been logged out successfully.", "success")
    return redirect(url_for('login'))


if __name__ == '__main__':
    if not os.path.exists(DATABASE):
        init_db()
    app.run(debug=True)
