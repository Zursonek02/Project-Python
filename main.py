from flask import Flask, render_template, redirect, url_for, request, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'iuafhiufsdghaweioug'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///work_journal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Database models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class WorkEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.String(150), nullable=False)

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user.is_admin:
            entries = WorkEntry.query.all()
        else:
            entries = WorkEntry.query.filter_by(created_by=user.username).all()
        return render_template('dashboard.html', user=user, entries=entries)
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        hashed_password = generate_password_hash(password, method='sha256')

        new_user = User(username=username, password=hashed_password, is_admin=is_admin)
        db.session.add(new_user)
        db.session.commit()

        flash('User registered successfully!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/add_entry', methods=['GET', 'POST'])
def add_entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']

        new_entry = WorkEntry(title=title, description=description, created_by=user.username)
        db.session.add(new_entry)
        db.session.commit()

        flash('Work entry added successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('add_entry.html')

@app.route('/edit_entry/<int:entry_id>', methods=['GET', 'POST'])
def edit_entry(entry_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    entry = WorkEntry.query.get(entry_id)
    if not entry or (not user.is_admin and entry.created_by != user.username):
        flash('Access denied!', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        entry.title = request.form['title']
        entry.description = request.form['description']
        db.session.commit()
        flash('Work entry updated successfully!', 'success')
        return redirect(url_for('home'))
    return render_template('edit_entry.html', entry=entry)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
