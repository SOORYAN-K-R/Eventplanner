from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_login import LoginManager,login_user, logout_user
from flask_login import login_required,current_user


app = Flask(__name__)
app.secret_key = 'your_secret_key'




# DB configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///events.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

#Event Model
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    date = db.Column(db.String(10), nullable=False)
    location = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# relation to user model
    creator = db.relationship('User', backref='events')
   
    
#RSVP model
class RSVP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # "Yes", "No", or "Maybe"
    

    user = db.relationship('User', backref='rsvps')
    event = db.relationship('Event', back_populates='rsvps')

Event.rsvps = db.relationship('RSVP', order_by=RSVP.id, back_populates='event')

#USER Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password_hash = db.Column(db.String(150), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
# Create the database tables
with app.app_context():
    db.create_all()

#route to Home Page
@app.route('/')
def home():
    events = Event.query.all()
    return render_template('index.html', events=events)

# Route to create Event
@app.route('/create', methods=['GET', 'POST'])
@login_required
def create_event():
    if request.method == 'POST':
        name = request.form['name']
        date = request.form['date']
        location = request.form['location']
        description = request.form['description']

        # Create a new event with created_by field set to current_user's ID
        new_event = Event(name=name, date=date, location=location, description=description, created_by=current_user.id)
        db.session.add(new_event)
        db.session.commit()

        return redirect(url_for('home'))

    return render_template('create_event.html')

#EVENT Details

@app.route('/event/<int:event_id>')
def event_detail(event_id):
    event = Event.query.get(event_id)
    return render_template('event_detail.html', event=event)
#RSVP

@app.route('/rsvp/<int:event_id>', methods=['POST'])
@login_required
def rsvp(event_id):
    print("RSVP route accessed")  # Debugging statement
    event = Event.query.get_or_404(event_id)
    
    # Check if the user has already RSVPed
    existing_rsvp = RSVP.query.filter_by(user_id=current_user.id, event_id=event.id).first()
    if existing_rsvp:
        existing_rsvp.status = request.form['status']  # Update status if they have already RSVP'd
    else:
        # Create a new RSVP entry
        new_rsvp = RSVP(user_id=current_user.id, event_id=event.id, status=request.form['status'])
        db.session.add(new_rsvp)

    db.session.commit()
    return redirect(url_for('event_detail', event_id=event.id))


login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))



#user registeration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('home'))
    return render_template('login.html')

#Logout
@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))

from authlib.integrations.flask_client import OAuth

oauth = OAuth(app)

facebook = oauth.register(
    name='facebook',
    client_id='463347610056649',
    client_secret='2e50a00e22a44c10fee75f1d56efdbc8',
    authorize_url='https://www.facebook.com/dialog/oauth',
    authorize_params=None,
    access_token_url='https://graph.facebook.com/oauth/access_token',
    access_token_params=None,
    refresh_token_url=None,
    redirect_uri='http://localhost:5000/login/facebook/authorized',
    client_kwargs={'scope': 'email'}
)
@app.route('/')
def index():
    user = session.get('user')  # Retrieve user info from session
    return render_template('index.html', user=user)  # Pass user info to template

@app.route('/login/facebook')
def login_facebook():
    redirect_uri = url_for('facebook_authorized', _external=True)
    return facebook.authorize_redirect(redirect_uri)

@app.route('/login/facebook/authorized')
def facebook_authorized():
    token = facebook.authorize_access_token()
    resp = facebook.get('https://graph.facebook.com/me?fields=id,name,email')
    profile = resp.json()
    
    # Store user info in session
    session['user'] = profile  # You can expand this based on your needs

    # Redirect to the index page after login
    return redirect(url_for('index'))

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))  # Default to port 5000 if not provided
    app.run(host="0.0.0.0", port=port, debug=True)
