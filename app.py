from email.policy import default
from unicodedata import name
from flask import Flask,redirect,url_for,render_template,request, flash, get_flashed_messages
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms.validators import DataRequired,EqualTo
from wtforms import StringField, PasswordField, SubmitField
from flask_login import login_user, logout_user, login_required, login_manager,LoginManager,current_user, UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from datetime import datetime
from flask_migrate import Migrate
import os

db = SQLAlchemy()
app=Flask(__name__)

migrate = Migrate()




# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:dev123@localhost/mydb'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://gsvxyfrpfrqjjv:d304b0e6c3631b0688d36a7d1ae09ff27c8421a181efc3227afa531365c739ad@ec2-44-208-88-195.compute-1.amazonaws.com:5432/d47q469f50cdfo'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'JSHHSJHKjhjkhjk7t57765@@567!?'

db.init_app(app)
migrate.init_app(app,db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)
## MODELS
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False, unique=True)
    password = db.Column(db.String, nullable=False)
    date_created= db.Column(db.DateTime, default=datetime.utcnow)
    
    def __init__(self, name, email, password):
        self.name = name
        self.email = email
        self.password = password
        
    def __repr__(self):
        return '<User%r>' % self.name
        
with app.app_context():
    db.create_all()


## FORMS

class UserForms(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email Address', validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired()])
    password_hash_2 = PasswordField('ConfirmPassword', validators=[DataRequired(), EqualTo('password_hash', message='Both passwords must match')])
 
    submit = SubmitField('Register')
    
    
class LoginForms(FlaskForm):
    email = StringField('Email', validators=[DataRequired()])
    password_hash = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


## ROUTES
@app.route('/',methods=['GET','POST'])
def home():
    all_users = Users.query.all()
    return render_template('index.html', all_users=all_users)

@app.route('/dashboard',methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/register',methods=['GET', 'POST'] )
def register():
    name=None
    password=None
   
    form = UserForms()
    if form.password_hash.data != form.password_hash_2.data:
        flash('Passwords do not match !!')
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data,'sha256')
            new_user = Users(name=form.name.data,
                             email=form.email.data,
                             password=hashed_pw)
            
            db.session.add(new_user)
            db.session.commit()
            
            form.name.data=""
            form.email.data=""
            form.password_hash.data=""
            
            flash('User created successfully', 'succes')
            
        else:
            flash('User already existing')
    return render_template('signup.html', form=form)


@app.route('/login',methods=['GET', 'POST'] )
def login():
    form = LoginForms()
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password_hash.data):
                login_user(user)
                flash('Login Successful')
                return redirect(url_for('dashboard'))
               
            else:
                flash('Wrong Pasword, Try Again')
        else:
            flash('User does not exist')
    return render_template('login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You are logged out')
    return redirect(url_for('login'))


@app.route('/delete/<int:id>', methods=['GET', 'POST'])
def delete(id):
    user = Users.query.filter_by(id=id).first()
    if request.method == 'POST':
        if user:
            db.session.delete(user)
            db.session.commit()
            return redirect('/')     
    return render_template('delete.html')
if __name__ == '__main__':
    #DEBUG is SET to TRUE. CHANGE FOR PROD
    app.run()