from flask import Flask, redirect, render_template, url_for, flash, request, abort, jsonify
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
import secrets
import os
from PIL import Image
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Mail, Message
from googletrans import Translator
from guess_language import guess_language
import json

app = Flask(__name__, static_url_path='/static')
app.config['SECRET_KEY'] = 'you-will-never-guess'
app.config['MYSQL_HOST'] = 'localhost'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost/uvotziv'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'univerotziv@gmail.com'
app.config['MAIL_PASSWORD'] = 'Deksesha2002'
mail = Mail(app)
trans = Translator()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def translate_this_text(text):
    if guess_language(text) != 'UNKNOWN':
        print("tuta")
        newtext = trans.translate(str(text), src=guess_language(text), dest='en')
    else:
        print("tut")
        newtext = trans.translate(str(text), src='ru', dest='en')
    return newtext.text

class User(db.Model, UserMixin):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(60), nullable=False)
    posts = db.relationship('Post', backref='author', lazy=True)

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id}).decode('utf-8')

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return User.query.get(user_id)

    def __repr__(self):
         return f"User('{self.username}', '{self.email}', '{self.image_file}')"

class Post(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    univer = db.Column(db.String(20), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    language = db.Column(db.String(5), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
         return f"Post('{self.title}', '{self.date_posted}')"

class RegistrationForm(FlaskForm):
    username = StringField('Никнейм', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Адрес почты', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(max=60)])
    confirm_password = PasswordField('Подтвердить Пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегестрировать')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Этот никнейм уже занят. Пожалуйста выберите другой')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('На этот адрес уже загестрирован аккаунт.')
class UpdateAccountForm(FlaskForm):
    username = StringField('Никнейм', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Адрес почты', validators=[DataRequired(), Email()])
    picture = FileField('Обновить фотографию профиля', validators=[FileAllowed(['jpg', 'png'])])
    submit = SubmitField('Изменить')
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Этот никнейм уже занят. Пожалуйста выберите другой')
    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError('На этот адрес уже загестрирован аккаунт.')


class LoginForm(FlaskForm):
    email = StringField('Адрес почты', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')
class PostForm(FlaskForm):
    title = StringField('Заголовок', validators=[DataRequired()])
    univer = StringField('Университет(абривиатура)', validators=[DataRequired()])
    content = TextAreaField('Контент', validators=[DataRequired()])
    submit = SubmitField('Отправить')

class RequestResetForm(FlaskForm):
    email = StringField('Адрес почты', validators=[DataRequired(), Email()])
    submit = SubmitField('Сбросить пароль')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is None:
            raise ValidationError('Аккаунта с таким адресом не существует')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Пароль', validators=[DataRequired(), Length(max=60)])
    confirm_password = PasswordField('Подтвердить Пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Сбросить пароль')

@app.route("/home")
@app.route("/")
def home():
    page = request.args.get('page', 1, type=int)
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(page=page, per_page=5)
    smalltext = {}
    for post in posts.items:
        if len(post.content) > 200:
            smalltext[post.id] = str(post.content[:200]) + '...'
        else:
            smalltext[post.id] = post.content
    return render_template("home.html", posts=posts, smalltext=smalltext)

@app.route("/about")
def about():
    return render_template("about.html", title='About')



@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Аккаунт был создан! Теперь вы можете войти!", "danger")
        return redirect(url_for('login'))
    return render_template("register.html", title='Sing Up', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Войти не удалось. Проверите адрес и пароль.', 'danger')
    return render_template("login.html", title='Sing In', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/images', picture_fn)
    output_size = (300, 300)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    return picture_fn

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Ваш аккаунт был обновлен!', 'danger')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image = url_for('static', filename='images/' + current_user.image_file)
    return render_template("account.html", title='Account', me=current_user, image=image, form=form)


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        if guess_language(form.content.data) != 'UNKNOWN':
            post = Post(title=form.title.data, univer=form.univer.data, content=form.content.data, author=current_user, language=guess_language(form.content.data))
        else:
            post = Post(title=form.title.data, univer=form.univer.data, content=form.content.data, author=current_user,
                        language='ru')
        db.session.add(post)
        db.session.commit()
        flash('Новый отзыв опубликован!', 'danger')
        return redirect(url_for('home'))
    return render_template("create_post.html", title='New Post', form=form)

@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def post(post_id):
    post = Post.query.get_or_404(post_id)
    form = PostForm()
    if form.validate_on_submit():
        post.title = form.title.data
        post.univer = form.univer.data
        post.content = form.content.data
        if guess_language(form.content.data) != 'UNKNOWN':
            post.language = guess_language(form.content.data)
        else:
            post.language = 'ru'
        db.session.commit()
        flash('Ваш отзыв был обновлен', 'danger')
        return redirect(url_for('home'))
    elif request.method == 'GET':
        form.title.data = post.title
        form.univer.data = post.univer
        form.content.data = post.content
    return render_template('post.html', title=post.title, post=post, form=form)
@app.route("/post/<int:post_id>/delete", methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    db.session.delete(post)
    db.session.commit()
    flash('Ваш отзыв был удален', 'danger')
    return redirect(url_for('home'))

@app.route("/user/<username>", methods=['GET', 'POST'])
def user(username):
    user = User.query.filter_by(username=username).first()
    if user == current_user:
        return redirect(url_for('account'))
    image = url_for('static', filename='images/' + user.image_file)
    return render_template('user.html', user=user, image=image)

def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Password Reset Request', sender='noreply@demo.com', recipients=[user.email])
    msg.body = f'''Что бы сбросить пароль, перейдите по следующей ссылке:
{url_for('reset_token', token=token, _external=True)}

Если вы не делали этот запрос, просто игнорируйте это письмо.
    '''
    mail.send(msg)

@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(user)
        flash('На ваш ардес было отправлено письмо для смены пароля', 'danger')
        return redirect(url_for('login'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = User.verify_reset_token(token)
    if not user:
        flash('Неверный токен', 'danger')
        return redirect(url_for('reset_request'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user.password = hashed_password
        db.session.commit()
        flash("Ваш пароль был обновлен!", "danger")
        return redirect(url_for('login'))
    return render_template('reset_token.html', title='Reset Password', form=form)

@app.route("/translate", methods=["POST"])
def translate():
    t = request.form['text']
    return jsonify({'text': translate_this_text(t)})

if (__name__ == '__main__'):
    app.run(debug=True)