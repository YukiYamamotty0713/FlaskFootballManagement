from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Blueprint, render_template, redirect, url_for, request, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask import render_template
from flask import Flask
from datetime import datetime


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#データベースのカラム
db = SQLAlchemy(app)

#マイグレーションの設定
migrate = Migrate(app, db)

#クラス定義
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    post_time = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    def __repr__(self):
        return f"Comment('{self.comment}', '{self.post_time}')"

#ユーザー新規登録
@app.route('/signup', methods=['GET'])
def signup():
    return render_template('signup.html')

@app.route('/signup',methods=['POST'])
def post_signup():
    username = request.form.get('username')
    email = request.form.get('mail')
    password = request.form.get('password')
    
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        flash('Username or email already exists. Please choose a different one.', 'danger')
        return redirect(url_for('signup'))
    new_user = User(username=username, email=email)
    new_user.set_password(password)
    db.session.add(new_user)
    db.session.commit()
    flash('Account created successfully. You can now log in.', 'success')
    return redirect(url_for('login'))

#ログイン処理
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            flash('Login successful', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    #GETメソッドの場合
    return render_template('login.html')

#ログアウト処理
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

#メインページ
@app.route('/',methods=['GET'])
@login_required
def index():
    return render_template('index.html',current_user = current_user)


#api部分
@app.route('/api/data',methods=['GET'])
@login_required
def fetch_data():
    data = Comment.query.filter_by(user_id=current_user.id).all()
    comments_list = [
        {
            'id': comment.id,
            'title': comment.title,
            'comment': comment.comment,
            'post_time':  comment.post_time.strftime("%Y-%m-%d %H:%M:%S"),
            'user_id': comment.user_id
        }
        for comment in data
    ]

    return jsonify(comments_list)


@app.route('/api/data',methods=['POST'])
@login_required
def post_data():
    if request.method == 'POST':
        title_text = request.form.get('title')
        comment_text = request.form.get('comment')  # HTMLフォームのコメントテキストを取得

        if comment_text:
            new_comment = Comment(
                title=title_text,
                comment=comment_text,
                user_id=current_user.id,
                post_time=datetime.utcnow()  # 現在のUTC時刻を使用（適宜変更）
            )

            db.session.add(new_comment)
            db.session.commit()

            return jsonify({'message': 'Comment added successfully'})

    return jsonify({'message': 'Invalid request'})

if __name__ == '__main__':
    app.run(debug =True)