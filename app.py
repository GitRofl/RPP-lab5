from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)


# Формат: Подключаемся к БД
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost/flask_lab_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Отключаем отслеживание изменений объектов для оптимизации
app.config['SECRET_KEY'] = os.urandom(24)  #Делаем секретный код полностью рандомным

# Инициализируем расширения 
db = SQLAlchemy(app)  
login_manager = LoginManager(app) 
login_manager.login_view = 'login'    

# Модель пользователя, которая будет хранить информацию о пользователях в базе данных
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  
    email = db.Column(db.String(120), unique=True, nullable=False)  
    password = db.Column(db.String(200), nullable=False)  # Зашифрованный пароль
    name = db.Column(db.String(100), nullable=False) 

login_manager.login_view = 'login'  # Страница входа, на которую будет перенаправляться пользователь
login_manager.login_message = 'Пожалуйста, войдите в аккаунт, чтобы получить доступ к этой странице'  

# Функция для загрузки пользователя по его ID 
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))  # Поиск пользователя в базе данных по ID

# Главная страница
@app.route('/')
@login_required  # Ожидаем, что пользователь будет авторизован, прежде чем дать доступ
def index():
    return render_template('index.html', user=current_user)  # Отображаем шаблон index.html с текущим пользователем

# Страница входа 
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':  # Если запрос метода POST 
        email = request.form['email']  
        password = request.form['password']  #
        user = User.query.filter_by(email=email).first()  # Ищем пользователя по email в базе данных
        
        if user is None:  
            flash('Такого пользователя у нас не обнаружено)', 'error')  
        elif not check_password_hash(user.password, password):  
            flash('Неправильный пароль', 'error')  
        else:
            login_user(user)  # Если данные верны, авторизуем пользователя
            return redirect(url_for('index'))  

    return render_template('login.html')  # Если запрос GET, показываем страницу входа

# Страница регистрации нового пользователя
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':  # Если форма была отправлена
        name = request.form['name']  
        email = request.form['email']  # 
        password = request.form['password']  # 
        
        user = User.query.filter_by(email=email).first()  # Проверяем, существует ли уже пользователь с таким email
        if user:
            flash('Такой пользователь уже существует', 'error')  #
        else:
            # Если такого пользователя нет, создаем нового
            new_user = User(name=name, email=email, password=generate_password_hash(password))  # Хешируем пароль перед сохранением
            db.session.add(new_user)  #
            db.session.commit()  #
            flash('Аккаунт успешно зарегестрирован :), теперь нужно войти', 'success')  
            return redirect(url_for('login'))  

    return render_template('signup.html')  # Если запрос GET, показываем страницу регистрации

# Страница выхода (разлогинивание)
@app.route('/logout')
@login_required  # Доступна только для авторизованных пользователей
def logout():
    logout_user()  
    return redirect(url_for('login'))  

# Главная точка запуска приложения
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создаем все таблицы в базе данных, если они еще не созданы
    app.run(debug=True)  # Запускаем сервер Flask в режиме отладки
