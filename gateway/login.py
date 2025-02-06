from app import app
from flask import render_template, request, redirect, url_for, session, flash
import utils.globals as globals
from utils.globals import *
from utils.tools import *
from werkzeug.security import check_password_hash, generate_password_hash
from gateway.index import *
import uuid


# 登录页面
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = next((user for user in globals.users if user['username'] == username), None)
        
        if user and check_password_hash(user['password'], password):
            # 登录成功，存储用户信息到session
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            # 如果是管理员，跳转到管理页面，否则跳转到ChatGPT共享页面
            if user['role'] == 'admin':
                return redirect(url_for('chatgpt'))
            else: 
                logurl = getoauth(session.get('user_id'))
                session.clear()
                return redirect(logurl)
        else:
            flash('用户名或密码错误，请重试。', 'error')
            
    return render_template('login.html')

# 登出路由
@app.route('/logout')
def logout():
    session.clear()
    flash('已成功登出。', 'success')
    return redirect(url_for('login'))

# 注册用户
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        
        # 检查用户名是否已存在
        if any(user['username'] == username for user in globals.users):
            flash('用户名已存在。', 'error')
        
        new_user = {
            'id': str(uuid.uuid4()),
            'username': username,
            'password': generate_password_hash(password),
            'role': 'user',
            'bind_token': '',
            'bind_email': '',
            'expiration_time': '',
            'bind_claude_token': '',
            'bind_claude_email': '',
            'claude_expiration_time': ''
        }
        
        globals.users.append(new_user)
        save_users(globals.users)
        return redirect(url_for('login'))
            
    return render_template('register.html')