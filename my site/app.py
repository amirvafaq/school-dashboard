# app.py
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_very_secret_key_change_this'  # عوضش کن به یه چیز امن‌تر

# دیتابیس اولیه (فقط اولین بار اجرا میشه)
def init_db():
    if not os.path.exists('database.db'):
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        
        # جدول والدین/کاربران
        c.execute('''CREATE TABLE users (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     melli_code TEXT UNIQUE NOT NULL,
                     password_hash TEXT NOT NULL,
                     full_name TEXT,
                     must_change_password INTEGER DEFAULT 1
                     )''')
        
        # جدول دانش‌آموزان
        c.execute('''CREATE TABLE students (
                     id INTEGER PRIMARY KEY AUTOINCREMENT,
                     melli_code TEXT UNIQUE NOT NULL,
                     full_name TEXT NOT NULL,
                     class TEXT,
                     absences INTEGER DEFAULT 0,
                     behavior TEXT,
                     average REAL DEFAULT 0.0,
                     parent_melli TEXT
                     )''')
        
        # نمونه داده (تو می‌تونی اینا رو پاک کنی و خودت اضافه کنی)
        sample_parents = [
            ("0012345678", "علی رضایی", "0012345678123"),    # رمز = کد ملی + 123
            ("0023456789", "فاطمه محمدی", "0023456789123"),
            ("0034567890", "حسن حسینی", "0034567890123"),
            ("0045678901", "مریم احمدی", "0045678901123"),
            ("0056789012", "رضا کریمی", "0056789012123")
        ]
        
        for melli, name, raw_pass in sample_parents:
            hashed = generate_password_hash(raw_pass)
            c.execute("INSERT INTO users (melli_code, password_hash, full_name) VALUES (?, ?, ?)",
                     (melli, hashed, name))
            
            # دانش‌آموز مربوطه
            student_name = "فرزند " + name.split()[0]  # مثلاً فرزند علی
            c.execute("""INSERT INTO students 
                        (melli_code, full_name, class, absences, behavior, average, parent_melli)
                        VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (melli, f"{student_name} - کلاس پنجم", "پنجم الف", 
                         2, "عالی", 18.75, melli))
        
        conn.commit()
        conn.close()
        print("دیتابیس و نمونه داده ساخته شد!")

init_db()

# دکوراتور برای نیاز به لاگین
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        melli = request.form['melli']
        password = request.form['password']
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("SELECT id, password_hash, full_name, must_change_password FROM users WHERE melli_code = ?", (melli,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['melli'] = melli
            session['full_name'] = user[2]
            
            if user[3] == 1:  # باید رمز عوض کنه
                flash('خوش آمدید! برای امنیت بیشتر، لطفاً رمز عبور خود را تغییر دهید.', 'warning')
                return redirect(url_for('change_password'))
            
            return redirect(url_for('dashboard'))
        else:
            flash('کد ملی یا رمز عبور اشتباه است!', 'danger')
    
    return render_template('login.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_pass = request.form['new_password']
        if len(new_pass) < 4:
            flash('رمز عبور باید حداقل ۴ کاراکتر باشد!', 'danger')
        else:
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            hashed = generate_password_hash(new_pass)
            c.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE melli_code = ?",
                     (hashed, session['melli']))
            conn.commit()
            conn.close()
            flash('رمز عبور با موفقیت تغییر کرد. حالا می‌تونید وارد داشبورد بشید.', 'success')
            return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute("""SELECT full_name, class, absences, behavior, average 
                 FROM students WHERE parent_melli = ?""", (session['melli'],))
    student = c.fetchone()
    conn.close()
    
    return render_template('dashboard.html', student=student, parent_name=session['full_name'])

@app.route('/logout')
def logout():
    session.clear()
    flash('با موفقیت خارج شدید.', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)