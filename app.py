from operator import attrgetter
from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime
from sqlalchemy.sql import text
import tkinter as tk

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
app.config['SECRET_KEY'] = "Fasoo"
db = SQLAlchemy(app)

#################
# SQL INJECTION #
#################

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    auth_TAN = db.Column(db.String(20), nullable=False, default='N/A')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return 'Blog Post ' + str(self.id)

@app.route('/')
def index():
        return render_template('index.html')

@app.route('/sql_injection', methods=['GET', 'POST'])
def posts():
        if request.method == 'POST':
            post_filter_by = request.form['auth_TAN']
            all_posts = BlogPost.query.filter(text("auth_TAN={}".format("\'"+ post_filter_by +"\'"))).all()
            return render_template('sql_injection/posts.html', posts=all_posts)
        else:
            all_posts = BlogPost.query.order_by(BlogPost.date_posted).all()
            return render_template('sql_injection/posts.html', posts=all_posts)

@app.route('/sql_injection/delete/<int:id>')
def delete(id):
    post = BlogPost.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    return redirect('/sql_injection')

@app.route('/sql_injection/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    post = BlogPost.query.get_or_404(id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.auth_TAN = request.form['auth_TAN']
        post.content = request.form['content']
        db.session.commit()
        return redirect('/sql_injection')
    else:
        return render_template('sql_injection/edit.html', post=post)

@app.route('/sql_injection/new', methods=['GET', 'POST'])
def new_post():
    if request.method =='POST':
        post_title = request.form['title']
        post_content = request.form['content']
        post_auth_TAN = request.form['auth_TAN']
        new_post = BlogPost(title=post_title, content=post_content, auth_TAN=post_auth_TAN)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/sql_injection')
    else:
        return render_template("sql_injection/new_post.html")

#########################
# BROKEN AUTHENTICATION #
#########################

class BlogAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(20), nullable=False)

def popupmsg(msg, title):
    """Generate a pop-up window for special messages."""
    root = tk.Tk()
    root.title(title)
    label = tk.Label(root, text=msg)
    label.pack(side="top", fill="x", pady=10)
    B1 = tk.Button(root, text="Okay", command = root.destroy)
    B1.pack()
    #popupmsg.mainloop()
        
@app.route('/auth', methods=['GET', 'POST'])
def broken_auth():
    flag = 0
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        username = BlogAuth.query.filter_by(username=acc_username).first()
        password = BlogAuth.query.filter_by(password=acc_password).first()
        
        if username and password:
            flash("Login Success!")
            return render_template("flash.html")
        elif username and not password:
            flash("Login Failed, Please enter a valid password!")
            return render_template("flash.html")
        elif not username and password:
            flash("Login Failed!, Please register before logging in!")
            return render_template("flash.html")
        else:
            flash("Login Failed!, Please register before logging in!")
            return render_template("flash.html")
    else:
        return render_template("broken_auth/broken_auth.html")    

@app.route('/auth/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        new_acc = BlogAuth(username=acc_username, password=acc_password)
        db.session.add(new_acc)
        db.session.commit()
        return redirect('/broken_auth/broken_auth.html')
    else:
        return render_template("/broken_auth/register.html")
        
#############
# DEBUGGING #
#############
if __name__ == "__main__":
	app.run(debug=True)