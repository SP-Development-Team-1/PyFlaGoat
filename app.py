from operator import attrgetter
from flask import Flask, render_template, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.sql import text
import tkinter as tk
import random

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/default.db'
app.config['SQLALCHEMY_BINDS'] = {
    'injection': 'sqlite:///database/injection.db',
    'broken_access': 'sqlite:///database/broken_access.db'
}
app.config['SECRET_KEY'] = 'FASOO'
db = SQLAlchemy(app)
db.create_all()
db.session.commit()

########
# HOME #
########

@app.route('/')
def index():
        return render_template('index.html')

#################
# SQL INJECTION #
#################

class BlogPost(db.Model):
    __bind_key__ = 'injection'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    content = db.Column(db.Text, nullable=False)
    auth_TAN = db.Column(db.String(20), nullable=False, default='N/A')
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return 'Blog Post ' + str(self.id)

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
        username_exists = len(BlogAuth.query.filter_by(username=acc_username).all())
        if username_exists:
            flash("Registration Failed! Username is already in use.")
            return render_template("flash.html")
        acc_password = request.form['password']
        new_acc = BlogAuth(username=acc_username, password=acc_password)
        db.session.add(new_acc)
        db.session.commit()
        return redirect('/auth')
    else:
        return render_template("broken_auth/register.html")

###########################
# SENSITIVE DATA EXPOSURE #
###########################

class SensitiveUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(20), nullable=False)

def sensitive_popupmsg(msg, title):
    """Generate a pop-up window for special messages."""
    root = tk.Tk()
    root.title(title)
    label = tk.Label(root, text=msg)
    label.pack(side="top", fill="x", pady=10)
    B1 = tk.Button(root, text="Okay", command = root.destroy)
    B1.pack()
    #popupmsg.mainloop()
        
@app.route('/sensitive_data', methods=['GET', 'POST'])
def sensitive_data():
    flag = 0
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        username = SensitiveUsers.query.filter_by(username=acc_username).first()
        password = SensitiveUsers.query.filter_by(password=acc_password).first()
        
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
        return render_template("sensitive_data/sensitive_data.html")    

@app.route('/sensitive_data/register', methods=['GET', 'POST'])
def sensitive_register():
    if request.method == 'POST':
        acc_username = request.form['username']
        username_exists = len(SensitiveUsers.query.filter_by(username=acc_username).all())
        if username_exists:
            flash("Registration Failed! Username is already in use.")
            return render_template("flash.html")
        acc_password = request.form['password']
        new_acc = SensitiveUsers(username=acc_username, password=acc_password)
        db.session.add(new_acc)
        db.session.commit()
        return redirect('/sensitive_data')
    else:
        return render_template("sensitive_data/register.html")

##############################
# XML EXTERNAL ENTITY ATTACK #
##############################

class XXE(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    comment = db.Column(db.String(255), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return 'Comment ' + str(self.id)
    
@app.route('/xxe', methods=['GET', 'POST'])
def xxe():
    if request.method == 'POST':
        user_name = request.form['author']
        user_comment = request.form['comment']
        new_comment = XXE(author=user_name, comment=user_comment)
        db.session.add(new_comment)
        db.session.commit()
        return redirect('/xxe')
    else:
        all_comments = XXE.query.order_by(XXE.date_posted).all()
        return render_template("xxe/xxe.html", comments=all_comments)

@app.route('/xxe/delete/<int:id>')
def delete_comment(id):
    comment = XXE.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    return redirect('/xxe')

##############################
      # CLIENT SIDE #
##############################

@app.route('/client/front-end/', methods=['GET', 'POST'])
def frontend():
    if request.method == 'POST':
        select_field = request.form['company']
        radio_button = request.form['drone']
        checkbox = request.form['check']
        input_5 = request.form['comment']
        random_input = request.form['readonly']
        return redirect('/client/front-end')
    else:
        return render_template("client_side/frontend.html")
        
#########################
# BROKEN ACCESS CONTROL #
#########################
class DirectObj(db.Model):
    __bind_key__ = 'broken_access'
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    name = db.Column(db.String(50), nullable=False)
    occupation = db.Column(db.String(50), nullable=False)

@app.route('/broken_access', methods=['GET', 'POST'])
def broken_access():
    return redirect('/broken_access/profile/0')

@app.route('/broken_access/profile/<int:id>', methods=['GET', 'POST'])
def profile_view(id):
    if id == 0 and not len(DirectObj.query.filter_by(id=0).all()):
        sentinel = DirectObj(id=0, username="WebGoat", password="password", name = "Chief WebGoat", occupation = "Administrator of WebGoat")
        db.session.add(sentinel)
        db.session.commit()
    return render_template("broken_access/broken_access.html", user = DirectObj.query.get(id))

@app.route('/broken_access/profile/<int:id>/edit', methods=['GET', 'POST'])
def profile_edit(id):
    to_edit = DirectObj.query.get_or_404(id)
    if request.method == 'POST':
        to_edit.username = request.form['username']
        to_edit.name = request.form['name']
        to_edit.occupation = request.form['occupation']
        to_edit.password = request.form['password']
        db.session.commit()
        return redirect('/broken_access/profile/' + str(id))
    else:
        return render_template('broken_access/edit.html', profile=to_edit)

@app.route('/broken_access/new', methods=['GET', 'POST'])
def create_user():
    if request.method == 'POST':
        acc_username = request.form['username']
        username_exists = len(DirectObj.query.filter_by(username=acc_username).all())
        if username_exists:
            flash("Creation Failed! Username is already in use.")
            return render_template("flash.html")
        acc_password = request.form['password']
        acc_id = random.randint(1, 9999999999)
        while len(DirectObj.query.filter_by(id=acc_id).all()):
            acc_id = random.randint(1, 9999999999)
        acc_name = request.form['name']
        acc_occupation = request.form['occupation']
        new_acc = DirectObj(id=acc_id, username=acc_username, password=acc_password, name=acc_name, occupation=acc_occupation)
        db.session.add(new_acc)
        db.session.commit()
        return redirect('/broken_access/profile/' + str(acc_id))
    else:
        return render_template("broken_access/new.html")

#############
# DEBUGGING #
#############
if __name__ == "__main__":
	app.run(debug=True)

