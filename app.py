from operator import attrgetter
from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy 
from datetime import datetime
from sqlalchemy.sql import text

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
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

@app.route('/posts', methods=['GET', 'POST'])
def posts():
        if request.method == 'POST':
            post_filter_by = request.form['auth_TAN']
            all_posts = BlogPost.query.filter(text("auth_TAN={}".format("\'"+ post_filter_by +"\'"))).all()
            return render_template('posts.html', posts=all_posts)
        else:
            all_posts = BlogPost.query.order_by(BlogPost.date_posted).all()
            return render_template('posts.html', posts=all_posts)

@app.route('/posts/delete/<int:id>')
def delete(id):
    post = BlogPost.query.get_or_404(id)
    db.session.delete(post)
    db.session.commit()
    return redirect('/posts')

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
def edit(id):
    post = BlogPost.query.get_or_404(id)
    if request.method == 'POST':
        post.title = request.form['title']
        post.auth_TAN = request.form['auth_TAN']
        post.content = request.form['content']
        db.session.commit()
        return redirect('/posts')
    else:
        return render_template('edit.html', post=post)

@app.route('/posts/new', methods=['GET', 'POST'])
def new_post():
    if request.method =='POST':
        post_title = request.form['title']
        post_content = request.form['content']
        post_auth_TAN = request.form['auth_TAN']
        new_post = BlogPost(title=post_title, content=post_content, auth_TAN=post_auth_TAN)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/posts')
    else:
        return render_template("new_post.html")

#########################
# BROKEN AUTHENTICATION #
#########################

class BlogAuth(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(20), nullable=False)
    
    def __repr__(self):
        return 'Account Number ' + str(self.id)

@app.route('/auth', methods=['GET', 'POST'])
def broken_auth():
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        new_acc = BlogAuth(username=acc_username, password=acc_password)
        db.session.add(new_acc)
        db.session.commit()
        return redirect('/posts/auth')
    else:
        return render_template("broken_auth.html")    
           
#############
# DEBUGGING #
#############
if __name__ == "__main__":
	app.run(debug=True)