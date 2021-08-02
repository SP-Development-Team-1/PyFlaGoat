from flask import Flask, Markup, render_template, request, redirect, flash, make_response, session, g, Response, abort
from flask.helpers import url_for
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from sqlalchemy.sql import text
from loguru import logger
from io import StringIO
from flask_wtf.csrf import CSRFProtect
import subprocess
import random
import zipfile
import os
import pickle
import base64
import time
import urllib.parse

app = Flask(__name__)
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database/default.db'
app.config['SQLALCHEMY_BINDS'] = {
    'injection': 'sqlite:///database/injection.db',
    'broken_access': 'sqlite:///database/broken_access.db'
}
app.config['SECRET_KEY'] = 'FASOOINCSPARROWCOLTD'

db = SQLAlchemy(app)
db.create_all()
db.session.commit()

CSRFProtect(app)

########
# HOME #
########

@app.route('/')
def index():
        return render_template('index.html')

##########
# LOG IN #
##########

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(20), nullable=False)

    def __repr__(self):
        return self.username

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user = [x for x in User.query.all() if x.id == session['user_id']][0]
        g.user = user
    
    g.safe_mode_on = False
    if 'safe_mode_on' in session:
        g.safe_mode_on = session['safe_mode_on'] 

    app.config['WTF_CSRF_ENABLED'] = False 

@app.route('/login',  methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.pop('user_id', None)

        acc_username = request.form['username']
        acc_password = request.form['password']
        
        user = User.query.filter_by(username=acc_username).first()

        if user and user.password == acc_password:
            session['user_id'] = user.id
            return redirect("/")
        else:
            flash("Your username does not exist, or your password is incorrect. Try again.")
            return render_template("flash.html")
    else:
        return render_template('login.html', fail=False)

@app.route('/logout')
def logout():
    if g.user:
        session.pop('user_id', None)
    return redirect("/")

@app.route('/register', methods=['GET', 'POST'])
def register_user():
    if request.method == 'POST':
        acc_username = request.form['username']
        username_exists = len(User.query.filter_by(username=acc_username).all())
        if username_exists:
            flash("Registration Failed! Username is already in use.")
            return render_template("flash.html")
        acc_password = request.form['password']
        acc_name = request.form['name']
        new_acc = User(username=acc_username, password=acc_password, name=acc_name)
        db.session.add(new_acc)
        db.session.commit()
        session.pop('user_id', None)
        session['user_id'] = new_acc.id
        return redirect('/')
    else:
        return render_template("register.html")

######################
# TOGGLE SECURE MODE #
######################

@app.route('/togglemode', methods=['GET', 'POST'])
def togglemode():
    new_mode = not session.pop('safe_mode_on', False)
    session['safe_mode_on'] = new_mode
    return redirect_back()

def redirect_back(default='hello', **kwargs):
    for target in request.args.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return redirect(target)
    return redirect(url_for(default, **kwargs))
 
def is_safe_url(target):
    ref_url = urllib.parse.urlparse(request.host_url)
    test_url = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc


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

@app.route('/sql_injection-intro', methods=['GET', "POST"])
def sql_injection_intro():
    return render_template('sql_injection/intro.html')

@app.route('/sql_injection', methods=['GET', 'POST'])
def posts():
        if request.method == 'POST':
            post_filter_by = request.form['auth_TAN']
            if g.safe_mode_on:
                all_posts = BlogPost.query.filter_by(auth_TAN=post_filter_by).all()
            else:
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

@app.route('/auth-intro', methods=['GET', "POST"])
def auth_intro():
    return render_template('broken_auth/intro.html')
        
@app.route('/auth', methods=['GET', 'POST'])
def broken_auth():
    flag = 0
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        username = BlogAuth.query.filter_by(username=acc_username).first()
        password = False
        if username:
            password = username.password == acc_password
        if username and password:
            flash("Login Success!")
            return render_template(flash.html)
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

@app.route('/sensitive_data-intro', methods=['GET', "POST"])
def sensitive_data_intro():
    return render_template('sensitive_data/intro.html')

@app.route('/sensitive_data', methods=['GET', 'POST'])
def sensitive_data():
    flag = 0
    if request.method == 'POST':
        acc_username = request.form['username']
        acc_password = request.form['password']
        username = SensitiveUsers.query.filter_by(username=acc_username).first()
        password = False
        if username:
            password = username.password == acc_password
        
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
    comment = db.Column(db.String(500), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return 'Comment ' + str(self.id)
    
@app.route('/xxe-intro', methods=['GET', "POST"])
def xxe_intro():
    return render_template('xxe/intro.html')
    
@app.route('/xxe', methods=['GET', 'POST'])
def xxe():
    path = ""
    xml = '''<?xml version='1.0'?><!DOCTYPE comment [<!ENTITY xxe SYSTEM "/app">]><comment><text>&xxe;</text></comment>'''
    flag = 0
    if request.method == 'POST':
        user_name = request.form['author']
        user_comment = request.form['comment']
        if not g.safe_mode_on:
            if "<?xml version='1.0'?>" in user_comment:
                for elem in user_comment:
                    if elem == '"':
                        flag += 1
                    elif flag == 1:
                        path += elem
                    elif flag == 2:
                        break   
                all_files = str(os.listdir(path))
                new_comment = XXE(author=user_name, comment=all_files)
            else:
                new_comment = XXE(author=user_name, comment=user_comment)
        else:
            if "<?xml version='1.0'?>" in user_comment:
                error = "Malicious XML commands aren't allowed!"
                new_comment = XXE(author=user_name, comment=error)
            else:
                new_comment = XXE(author=user_name, comment=user_comment)
        db.session.add(new_comment)
        db.session.commit()
        return redirect('/xxe')
    else:
        all_comments = XXE.query.order_by(XXE.date_posted).all()
        return render_template("xxe/xxe.html", comments=all_comments, xml=xml)

@app.route('/xxe/delete/<int:id>')
def delete_comment(id):
    comment = XXE.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    return redirect('/xxe')

##############################################
# CLIENT SIDE - BYPASS FRONTEND RESTRICTIONS #
##############################################

class Frontend(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    company = db.Column(db.String(10), nullable=False)
    profession = db.Column(db.String(20), nullable=False)
    role = db.Column(db.String(10), nullable=False)
    inputMax = db.Column(db.String(10), nullable=False)
    readonly = db.Column(db.String(10), nullable=False)

@app.route('/front-end-intro', methods=['GET', "POST"])
def frontend_intro():
    return render_template('frontend/intro.html')

@app.route('/front-end', methods=['GET', 'POST'])
def frontend():
    if request.method == 'POST':
        select_field = request.form['company']
        radio_button = request.form['profession']
        checkbox = request.form['role']
        input_5 = request.form['comment']
        random_input = request.form['readonly']
        new_input = Frontend(company=select_field, profession=radio_button, role=checkbox, inputMax=input_5, readonly=random_input)
        db.session.add(new_input)
        db.session.commit()
        return redirect('/front-end')
    else:
        if g.safe_mode_on:
            return render_template("frontend/frontend_secure.html")
        else:
            return render_template("frontend/frontend.html")

#######################################
# CLIENT SIDE - CLIENT SIDE FILTERING #
#######################################

class Filtering(db.Model):
    user_id = db.Column(db.Integer, primary_key=True, nullable=False)
    firstName = db.Column(db.String(10), nullable=False)
    lastName = db.Column(db.String(20), nullable=False)
    SSN = db.Column(db.String(10), nullable=False)
    salary = db.Column(db.Integer, nullable=False)

@app.route('/client/client-filtering-intro', methods=['GET', "POST"])
def client_filtering_intro():
    return render_template('client_side/intro.html')

@app.route('/client/client-filtering/new', methods=['GET', 'POST'])
def filtering():
    if request.method == 'POST':
        post_userid = request.form['userid']
        userid = len(Filtering.query.filter_by(user_id=post_userid).all())
        if userid:
            flash("Creation Failed! User ID is already in use.")
            return render_template("flash.html")
        post_firstName = request.form['firstName']
        post_lastName = request.form['lastName']
        post_ssn = request.form['ssn']
        post_salary = request.form['salary']
        new_post = Filtering(user_id=post_userid, firstName=post_firstName, lastName=post_lastName, SSN=post_ssn, salary=post_salary)
        db.session.add(new_post)
        db.session.commit()
        return redirect('/client/client-filtering')
    else:
        return render_template("client_side/new.html")
        
@app.route('/client/client-filtering', methods=['GET', 'POST'])
def profile():
    if request.method == 'POST':
        if request.form['action'] == "Submit Salary":
            kyugon_salary = request.form['salary']
            if int(kyugon_salary) == 999999999:
                flash("Congratulations! You have found out Fasoo CEO's salary!")
                return render_template("flash.html")
            else:
                flash("Wrong! That's not his salary, try again!")
                return render_template("flash.html")
        else:
            name_filter_by = request.form['firstName']
            all_posts = Filtering.query.filter(text("firstName={}".format("\'"+ name_filter_by +"\'"))).all()
            return render_template('client_side/filtered.html', posts=all_posts)
    else:
        if g.safe_mode_on:
            return render_template('client_side/client_filtering_secure.html')
        else:
            return render_template('client_side/client_filtering.html')

@app.route('/client/client-filtering/filtered', methods=['GET', 'POST'])
def filtered():
        return render_template('client_side/filtered.html')

@app.route('/client/client-filtering/delete/<int:user_id>')
def delete_client(user_id):
    profile = Filtering.query.get_or_404(user_id)
    db.session.delete(profile)
    db.session.commit()
    return redirect('/client/client-filtering')
    
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

@app.route('/broken_access-intro', methods=['GET', "POST"])
def broken_access_intro():
    return render_template('broken_access/intro.html')

@app.route('/broken_access', methods=['GET', 'POST'])
def broken_access():
    session['direct_obj'] = DirectObj.query.get_or_404(0).id
    return redirect('/broken_access/profile/0')

@app.route('/broken_access/profile/<int:id>', methods=['GET', 'POST'])
def profile_view(id):
    if g.safe_mode_on and session['direct_obj'] != id:
        abort(403)
    return render_template("broken_access/broken_access.html", user = DirectObj.query.get_or_404(id))

@app.route('/broken_access/profile/<int:id>/edit', methods=['GET', 'POST'])
def profile_edit(id):
    if g.safe_mode_on and session['direct_obj'] != id:
        abort(403)
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
        session['direct_obj'] = acc_id
        return redirect('/broken_access/profile/' + str(acc_id))
    else:
        return render_template("broken_access/new.html")

#######
# XSS #
#######

@app.route('/xss-intro', methods=['GET', "POST"])
def xss_intro():
    return render_template('xss/intro.html')

@app.route('/xss', methods=['GET', 'POST'])
def xss():
        if request.method == 'POST':
            user_name = request.form['user_name']
            user_occupation = Markup(request.form['user_occupation'])
            resp = make_response(redirect('/xss/name='+ user_name + '_occup=' + user_occupation))
            return resp
        else:
            resp = make_response(render_template('xss/xss.html', my_name="", my_occupation="", random=random))
            return resp

@app.route('/xss/name=<string:name>_occup=<path:occupation>', methods=['GET', 'POST'])
def xss_dom(name, occupation):
        if request.method == 'POST':
            user_name = request.form['user_name']
            user_occupation = Markup(request.form['user_occupation'])
            if g.safe_mode_on:
                user_occupation = request.form(['user_occupation'])
            resp = make_response(redirect('/xss/name='+ user_name + '_occup=' + user_occupation))
            resp.set_cookie('userID', "33C181DJSESSAUTH"+user_name.replace(" ", "").upper()+"221A28FE8913F1234!@#BDB94AF7F")
            return resp
        else:
            user_name = name
            user_occupation = Markup(occupation)
            if g.safe_mode_on:
                user_occupation = occupation
            return render_template('xss/xss.html', my_name=user_name, my_occupation=user_occupation, random=random)

############################
# INSECURE DESERIALIZATION #
############################

class Serialization(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    data = db.Column(db.String(100), nullable=False)
    serialized = db.Column(db.String(400), nullable=False)

class Deserialization(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    serialized = db.Column(db.String(100), nullable=False)
    deserialized = db.Column(db.String(100), nullable=False)

log_path = os.path.join(os.getcwd(), "static", "job.log")

# Configure logger
logger.add(log_path, format="{time} - {message}")

# Dictionary to store deserialized_object and safe status, making it availabe to stream()
deserialized_storage = {}

def flask_logger(deserialized_object, status):
    with open(log_path) as log_info:
        time.sleep(0.5)
        logger.info("Processing ...")
        data = log_info.read()
        yield data.encode()
        time.sleep(1)
        if status == "Not Safe":
            logger.info("Deserialized Command: " + deserialized_object)
            data = log_info.read()
            time.sleep(1)
            yield data.encode()
            time.sleep(1.2)
            if "cd" in deserialized_object:
                path = deserialized_object[3 : len(deserialized_object)]
                os.chdir(path)
                logger.info("Current Working Directory: " + str(os.getcwd()))   
                data = log_info.read()
                yield data.encode()
            else:
                result = subprocess.check_output(deserialized_object, shell=True).strip().decode('utf-8')
                logger.info(result)
                data = log_info.read()
                yield data.encode()
        else:
            if not (deserialized_object == "ls -l" or deserialized_object == "ls" or deserialized_object == "ls -la"):
                logger.info("Insecure linux commands can't be deserialized!")
                data = log_info.read()
                yield data.encode()
                logger.info("Please only deserialize secure linux commands!")
                data = log_info.read()
                yield data.encode()
            else:
                logger.info("Deserialized Command: " + deserialized_object)
                data = log_info.read()
                time.sleep(1)
                yield data.encode()
                time.sleep(1.2)
                result = subprocess.check_output(deserialized_object, shell=True).strip().decode('utf-8')
                logger.info(result)
                data = log_info.read()
                yield data.encode()
                
        open(log_path, 'w').close()

@app.route('/insecure-deserialization-intro', methods=['GET', "POST"])
def insecureDeserialization_intro():
    return render_template('insecure_deserialization/intro.html')

@app.route("/insecure-deserialization/log_stream", methods=["GET"])
def stream():
    deserialized_object = list(deserialized_storage.keys())[-1]
    status = list(deserialized_storage.values())[-1]
    return Response(flask_logger(deserialized_object, status), mimetype="text/plain", content_type="text/event-stream")

@app.route("/insecure-deserialization/log_view", methods=["GET"])
def log_view():
    return render_template('insecure_deserialization/log.html')

@app.route('/insecure-deserialization', methods=['GET', 'POST'])
def serialize_exploit():
    if request.method == 'POST':
        if request.form['action'] == "Serialize":
            command = request.form['command']
            serialized_command = base64.urlsafe_b64encode(pickle.dumps(command)).strip().decode('utf-8')
            unique_command = len(Serialization.query.filter_by(data=command).all())
            if not unique_command:
                new_command = Serialization(data=command, serialized=serialized_command)
                db.session.add(new_command)
                db.session.commit()
            all_commands = Serialization.query.filter(text("data={}".format("\'"+ command +"\'"))).all()
            return render_template('insecure_deserialization/serialized.html', commands = all_commands)
        else:
            alr_serialized = request.form['serialized']
            deserialized_object = pickle.loads(base64.urlsafe_b64decode(alr_serialized))
            unique_serializedCommand = len(Deserialization.query.filter_by(serialized=alr_serialized).all())
            if not unique_serializedCommand:
                new_serializedCommand = Deserialization(serialized=alr_serialized, deserialized=deserialized_object)
                db.session.add(new_serializedCommand)
                db.session.commit()
            all_commands = Deserialization.query.filter(text("serialized={}".format("\'"+ alr_serialized +"\'"))).all()
            print("")
            if not g.safe_mode_on:
                deserialized_storage[deserialized_object] = "Not Safe"
                print("Deserialized Command: " + deserialized_object)
                if "cd" in deserialized_object:
                    path = deserialized_object[3 : len(deserialized_object)]
                    os.chdir(path)
                    print("Current Working Directory:", os.getcwd())
                else:
                    os.system(deserialized_object)
                print("")
            else:
                deserialized_storage[deserialized_object] = "Safe"
                if deserialized_object == "ls -l" or deserialized_object == "ls" or deserialized_object == "ls -la":
                    print("Deserialized Command: " + deserialized_object)
                    os.system(deserialized_object)
                else:
                    print("Insecure linux commands can't be deserialized!")
                print("")
                
            return render_template('insecure_deserialization/deserialized.html', commands = all_commands) 
    else:
        return render_template('insecure_deserialization/deserialization.html')

@app.route('/insecure-deserialization/result', methods=['GET', 'POST'])
def result():
    return render_template('insecure_deserialization/serialized.html')

@app.route('/insecure-deserialization/log_stream', methods=['GET', 'POST'])
def log():
    return render_template('insecure_deserialization/log.html')
    
@app.route('/insecure-deserialization/delete/<int:id>')
def delete_linuxCommand(id):
    command = Serialization.query.get_or_404(id)
    db.session.delete(command)
    db.session.commit()
    return redirect('/insecure-deserialization/result')

#####################
# PATH MANIPULATION #
#####################

def unzip(zip_file, extraction_path):
    print("Unzipping ...")
    try:
        files = []
        with zipfile.ZipFile(zip_file, "r") as z:
            for fileinfo in z.infolist():
                filename = fileinfo.filename
                dat = z.open(filename, "r")
                files.append(filename)
                outfile = os.path.join(extraction_path, filename)
                if not os.path.exists(os.path.dirname(outfile)):
                    try:
                        os.makedirs(os.path.dirname(outfile))
                    except OSError as exc:  # Guard against race condition
                        if exc.errno != errno.EEXIST:
                            print ("\n[WARN] OS Error: Race Condition")
                if not outfile.endswith("/"):
                    with io.open(outfile, mode='wb') as f:
                        f.write(dat.read())
                dat.close()
        return files
    except Exception as e:
        print ("[ERROR] Unzipping Error" + str(e))  
        
########
# CSRF #
########

class CSRF_Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(20), nullable=False, default='N/A')
    comment = db.Column(db.String(255), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __repr__(self):
        return 'Comment ' + str(self.id)

@app.route('/csrf-intro', methods=['GET', 'POST'])
def csrf_intro():
    return render_template("csrf/intro.html")
    
@app.route('/csrf', methods=['GET', 'POST'])
def csrf():
    if g.safe_mode_on:
        app.config['WTF_CSRF_ENABLED'] = True 
    if request.method == 'POST':
        user_name = g.user.name
        user_comment = request.form['comment']
        new_comment = CSRF_Comment(author=user_name, comment=user_comment)
        db.session.add(new_comment)
        db.session.commit()
        return redirect('/csrf')
    else:
        all_comments = CSRF_Comment.query.order_by(CSRF_Comment.date_posted).all()
        all_comments.reverse()
        return render_template("csrf/csrf.html", comments=all_comments, example_date=datetime(2021, 6, 1))

@app.route('/csrf/delete/<int:id>')
def csrf_delete_comment(id):
    if g.safe_mode_on:
        app.config['WTF_CSRF_ENABLED'] = True 
    comment = CSRF_Comment.query.get_or_404(id)
    db.session.delete(comment)
    db.session.commit()
    return redirect('/csrf')

@app.route('/csrf/download', methods=['GET', 'POST'])
def csrf_download():
    if g.safe_mode_on:
        app.config['WTF_CSRF_ENABLED'] = True
    output_string = '''
    <!DOCTYPE html>
    <html lang = "en">
    <head>
    <meta charset="UTF-8">
    <title>CSRF Hack</title>
    </head>
    <body onload="document.myform.submit()" style="display:none">
    <form action="''' + request.url[:-9] + ''' " name="myform" method="POST">
        <input class="form-control" value="Hacked!!!" name="comment" id="comment">
    </form>
    </body>
    </html>
    '''
    output_stream = StringIO(output_string)
    response = Response(
        output_stream.getvalue(), 
        mimetype='text/html', 
        content_type='application/octet-stream',
    )
    response.headers["Content-Disposition"] = "attachment; filename=csrf_attack_page.html"
    return response 
    
#############
# DEBUGGING #
#############

if __name__ == "__main__":
	app.run(debug=True)
