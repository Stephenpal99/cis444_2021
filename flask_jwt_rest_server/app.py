#Gunicorn server running on port 8000. Has permissions to AWS port
# CMD line to run server gunicorn --workers=1 --bind 0.0.0.0 app:app
from flask import Flask,json,render_template,request, jsonify, redirect, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
import jwt
import json
import datetime
import bcrypt
import html
import os

from db_con import get_db_instance, get_db

from tools.token_required import token_required
from tools.get_aws_secrets import get_secrets
from tools.logging import logger

ERROR_MSG = "Ooops.. Didn't work!"
INV = "Unable to process"
app = Flask(__name__)
FlaskJSON(app)
"""def create_app():
    app = Flask(__name__)
    return app"""

JWT_SECRET = None
CUR_ENV = "PRD"

global_db_con = get_db()
#g is flask for a global var storage 
"""def init_new_env():
    if 'db' not in g:
        g.db = get_db()

    g.secrets = get_secrets()
"""
token = None

"""def app(environ, start_response):
    data = b'Welcome to Barn & Noodle 2.0\n'
    status = '200 OK'
    response_headers = [
        ('Content-type', 'text/plain'),
        ('Content-Length', str(len(data)))
    ]
    start_response(status, response_headers)
    return redirect ('static/first_form.html')"""

@app.route('/') #endpoint
def index():
    return redirect('/static/first_form.html')


@app.route('/backp',  methods=['POST']) #endpoint
def backp():
    print(request.form)
    salted = bcrypt.hashpw( bytes(request.form['fname'],  'utf-8' ) , bcrypt.gensalt(10))
    print(salted)

    print(  bcrypt.checkpw(  bytes(request.form['fname'],  'utf-8' )  , salted ))

    return render_template('backatu.html',input_from_browser= str(request.form) )


@app.route('/exposejwt') #endpoint
def exposejwt():
    logger.debug(f"Exposure of jwt")
    jwt_token = request.args.get('jwt')
    print(jwt_token)
    return json_response(output=jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"]))



app.config['SECRET_KEY'] = 'helloworld'

def create_token(user):
    logger.debug("Creation of the jwt token")
    payload = list(user)
    token = jwt.encode({'username': user, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return token

@app.route('/addUser',methods = ["GET","POST"])
def addUser():
	logger.debug(f"The user is creating an account.")
	if request.method == "POST":
		cur =global_db_con.cursor()
		user = request.form.get("username")
		password = request.form.get("password")
		enc_password = bcrypt.hashpw(bytes(password,"utf-8"),bcrypt.gensalt())
		userInsert = """INSERT INTO users(username,pass) values(%s, %s);"""
		cur.execute(userInsert,(user,enc_password))
		global_db_con.commit()
		print("Your user account has successfully been created. Please login now.")
                #logger.info("The account has successfully been created")
		return "Welcome " + user
	#else:
                #logger.error(user + " not successfully created.")
	        #return json_response(status_=500 ,data=INV)

@app.route('/getUser', methods=['POST'])
def login():
    logger.debug(f"The user is logging in with credentials!:")
     #setup the env
    #init_new_env()
    user = request.form['username']
    data = user
    password = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"SELECT pass FROM users WHERE username = '{user}';")
    checkr = cur.fetchone()[0]
    if checkr == None:
        logger.warning("Username not found")
        print("The username was not found")
        return "User not found"
    elif(checkr == password):
        logger.info("User has successfully logged in")
        global token
        token = create_token(user)
        return render_template('profile.html',jsonfile=json.dumps(data))
    else:
        logger.error(user + " has passed wrong password " + password)
        return redirect('/static/first_form.html')
            	
@app.route('/getMyBooks', methods = ["GET", "POST"])
def myBooks():
    logger.debug(f"User look up of books owned:")
    cur = global_db_con.cursor() 
    global token
    getUser = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = getUser['username']
    #username = "stevep"
    sqlExecute = (f"SELECT book_title FROM owners WHERE username = '{username}';")
    cur.execute(sqlExecute)
    rows = cur.fetchall()
    if rows == None:
        logger.info(username + " request access to books")
        return "You don't own any books"
    else:
        logger.info(username + " request access to books")
        return jsonify(str(rows))

@app.route('/buyBook_id_321', methods = ["GET", "POST"])
def buyCatHat():
    logger.debug(f"Purchase of book:")
    cur = global_db_con.cursor() 
    global token
    getUser = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = getUser['username']
    book_title = "Cat With Hat"
    #username = "stevep"
    sqlExecute = """INSERT INTO owners(username,book_title) VALUES(%s,%s);"""
    cur.execute(sqlExecute,(username,book_title))
    global_db_con.commit()
    logger.info(book_title + " has been purchased by user " + username)
    return username + "has successfully purchased the book Cat With Hat"
   

@app.route('/buyBook_id_123', methods = ["GET", "POST"])
def buyMocking():
    logger.debug(f"Purchase of book:")
    cur = global_db_con.cursor() 
    global token
    getUser = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = getUser['username']
    book_title = "Kill Mockingbird"
    #username = "stevep"
    sqlExecute = """INSERT INTO owners(username,book_title) VALUES(%s,%s);"""
    cur.execute(sqlExecute,(username,book_title))
    global_db_con.commit()
    logger.info(book_title + " has been purchased by user " + username)
    return username + " has successfully purchased the book Kill Mockingbird"
     
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8000, ssl_context='adhoc')

