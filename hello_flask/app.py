from flask import Flask,render_template,request, jsonify, redirect
from flask_json import FlaskJSON, JsonError, json_response, as_json
import jwt

import datetime
import bcrypt


from db_con import get_db_instance, get_db

app = Flask(__name__)
FlaskJSON(app)

JWT_SECRET = None
CUR_ENV = "PRD"

global_db_con = get_db()

token = None

@app.route('/backp',  methods=['POST']) #endpoint
def backp():
    print(request.form)
    salted = bcrypt.hashpw( bytes(request.form['fname'],  'utf-8' ) , bcrypt.gensalt(10))
    print(salted)

    print(  bcrypt.checkpw(  bytes(request.form['fname'],  'utf-8' )  , salted ))

    return render_template('backatu.html',input_from_browser= str(request.form) )


@app.route('/exposejwt') #endpoint
def exposejwt():
    jwt_token = request.args.get('jwt')
    print(jwt_token)
    return json_response(output=jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"]))



app.config['SECRET_KEY'] = 'helloworld'

def create_token(user):
    payload = list(user)
    token = jwt.encode({'username': user, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
    return token

@app.route('/addUser',methods = ["GET","POST"])
def addUser():
	if request.method == "POST":
		cur =global_db_con.cursor()
		user = request.form.get("username")
		password = request.form.get("password")
		enc_password = bcrypt.hashpw(bytes(password,"utf-8"),bcrypt.gensalt())
		userInsert = """INSERT INTO users(username,pass) values(%s, %s);"""
		cur.execute(userInsert,(user,enc_password))
		global_db_con.commit()
		print("Your user account has successfully been created. Please login now.")
		return "Welcome" + user
	return "There was an error on our part. Please try again!"

@app.route('/getUser', methods=['POST'])
def login():
    user = request.form['username']
    password = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"SELECT pass FROM users WHERE username = '{user}';")
    checkr = cur.fetchone()[0]
    if checkr == None:
        print("The username was not found")
        return "User not found"
    elif(checkr == password):
        global token
        token = create_token(user)
        return redirect('/static/myprofile.html')
    else:
        return "Invalid password"
        
      
      	
@app.route('/getMyBooks', methods = ["GET", "POST"])
def myBooks():
    cur = global_db_con.cursor() 
    global token
    getUser = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    username = getUser['username']
    #username = "stevep"
    sqlExecute = "SELECT * FROM owners WHERE username = username"
    cur.execute(sqlExecute)
    rows = cur.fetchall()
    print(username)
    if rows == None:
        return "You don't own any books"
    else:
        books = []
        for row in rows:
            books.append(row[1])
        return jsonify(str(books))

app.run(host='0.0.0.0', port=80)

