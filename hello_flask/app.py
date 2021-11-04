from flask import Flask,render_template,request, jsonify, redirect, session
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
def create_token(user):
    payload = list(user)
    jwt_token = jwt.encode({'username': user, 'password': password}, JWT_SECRET, algorithm="HS256")
    return jwt_token

def exposejwt(token):
    print(token)
    return json_response(output=jwt.decode(token, JWT_SECRET, algorithms=["HS256"]))

  
@app.route('/login', methods=['POST'])
def login():
    user = request.form['username']
    password = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"SELECT pass FROM users WHERE username = '{user}';")
    checkr = cur.fetchone()[0]
    if checkr == None:
        print("The username was not found")
        return "User not found", redirect('first_form.html')
    else:
        token = create_token(user)
        print(token)
        return "This is token" + token + ". This is exposed token " + reveal #redirect('/static/myprofile.html')
      
app.run(host='0.0.0.0', port=80)
