from flask import Flask, render_template, redirect, request, jsonify, url_for, jsonify, session, g, jsonify
from flask_socketio import SocketIO, disconnect
import pyrebase
import random
import string
import os
import requests
#import hashlib

config = {
    "apiKey": "AIzaSyD5tDKhe1wUys8tgBWaOhfCpT7RXb3z4es",
    "authDomain": "trivia-259917.firebaseapp.com",
    "databaseURL": "https://trivia-259917.firebaseio.com",
    "projectId": "trivia-259917",
    "storageBucket": "gs://trivia-259917.appspot.com",
    "serviceAccount": "app/firebase-private-key.json",
    "messagingSenderId": "115605857619"
  }

firebase = pyrebase.initialize_app(config)

db = firebase.database()
auth = firebase.auth()

app = Flask(__name__)

app.secret_key = os.urandom(24)
app.config['SECRET_KEY'] = 'verysecret'
socketio = SocketIO(app)

games = dict() #{'game1_code': [player1, player2, ..], 'game2_code': [player1, player2, ...]}

@app.route('/')
@app.route('/index')
def index():
    db_users = db.child('users').get()

    leaderboard_scores = []
    for data in db_users.each(): 
        leaderboard_scores.append(data.val()['score'])

    leaderboard_scores.sort(reverse = True)

    leaderboard_names =[]
    for score in leaderboard_scores:
        for data in db_users.each():
            if score == data.val()['score'] and not data.val()['username'] in leaderboard_names:
                leaderboard_names.append(data.val()['username'])

    return render_template('index.html', names=leaderboard_names, scores=leaderboard_scores, errors='')

@app.route('/index_err/<err>')
def index_err(err):
    print(err)
    db_users = db.child('users').get()

    leaderboard_scores = []
    for data in db_users.each(): 
        leaderboard_scores.append(data.val()['score'])

    leaderboard_scores.sort(reverse = True)

    leaderboard_names =[]
    for score in leaderboard_scores:
        for data in db_users.each():
            if score == data.val()['score'] and not data.val()['username'] in leaderboard_names:
                leaderboard_names.append(data.val()['username'])

    return render_template('index.html', names=leaderboard_names, scores=leaderboard_scores, error=err)


@app.route('/signup', methods=['POST'])
def signup():
    email = request.form['signup_email']
    username = request.form['signup_username']
    password = request.form['signup_password']
    password2 = request.form['signup_password_repeat']

    if not password == password2:
         return redirect(url_for('index_err', err='PP'))


    db_users = db.child('users').get()
    for data in db_users.each(): 
        if username == data.val()['username']:
            return redirect(url_for('index_err', err='UE'))

    try:
        user = auth.create_user_with_email_and_password(email, password)
    except requests.HTTPError as err:
        if "EMAIL_EXISTS" in str(err):
            return redirect(url_for('index_err', err='EE'))
        elif "WEAK_PASSWORD" in str(err):
            return redirect(url_for('index_err', err='WP'))
    else:
        db.child("users").push({'email': user['email'], 'username': username, 'score': 0})

        auth.send_email_verification(user['idToken'])

        return '<h1>Please confirm your password by going to your email.</h1>'

@app.route('/signin', methods=['POST', 'GET'])
def signin():

    if request.method == 'GET':
        print('GET request detected!')
        return '<h1>Page refreshed</h1>'
    else:
        print('POST request detected')

        email = request.form['signin_email']
        password = request.form['signin_password']

        try:
            user = auth.sign_in_with_email_and_password(email, password) 
        except requests.HTTPError as err:
            print(err)
            if "EMAIL_NOT_FOUND" in str(err):
                return redirect(url_for('index_err', err='IE'))
            elif "INVALID_PASSWORD" in str(err):
                return redirect(url_for('index_err', err='IP'))
        else:
            session['user'] = user
            session['email'] = user['email']

            db_admins = db.child("admins").get()

            user_data = auth.get_account_info(user['idToken'])

            session['isAdmin'] = False
            for admin in db_admins.each():
                if user['email'] in admin.val():
                    session['isAdmin'] = True

            if user_data['users'][0]['emailVerified'] == True: # if email is verified
                return redirect(url_for('home'))
            else:
                # add the css for this error
                return redirect(url_for('index_err', err='EV'))

@app.route('/passwordrecovery')
def passwordrecovery():
    return render_template('passwordrecovery.html')

@app.route('/reset', methods=['POST'])
def reset():
    email = request.form['email']

    auth.send_password_reset_email(email)

    return '<h1>Check your email to reset your password </h1>'

@app.route('/home', methods=['GET'])
def home():
    db_users = db.child('users').get()
    leaderboard_scores = []
    for data in db_users.each(): 

        leaderboard_scores.append(data.val()['score'])

    leaderboard_scores.sort(reverse = True)
    leaderboard_names =[]

    for score in leaderboard_scores:
        for data in db_users.each():
            if score == data.val()['score'] and not data.val()['username'] in leaderboard_names:
                leaderboard_names.append(data.val()['username'])

    if session['isAdmin'] == True: # if the user is an admin

        for data in db_users.each():  
            if session['user']['email'] == data.val()['email']: # the credentials that match the email
                    session['username'] = data.val()['username']
                    return render_template('adminhome.html', username = session['username'], names = leaderboard_names, scores=leaderboard_scores)
    else: # if not admin

        for data in db_users.each():
            if session['user']['email'] == data.val()['email']: # the credentials that match the email
                session['username'] = data.val()['username']
                score = data.val()['score']
                return render_template('userhome.html', username = session['username'], score = score, scores = leaderboard_scores, names=leaderboard_names)
                            

@app.route('/create', methods=['POST', 'GET'])
def create():
    code = game_link_generator()

    global games
    games[code] = []

    return redirect(url_for('lobby', code=code))


#@socketio.on('connect')
#def test_connect():
#    print('User connected')

#@socketio.on('disconnect')
#def test_disconnect():
#    global games
#    for code in games:
#        if session['username'] in games[code]:
#            games[code].remove(session['username'])

@app.route('/join', methods=['POST', 'GET'])
def join():
    
    code = request.form['code']

    global games

    print(code)
    print(games)
    if code in games:
        games[code].append(session['username'])
        return redirect(url_for('lobby', code=code))
    else:
        return '<h1>Game Not Found</h1>'
    
@app.route('/settings', methods=['POST', 'GET'])
def settings():
    if request.method == 'GET':
        return render_template('settings.html')
    else:
        if 'changeuser' in request.form:
            username = request.form['username']
            db_users = db.child('users').get()
            for data in db_users.each(): # check if username is already in the database
                if username == data.val()['username']:
                    return '<h1>Username already in use.</h1>'
            for data in db_users.each(): # if username is unique, check for the user with the same email and change the username
                if session['email'] == data.val()['email']:
                    db.child('users').child(data.key()).update({"username": username})
                    return redirect(url_for('index'))

            return '<h1>An Error Occured</h1>'
        elif 'changepass' in request.form:
            print('form clicked')
            email = session['email']
            password = request.form['password1']
            user = auth.sign_in_with_email_and_password(email, password)
            oob = auth.send_password_reset_email(user['email'])
            print(oob)
            new_password = request.form['password2']
            auth.update_password(oob, new_password, password, email)
            return redirect(url_for('index'))


@app.route('/<code>/lobby')
def lobby(code):
    if session['isAdmin']: # if user is admin
        return render_template('adminlobby.html', code=code)
    else: # if user is not admin
        return render_template('userlobby.html', code=code)

@app.route('/<code>/update', methods=['POST'])
def update(code):
    global games
    return jsonify({'players': games[code]})

@app.route('/<code>/start')
def start(code):
    global games
    games[code].append("gameShouldStart")
    print("Appended")
    print(games[code])

    return redirect(url_for('game', code = code))

@app.route('/<code>/game', methods=['POST', 'GET'])
def game(code):
    global games
    if request.method == 'GET':
        if session['isAdmin'] == True:
            games[code].clear()
            games[code].append("gameShouldStart")
            return render_template('admingame.html', code = code, players_pressed = games[code])
        else:
            return render_template('usergame.html', code = code, players_pressed = games[code])
    elif request.method == 'POST':
        print('POST request detected')
        if not session['username'] in games[code]:
            games[code].append(session['username'])
        return '', 204 # return an empty response with a 204 protocol

@app.route('/<code>/reset_game', methods=['POST'])
def reset_game(code):
    username = request.form.get('username')

    db_users = db.child('users').get()
    for data in db_users.each():
        if username == data.val()['username']:
            score = data.val()['score']
            db.child('users').child(data.key()).update({"score": score + 10})

    global games
    games[code].clear()
    games[code].append('NA')
    return '', 204

@app.route('/prank')
def prank():
    return redirect('https://youtu.be/dQw4w9WgXcQ?t=43')

@app.errorhandler(404)
def not_found_error(error):
    return '<h2>Page not found</h2>', 404

def game_link_generator(size=6, chars=string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

if __name__ == "__main__":
    socketio.run(app, debug=True)
    #socektio.run(app, host='0.0.0.0', port=8080, debug=False)
    #app.run(debug=True)
    #app.run(host='0.0.0.0', port=8080, debug=False)
