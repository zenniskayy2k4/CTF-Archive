import re
import uuid
from flask import Flask, request, render_template, jsonify, abort

app = Flask(__name__)


import os
ITEM = os.environ.get("FLAG", "07CTF{DUMMY}")  # Read flag from environment variable

games = {} 
base_exec_func = exec
import re
RE_ACTUAL = re.compile(r'^[A-Z ]{3}$')

A="Sorry, wrong guess."
B="Congratulations! Here is your flag:"
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/create', methods=['GET', 'POST'])
def create_game():
    if request.method == 'POST':
        actual = request.form.get('actual', '')
        operator = request.form.get('operator', '')
        if not RE_ACTUAL.fullmatch(actual):
            return render_template('create.html', error='Actual must be exactly 3 lowercase letters')
        if len(operator) != 2 or '=' not in operator:
            return render_template('create.html', error='Operator must be exactly 2 chars and include "="')
        #check  each char of operator by isalnum()
        if any(c.isalpha() for c in operator):
            return render_template('create.html', error='Operator must not contain alphanum')
        game_id = str(uuid.uuid4())[:8]
        games[game_id] = {'actual': actual, 'operator': operator}
        return render_template('created.html', game_id=game_id)
    return render_template('create.html')

@app.route('/play/<game_id>', methods=['GET', 'POST'])
def play_game(game_id):
    if game_id not in games:
        abort(404)
    message = "-"
    flag = None
    if request.method == 'POST':
        guess = request.form.get('guess', '')
        if len(guess) != 3:
            message = 'Guess must be exactly 3 characters'
        else:
            actual = games[game_id]['actual']
            operator = games[game_id]['operator']
            expr = f"{actual}{operator}{guess}"
            try:
                result = base_exec_func(expr, globals())
            except Exception as e:
                message += "Sorry, wrong guess."
            else:
                if result:
                    message = B
                    flag = ITEM
                else:
                    message = "Sorry, wrong guess."
    return render_template('play.html', game_id=game_id, message=message, flag=flag)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")