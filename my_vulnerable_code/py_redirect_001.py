from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def open_redirect():
    target = request.args.get('next')
    return redirect(target)
