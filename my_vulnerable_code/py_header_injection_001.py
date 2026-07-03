from flask import Flask, request, make_response

app = Flask(__name__)

@app.route('/redirect')
def redirect_user():
    location = request.args.get('location')
    response = make_response('Redirecting...')
    response.headers['Location'] = location
    return response
