from flask import Flask, request
app = Flask(__name__)

@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"  # Vulnerable: unsanitized
