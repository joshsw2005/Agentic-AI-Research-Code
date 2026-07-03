from flask import Flask, request
import os

app = Flask(__name__)

@app.route('/download')
def download():
    filename = request.args.get('file')
    filepath = os.path.join('/var/www/files', filename)  # Vulnerable: no sanitization
    with open(filepath, 'r') as f:
        return f.read()
