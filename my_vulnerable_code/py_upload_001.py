from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    file.save(f'/var/www/uploads/{file.filename}')
    return 'File uploaded'
