from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['POST'])
def upload_file():
    file = request.files['file']
    file.save(f'/var/www/uploads/{file.filename}')  # Vulnerable: no type/name validation
    return "File uploaded"
