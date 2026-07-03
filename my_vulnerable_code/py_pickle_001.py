import pickle
from flask import Flask, request

app = Flask(__name__)

@app.route('/deserialize', methods=['POST'])
def deserialize():
    data = request.data
    obj = pickle.loads(data)
    return str(obj)
