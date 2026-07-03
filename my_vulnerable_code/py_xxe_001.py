from flask import Flask, request
from lxml import etree

app = Flask(__name__)

@app.route('/xml', methods=['POST'])
def parse_xml():
    parser = etree.XMLParser(resolve_entities=True)
    root = etree.fromstring(request.data, parser)
    return etree.tostring(root).decode()
