import os.path

from dict_hash import sha256
from flask import Flask, request, jsonify, send_from_directory, send_file
from pymongo import MongoClient
from bson.json_util import dumps
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
import jwt
import json
import time
import bcrypt
import random
import string
import re
import hashlib

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'res\\files'
app.config['SECRET_KEY'] = 'D5*F?_1?-d$f*1'

client = MongoClient('mongodb://root:example@localhost:27017/')
db = client['digital_id_database']
users_collection = db['systemUsers']
transactions_collection = db['transactionBlockchain']
document_repositories_collection = db['documentsRepository']


def generate_uid():
    return ''.join(random.choices('abcdef' + string.digits, k=6))

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = ""
        if 'authorization' in request.headers:
            token = request.headers['authorization']
        if not token:
            return jsonify({'message': 'Acceso no autorizado. Autentifíquese con un token'}), 401

        try:
            token = re.sub('Bearer\s', '', token)
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            print(data)
            if data['iss'] == 'digitalid_user':
                current_user = users_collection.find_one({"uid": data['uid']})
                print(current_user)
            else:
                return jsonify({
                    'message': 'Acceso no autiroizado. El token está mal estructurado o es inválido'
                }), 401
        except:
            return jsonify({
                'message': 'Acceso no autiroizado. El token está mal estructurado o es inválido'
            }), 401
        return f(current_user, *args, **kwargs)

    return decorated


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if data['password'] != data['confirm_password']:
        return jsonify({"error": "Las contraseñas no coinciden"}), 400

    hashed_password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())

    uid = ''.join(random.choices('0123456789abcdef', k=6))

    user_document = {
        "uid": uid,
        "name": data['full_name'],
        "email": data['email'],
        "password": hashed_password.decode('utf-8'),
        "birth_date": data['birth_date'],
        "gender": data['gender']
    }

    transaction_document = create_blockchain(user_document, None)

    user_document["initial_block"] = transaction_document['hash_block']['current_hash']
    user_document["current_block"] = transaction_document['hash_block']['current_hash']

    result = users_collection.insert_one(user_document)

    user_document["_id"] = str(result.inserted_id)

    document_repository = {
        "uid": uid,
        "document_list": [],
        "last_document_uploaded_timestamp": time.time()
    }

    document_repositories_collection.insert_one(document_repository)

    return jsonify({"message": "Usuario registrado exitosamente", "user": user_document}), 201


@app.route('/login', methods=['GET'])
def login_user():
    auth = request.authorization

    print(auth.username)

    user_document = users_collection.find_one({"email": auth.username})
    print("User Document: ")
    print(user_document)

    password = auth.password.encode('utf-8')

    hashed_password = user_document['password'].encode('utf-8')

    is_password = bcrypt.checkpw(password, hashed_password)

    print(is_password)

    if is_password:
        user_data = {
            "uid": user_document['uid'],
            "name": user_document['name'],
            "email": user_document['email'],
            "birth_date": user_document['birth_date'],
            "gender": user_document['gender']
        }
        #actual_blockchain = create_blockchain(user_data, user_document['current_block'])
        #users_collection.find_one_and_update({"email": auth.username}, {'$set': {"current_block": actual_blockchain['hash_block']['current_hash']}})
        token = jwt.encode({
            'iss': 'digitalid_user',
            'uid': user_document['uid'],
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(minutes=30),
            'user_data': user_data
        }, app.config['SECRET_KEY'], algorithm="HS256")
        return jsonify({"message": "Sesión iniciada correctamente",
                        "user_data": user_data,
                        "auth_token": token}), 200
    else:
        return jsonify({"message": "Fallo al iniciar sesión, intente nuevamente"}), 200

@app.route('/upload_document', methods=['POST'])
@token_required
def upload_document(current_user):
    print("Current User Token: ")
    print(current_user)
    user_document = current_user
    print("User Document: ")
    print(user_document)
    form_document = request.form

    if 'file' not in request.files:
        return jsonify({"message": "No se ha incluído el archivo en la petición"}), 400
    document = request.files['file']
    if document.filename == '':
        return jsonify({"message": 'No hay ningún archivo en la petición'}), 400

    uid = ''.join(random.choices('0123456789abcdef', k=6))

    sha256hash = hashlib.sha256()
    while data := document.stream.read(8192):
        sha256hash.update(data)

    document_registry = {
        "uid": uid,
        "filename": document.filename,
        "document_type": form_document['tipo_documento'],
        "view_url": "http://localhost:5000/document/"+uid+"?mode=view",
        "download_url": "http://localhost:5000/document/" + uid + "?mode=download",
        "document_hash": sha256hash.hexdigest()
    }

    result = document_repositories_collection.find_one_and_update({"uid": user_document['uid']}, {'$push': {'document_list': document_registry}})

    result = dumps(result)
    result = json.loads(result)

    Path(app.config['UPLOAD_FOLDER']+"/"+user_document['uid']).mkdir(parents=True, exist_ok=True)

    document.save(os.path.join(app.config['UPLOAD_FOLDER']+"/"+user_document['uid'], document.filename))

    return jsonify({"message": "Documento guardado exitosamente", "data": result}), 201

@app.route('/access_documents/<uid>')
def access_documents(uid):
    print("Current User Token: ")
    print(request.args.get('auth_token'))
    token = request.args.get('auth_token')
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    print(data)
    print(data.get('user_data', {}))
    institution_document = data.get('user_data', {})
    print("Institution Document: ")
    print(institution_document)
    user_document = users_collection.find_one({"uid": uid})
    print("User Document: ")
    print(user_document)

    result = document_repositories_collection.find_one({"uid": uid})
    list_documents = result['document_list']
    list_documents = json.loads(dumps(list_documents))

    blockchain_data = {
        'token': token,
        'user_document': institution_document
    }
    if not user_document['uid'] == institution_document['uid']:
        actual_blockchain = create_blockchain(blockchain_data, user_document['current_block'])
        users_collection.find_one_and_update({"uid": uid}, {'$set': {"current_block": actual_blockchain['hash_block']['current_hash']}})

    return jsonify({"message": "Documentos extraidos exitosamente", "data": list_documents}), 200

@app.route('/document/<uid>')
def get_document(uid):
    print("Current User Token: ")
    print(request.args.get('auth_token'))
    token = request.args.get('auth_token')
    data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
    print(data)
    print(data.get('user_data', {}))
    user_document = data.get('user_data', {})

    result = document_repositories_collection.find_one({
        "uid": user_document['uid'],
        "document_list.uid": uid
    },
{
        "document_list": {
            "$elemMatch": {
                "uid": uid
            }
        }
    })

    print(result)

    document_file_data = result.get("document_list", [])[0] if result else None

    print(document_file_data)
    print(type(document_file_data))

    if request.args.get('mode') == "view":
        return send_from_directory(app.config['UPLOAD_FOLDER']+"/"+user_document['uid'], document_file_data['filename']), 200
    if request.args.get('mode') == "download":
        return send_file(app.config['UPLOAD_FOLDER']+"\\"+user_document['uid']+"\\"+document_file_data['filename'], as_attachment=True), 200

@app.route('/get_blockchain', methods=['GET'])
@token_required
def get_blockchain(current_user):
    print("Current User Token: ")
    print(current_user)
    user_document = current_user
    print("User Document: ")
    print(user_document)

    blockchain = []
    final_block = user_document['current_block']
    initial_block = user_document['initial_block']
    actual_block = transactions_collection.find_one({"hash_block.current_hash": final_block})
    actual_hash = actual_block['hash_block']['current_hash']
    while True:
        prev_hash = actual_block['hash_block']['prev_hash']
        actual_block = dumps(actual_block)
        actual_block = json.loads(actual_block)
        is_block_uncorrupted = verify_block_integrity(actual_block)
        if is_block_uncorrupted:
            actual_block['hash_block']['current_hash'] = actual_hash
            blockchain.append(actual_block)
        else:
            return jsonify({"message": "Existe una corrupción en la cadena de bloques, consulta a soporte técnico para mas información"}), 400
        if prev_hash is None:
            break
        else :
            actual_block = transactions_collection.find_one({"hash_block.current_hash": prev_hash})
            if actual_block is None:
                break
            actual_hash = actual_block['hash_block']['current_hash']
    if actual_hash == initial_block:
        return jsonify({"message": "Cadena de bloques recuperada correctamente.",
                        "data": blockchain}), 200
    else:
        return jsonify({"message": "Existe una corrupción en la cadena de bloques, consulta a soporte técnico para mas información"}), 400

def create_blockchain(transaction, actual_block):
    transaction_document = {
        "header_block": {
            "block_no": 0,
            "timestamp": time.time(),
            "request_ip": request.environ.get('HTTP_X_REAL_IP', request.remote_addr)
        },
        "data_block": transaction,
        "hash_block": {
            "method": "SHA256",
            "prev_hash": actual_block
        }
    }

    transaction_hash = sha256(transaction_document)

    transaction_document["hash_block"]["current_hash"] = transaction_hash
    print(transaction_document)

    transactions_collection.insert_one(transaction_document)

    return transaction_document

def verify_block_integrity(block):
    saved_hash = block["hash_block"]["current_hash"]
    del block["hash_block"]["current_hash"]
    del block['_id']

    print(block)

    actual_hash = sha256(block)

    print("Actual hash: "+actual_hash)
    print("Saved hash: "+saved_hash)

    if saved_hash == actual_hash:
        return True
    else:
        return False

if __name__ == '__main__':
    app.run(debug=True)
