from flask import Flask, request, jsonify, send_file
import psycopg2
import jwt
from datetime import datetime, timezone, timedelta
from functools import wraps
import io
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = '123'  # Substitua por uma chave segura em produção
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

# Configurações JWT
JWT_SECRET = 'sua_chave_secreta_super_forte_123!'  # Deve ser igual ao usado no PostgreSQL
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = 24

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def get_db_connection():
    return psycopg2.connect(
        host="aid.estgoh.ipc.pt",
        database="db2022145941",
        user="a2022145941",
        password="1234567890"
    )

def create_token(user_id, role):
    """Cria um token JWT válido"""
    payload = {
        'sub': str(user_id),  # Garante que o user_id é string
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'success': False, 'message': 'Token não fornecido'}), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
                
                # Configura o usuário atual na requisição
                request.current_user = {
                    'user_id': int(payload['sub']),  # Converte de volta para inteiro
                    'role': payload['role']
                }
                
                if roles and payload['role'] not in roles:
                    return jsonify({'success': False, 'message': 'Acesso não autorizado'}), 403
                
            except jwt.ExpiredSignatureError:
                return jsonify({'success': False, 'message': 'Token expirado'}), 401
            except jwt.InvalidTokenError as e:
                return jsonify({'success': False, 'message': f'Token inválido: {str(e)}'}), 401
            except Exception as e:
                return jsonify({'success': False, 'message': f'Erro ao processar token: {str(e)}'}), 500
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Endpoints de Autenticação
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    required = ['nome', 'email', 'senha', 'tipo']
    
    if not all(field in data for field in required):
        return jsonify({'success': False, 'message': 'Campos em falta'}), 400
    
    if data['tipo'] not in ['cliente', 'rececionista', 'admin']:
        return jsonify({'success': False, 'message': 'Tipo de utilizador inválido'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.callproc('registar_utilizador', [
            data['nome'],
            data['email'],
            data['senha'],
            data['tipo']
        ])
        result = cur.fetchone()[0]
        conn.commit()
        
        return jsonify(result), 201 if result['success'] else 400
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('email') or not data.get('senha'):
        return jsonify({'success': False, 'message': 'Credenciais necessárias'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.callproc('autenticar_utilizador', [data['email'], data['senha']])
        result = cur.fetchone()[0]
        
        if not result['success']:
            return jsonify(result), 401
        
        token = create_token(result['user_id'], result['tipo'])
        
        return jsonify({
            'success': True,
            'token': token,
            'user_id': result['user_id'],
            'role': result['tipo']
        }), 200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Endpoints de Reservas
@app.route('/reservas', methods=['POST'])
@token_required(roles=['cliente', 'rececionista'])
def criar_reserva():
    data = request.get_json()
    required = ['quarto_id', 'data_checkin', 'data_checkout']
    
    if not all(field in data for field in required):
        return jsonify({'success': False, 'message': 'Campos em falta'}), 400
    
    cliente_id = data.get('cliente_id', request.current_user['user_id'])
    if request.current_user['role'] == 'cliente' and cliente_id != request.current_user['user_id']:
        return jsonify({'success': False, 'message': 'Não pode criar reservas para outros clientes'}), 403
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.callproc('criar_reserva', [
            cliente_id,
            data['quarto_id'],
            data['data_checkin'],
            data['data_checkout']
        ])
        result = cur.fetchone()[0]
        conn.commit()
        
        return jsonify(result), 201 if result['success'] else 400
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/reservas/<int:reserva_id>', methods=['GET'])
@token_required()
def obter_reserva(reserva_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        if request.current_user['role'] == 'cliente':
            cur.callproc('obter_reserva_cliente', [reserva_id, request.current_user['user_id']])
        else:
            cur.callproc('obter_reserva', [reserva_id])
        
        result = cur.fetchone()[0]
        return jsonify(result), 200 if result['success'] else 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/reservas/<int:reserva_id>/cancelar', methods=['PUT'])
@token_required(roles=['cliente', 'rececionista'])
def cancelar_reserva(reserva_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        if request.current_user['role'] == 'cliente':
            cur.callproc('cancelar_reserva_cliente', [reserva_id, request.current_user['user_id']])
        else:
            cur.callproc('cancelar_reserva', [reserva_id])
        
        result = cur.fetchone()[0]
        conn.commit()
        
        return jsonify(result), 200 if result['success'] else 400
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Endpoints de Pagamentos
@app.route('/pagamentos', methods=['POST'])
@token_required(roles=['cliente', 'rececionista','admin'])
def processar_pagamento():
    data = request.get_json()
    required = ['reserva_id', 'metodo', 'valor']
    
    if not all(field in data for field in required):
        return jsonify({'success': False, 'message': 'Campos em falta'}), 400
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.callproc('processar_pagamento', [
            data['reserva_id'],
            data['metodo'],
            data['valor'],
            request.current_user['user_id']
        ])
        result = cur.fetchone()[0]
        conn.commit()
        
        return jsonify(result), 201 if result['success'] else 400
    except Exception as e:
        conn.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Endpoints de Imagens
@app.route('/upload-imagem', methods=['POST'])
@token_required(roles=['admin'])
def upload_imagem():
    if 'imagem' not in request.files:
        return jsonify({'success': False, 'message': 'Nenhuma imagem enviada'}), 400
    
    file = request.files['imagem']
    quarto_id = request.form.get('quarto_id')
    
    if not quarto_id or not file or file.filename == '':
        return jsonify({'success': False, 'message': 'Dados inválidos'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'success': False, 'message': 'Tipo de ficheiro não permitido'}), 400
    
    filename = secure_filename(file.filename)
    image_data = file.read()
    
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        # Chama a função e obtém o resultado
        cur.callproc('upload_imagem_quarto', [quarto_id, image_data, filename])
        result = cur.fetchone()[0]  # Obtém o JSON retornado
        
        if not result['success']:
            conn.rollback()
            return jsonify(result), 404
        
        conn.commit()
        return jsonify(result), 201
        
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Erro ao carregar imagem: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Erro ao processar o pedido'
        }), 500
        
    finally:
        cur.close()
        conn.close()

@app.route('/quartos/<int:quarto_id>/imagem', methods=['GET'])
def obter_imagem_quarto(quarto_id):
    conn = get_db_connection()
    cur = conn.cursor()
    
    try:
        cur.callproc('obter_imagem_quarto', [quarto_id])
        img_data = cur.fetchone()[0]
        
        if not img_data:
            return jsonify({
                'success': False,
                'message': 'Quarto não encontrado ou sem imagem'
            }), 404
            
        return send_file(
            io.BytesIO(img_data),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=f'quarto_{quarto_id}.jpg'
        ), 200
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'message': str(e)
        }), 500
        
    finally:
        cur.close()
        conn.close()
        
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)
