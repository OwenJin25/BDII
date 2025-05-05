from flask import Flask, request, jsonify
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required,
    get_jwt_identity
)
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import timedelta
import os
from dotenv import load_dotenv

# Carregar variáveis de ambiente
load_dotenv()

app = Flask(__name__)

# Configuração do JWT
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', '123')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)
jwt = JWTManager(app)

# Configuração do PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv('DB_HOST', 'aid.estgoh.ipc.pt'),
            database=os.getenv('DB_NAME', 'db2022145941'),
            user=os.getenv('DB_USER', 'a2022145941'),
            password=os.getenv('DB_PASSWORD', '1234567890'),
            cursor_factory=RealDictCursor
        )
        return conn
    except psycopg2.Error as e:
        app.logger.error(f"Erro ao conectar ao PostgreSQL: {e}")
        return None

# Helper para chamar funções no PostgreSQL
def call_db_function(func_name, args):
    conn = None
    try:
        conn = get_db_connection()
        if not conn:
            return {'error': 'Erro de conexão com o banco de dados', 'status': 500}
        
        with conn.cursor() as cur:
            cur.callproc(func_name, args)
            if cur.description:
                result = cur.fetchone()
                if result:
                    return dict(result)
            return None
    except psycopg2.Error as e:
        app.logger.error(f"Erro na função {func_name}: {e}")
        return {'error': str(e), 'status': 500}
    finally:
        if conn:
            conn.close()

## Endpoints Públicos ##

@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados JSON inválidos', 'status': 400}), 400
    
    required_fields = ['nome', 'email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Campos obrigatórios faltando', 'status': 400}), 400
    
    result = call_db_function('registar_cliente', [
        data['nome'],
        data['email'],
        data['password']
    ])
    
    if 'error' in result:
        return jsonify(result), result.get('status', 500)
    
    return jsonify({
        'success': True,
        'message': 'Utilizador registado com sucesso',
        'user_id': result['id_utilizador'],
        'status': 201
    }), 201

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados JSON inválidos', 'status': 400}), 400
    
    required_fields = ['email', 'password']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Campos obrigatórios faltando', 'status': 400}), 400
    
    # Verificar credenciais no PostgreSQL
    user = call_db_function('verificar_credenciais', [
        data['email'],
        data['password']
    ])
    
    if not user or 'error' in user:
        app.logger.warning(f"Tentativa de login falhou para {data['email']}")
        return jsonify({'error': 'Credenciais inválidas', 'status': 401}), 401
    
    # Gerar token JWT
    access_token = create_access_token(identity={
        'id': user['id_utilizador'],
        'email': user['email_utilizador'],
        'perfil': user['tipo_utilizador']
    })
    
    return jsonify({
        'access_token': access_token,
        'user': {
            'id': user['id_utilizador'],
            'email': user['email_utilizador'],
            'perfil': user['tipo_utilizador']
        },
        'status': 200
    }), 200

## Endpoints Protegidos ##

@app.route('/reservas', methods=['POST'])
@jwt_required()
def criar_reserva():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados JSON inválidos', 'status': 400}), 400
    
    required_fields = ['quarto_id', 'data_entrada', 'data_saida']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Campos obrigatórios faltando', 'status': 400}), 400
    
    try:
        result = call_db_function('criar_reserva', [
            current_user['id'],
            int(data['quarto_id']),
            data['data_entrada'],
            data['data_saida']
        ])
    except ValueError:
        return jsonify({'error': 'ID do quarto inválido', 'status': 400}), 400
    
    if 'error' in result:
        return jsonify(result), result.get('status', 500)
    
    return jsonify(result), 201

@app.route('/reservas/<int:reserva_id>', methods=['GET'])
@jwt_required()
def consultar_reserva(reserva_id):
    current_user = get_jwt_identity()
    
    result = call_db_function('consultar_reserva', [
        reserva_id,
        current_user['id'],
        current_user['perfil']
    ])
    
    if 'error' in result:
        return jsonify(result), result.get('status', 500)
    
    return jsonify(result), 200

@app.route('/pagamentos', methods=['POST'])
@jwt_required()
def processar_pagamento():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'Dados JSON inválidos', 'status': 400}), 400
    
    required_fields = ['reserva_id', 'metodo_pagamento', 'valor']
    if not all(field in data for field in required_fields):
        return jsonify({'error': 'Campos obrigatórios faltando', 'status': 400}), 400
    
    try:
        result = call_db_function('processar_pagamento', [
            int(data['reserva_id']),
            data['metodo_pagamento'],
            float(data['valor']),
            current_user['id'],
            current_user['perfil']
        ])
    except (ValueError, TypeError):
        return jsonify({'error': 'Dados inválidos', 'status': 400}), 400
    
    if 'error' in result:
        return jsonify(result), result.get('status', 500)
    
    return jsonify(result), 200

@app.route('/reservas/<int:reserva_id>/cancelar', methods=['PUT'])
@jwt_required()
def cancelar_reserva(reserva_id):
    current_user = get_jwt_identity()
    
    result = call_db_function('cancelar_reserva', [
        reserva_id,
        current_user['id'],
        current_user['perfil']
    ])
    
    if 'error' in result:
        return jsonify(result), result.get('status', 500)
    
    return jsonify(result), 200

@app.route('/quartos/<int:quarto_id>/imagem', methods=['GET'])
@jwt_required()
def obter_imagem_quarto(quarto_id):
    current_user = get_jwt_identity()
    
    try:
        conn = get_db_connection()
        if not conn:
            return jsonify({'error': 'Erro de conexão com o banco de dados', 'status': 500}), 500
            
        with conn.cursor() as cur:
            cur.callproc('obter_imagem_quarto', [
                quarto_id,
                current_user['id'],
                current_user['perfil']
            ])
            result = cur.fetchone()
            if not result:
                return jsonify({'error': 'Imagem não encontrada', 'status': 404}), 404
            
            imagem = result['imagem'] if 'imagem' in result else result[0]
            return app.response_class(imagem, mimetype='image/jpeg')
    except Exception as e:
        app.logger.error(f"Erro ao obter imagem: {e}")
        return jsonify({'error': str(e), 'status': 500}), 500
    finally:
        if conn:
            conn.close()

@app.route('/upload-imagem', methods=['POST'])
@jwt_required()
def upload_imagem():
    current_user = get_jwt_identity()
    
    if 'file' not in request.files:
        return jsonify({'error': 'Nenhum ficheiro enviado', 'status': 400}), 400
    
    file = request.files['file']
    quarto_id = request.form.get('quarto_id')
    
    if not quarto_id:
        return jsonify({'error': 'ID do quarto não especificado', 'status': 400}), 400
    
    try:
        quarto_id = int(quarto_id)
    except ValueError:
        return jsonify({'error': 'ID do quarto inválido', 'status': 400}), 400
    
    try:
        imagem_bytes = file.read()
        if len(imagem_bytes) > 5 * 1024 * 1024:  # 5MB
            return jsonify({'error': 'Imagem demasiado grande (máx. 5MB)', 'status': 400}), 400
            
        tipo_imagem = file.content_type
        if tipo_imagem not in ['image/jpeg', 'image/png']:
            return jsonify({'error': 'Tipo de imagem não suportado', 'status': 400}), 400
        
        result = call_db_function('upload_imagem_quarto', [
            quarto_id,
            imagem_bytes,
            tipo_imagem,
            current_user['id'],
            current_user['perfil']
        ])
        
        if 'error' in result:
            return jsonify(result), result.get('status', 500)
        
        return jsonify(result), 200
    except Exception as e:
        app.logger.error(f"Erro no upload: {e}")
        return jsonify({'error': str(e), 'status': 500}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
