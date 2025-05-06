from flask import Flask, request, jsonify, send_file
from io import BytesIO
import psycopg2
import jwt
from functools import wraps
import os
from datetime import datetime, timedelta
import bcrypt
import logging

# Configuração básica de logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
# Configuração da conexão com o PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=os.environ.get('DB_HOST'),
            database=os.environ.get('DB_NAME'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASSWORD')
        )
        return conn
    except Exception as e:
        logger.error(f"Erro ao conectar ao banco de dados: {str(e)}")
        raise
    
required_env_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'SECRET_KEY']
missing_vars = [var for var in required_env_vars if not os.environ.get(var)]

if missing_vars:
    raise RuntimeError(f"Variáveis de ambiente ausentes: {', '.join(missing_vars)}")

# Decorator para verificar o token JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            token = request.headers['Authorization']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            # Remove o 'Bearer ' do token se presente
            if token.startswith('Bearer '):
                token = token[7:]
            
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            logger.error(f"Erro ao decodificar token: {str(e)}")
            return jsonify({'message': 'Token verification failed!'}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Helper para obter tipo de usuário
def get_user_type(user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT tipo_utilizador FROM Utilizador WHERE id_utilizador = %s",
            (user_id,)
        )
        
        result = cur.fetchone()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Erro ao obter tipo de usuário: {str(e)}")
        return None
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13a. Registar um novo cliente
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados não fornecidos'}), 400

    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not nome or not email or not senha:
        return jsonify({'error': 'Nome, email e senha são obrigatórios'}), 400

    try:
        # Hash da senha com bcrypt e armazenar como string
        hashed_senha = bcrypt.hashpw(senha.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "INSERT INTO Utilizador (nome_utilizador, email_utilizador, senha_utilizador, tipo_utilizador) VALUES (%s, %s, %s, 'cliente') RETURNING id_utilizador",
            (nome, email, hashed_senha)
        )
        
        user_id = cur.fetchone()[0]
        conn.commit()
        
        # Gerar token JWT
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'message': 'Usuário registrado com sucesso',
            'token': token,
            'user_id': user_id
        }), 201
        
    except psycopg2.IntegrityError:
        return jsonify({'error': 'Email já está em uso'}), 400
    except Exception as e:
        logger.error(f"Erro no registro: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13b. Autenticação de cliente
@app.route('/auth/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados não fornecidos'}), 400

    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({'error': 'Email e senha são obrigatórios'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT id_utilizador, senha_utilizador, tipo_utilizador FROM Utilizador WHERE email_utilizador = %s",
            (email,)
        )
        
        user = cur.fetchone()
        
        if not user:
            return jsonify({'error': 'Credenciais inválidas'}), 401
        
        user_id, hashed_senha_db, user_type = user
        
        # Verificar e converter o hash
        if isinstance(hashed_senha_db, memoryview):
            hashed_senha_db = bytes(hashed_senha_db)
        elif isinstance(hashed_senha_db, str):
            if not hashed_senha_db.startswith('$2b$'):
                logger.error("Formato de hash inválido armazenado")
                return jsonify({'error': 'Problema na configuração do sistema'}), 500
            hashed_senha_db = hashed_senha_db.encode('utf-8')
        
        # Verificar senha
        if not bcrypt.checkpw(senha.encode('utf-8'), hashed_senha_db):
            return jsonify({'error': 'Credenciais inválidas'}), 401
            
        # Gerar token JWT
        if not app.config['SECRET_KEY']:
            logger.error("Secret key não configurada")
            return jsonify({'error': 'Erro no servidor'}), 500
            
        token = jwt.encode({
            'user_id': user_id,
            'user_type': user_type,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'message': 'Login bem-sucedido',
            'token': token,
            'user_id': user_id,
            'user_type': user_type
        }), 200
            
    except Exception as e:
        logger.error(f"Erro no login: {str(e)}", exc_info=True)
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()
    
# 13c. Criar uma nova reserva
@app.route('/reservas', methods=['POST'])
@token_required
def criar_reserva(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados não fornecidos'}), 400

    quarto_id = data.get('quarto_id')
    data_checkin = data.get('data_checkin')
    data_checkout = data.get('data_checkout')

    if not all([quarto_id, data_checkin, data_checkout]):
        return jsonify({'error': 'Todos os campos são obrigatórios'}), 400

    try:
        # Convert string dates to date objects
        checkin_date = datetime.strptime(data_checkin, '%Y-%m-%d').date()
        checkout_date = datetime.strptime(data_checkout, '%Y-%m-%d').date()
        
        conn = get_db_connection()
        cur = conn.cursor()

        # Registrar auditoria
        cur.execute("SELECT current_user")
        db_user = cur.fetchone()[0]
        registrar_auditoria(
            db_user=db_user,
            app_user=current_user,
            acao="INSERIR RESERVA",
            detalhes=f"Quarto: {quarto_id}, Check-in: {data_checkin}, Check-out: {data_checkout}"
        )
        
        # Verificar se o quarto existe
        cur.execute("SELECT id_quarto FROM QuartoHotel WHERE id_quarto = %s", (quarto_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Quarto não encontrado'}), 404
        
        # Chamar procedure com tipos explícitos
        cur.execute("CALL criar_reserva(%s, %s, %s, %s)", 
                   (current_user, quarto_id, checkin_date, checkout_date))
        
        # Obter o ID da reserva criada
        cur.execute("SELECT lastval()")
        reserva_id = cur.fetchone()[0]
        
        conn.commit()
        
        return jsonify({
            'message': 'Reserva criada com sucesso',
            'reserva_id': reserva_id
        }), 201
        
    except ValueError:
        return jsonify({'error': 'Formato de data inválido. Use YYYY-MM-DD'}), 400
    except psycopg2.Error as e:
        conn.rollback()
        error_msg = str(e).split('\n')[0]
        return jsonify({'error': error_msg}), 400
    except Exception as e:
        logger.error(f"Erro ao criar reserva: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13d. Consultar detalhes de uma reserva
@app.route('/reservas/<int:id_reserva>', methods=['GET'])
@token_required
def consultar_reserva(current_user, id_reserva):
    try:
        user_type = get_user_type(current_user)
        if not user_type:
            return jsonify({'error': 'Tipo de usuário não encontrado'}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        
        if user_type == 'admin':
            # Admin pode ver qualquer reserva
            cur.execute("""
                SELECT r.id_reserva, r.cliente_id, u.nome_utilizador, r.quarto_id, q.numero_quarto, 
                       r.data_checkin, r.data_checkout, r.disponivel, r.valor_total
                FROM Reserva r
                JOIN Utilizador u ON r.cliente_id = u.id_utilizador
                JOIN QuartoHotel q ON r.quarto_id = q.id_quarto
                WHERE r.id_reserva = %s
            """, (id_reserva,))
        else:
            # Outros usuários só podem ver suas próprias reservas
            cur.execute("""
                SELECT r.id_reserva, r.cliente_id, u.nome_utilizador, r.quarto_id, q.numero_quarto, 
                       r.data_checkin, r.data_checkout, r.disponivel, r.valor_total
                FROM Reserva r
                JOIN Utilizador u ON r.cliente_id = u.id_utilizador
                JOIN QuartoHotel q ON r.quarto_id = q.id_quarto
                WHERE r.id_reserva = %s AND r.cliente_id = %s
            """, (id_reserva, current_user))
        
        reserva = cur.fetchone()
        
        if not reserva:
            return jsonify({'error': 'Reserva não encontrada ou não autorizada'}), 404
            
        # Converter para dicionário
        reserva_dict = {
            'id_reserva': reserva[0],
            'cliente_id': reserva[1],
            'nome_cliente': reserva[2],
            'quarto_id': reserva[3],
            'numero_quarto': reserva[4],
            'data_checkin': reserva[5].isoformat(),
            'data_checkout': reserva[6].isoformat(),
            'status': reserva[7],
            'valor_total': float(reserva[8]) if reserva[8] else None
        }
        
        return jsonify(reserva_dict), 200
        
    except Exception as e:
        logger.error(f"Erro ao consultar reserva: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13e. Processar pagamento de uma reserva
@app.route('/pagamentos', methods=['POST'])
@token_required
def processar_pagamento(current_user):
    data = request.get_json()
    if not data:
        return jsonify({'error': 'Dados não fornecidos'}), 400

    reserva_id = data.get('reserva_id')
    metodo_pagamento = data.get('metodo_pagamento')
    valor = data.get('valor')

    if not all([reserva_id, metodo_pagamento, valor]):
        return jsonify({'error': 'Todos os campos são obrigatórios'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a reserva existe e pertence ao usuário (exceto admin)
        user_type = get_user_type(current_user)
        
        if user_type != 'admin':
            cur.execute("""
                SELECT 1 FROM Reserva 
                WHERE id_reserva = %s AND cliente_id = %s
            """, (reserva_id, current_user))
            
            if not cur.fetchone():
                return jsonify({'error': 'Reserva não encontrada ou não autorizada'}), 404
        
        # Registrar o pagamento
        cur.execute("""
            INSERT INTO Pagamento (reserva_id, metodo_pagamento, valor_pagamento)
            VALUES (%s, %s, %s)
            RETURNING id_pagamento
        """, (reserva_id, metodo_pagamento, valor))
        
        payment_id = cur.fetchone()[0]
        
        # Atualizar status da reserva para 'pago'
        cur.execute("""
            UPDATE Reserva SET disponivel = 'pago' 
            WHERE id_reserva = %s
        """, (reserva_id,))
        
        conn.commit()
        
        return jsonify({
            'message': 'Pagamento processado com sucesso',
            'payment_id': payment_id
        }), 201
        
    except psycopg2.Error as e:
        conn.rollback()
        error_msg = str(e).split('\n')[0]
        return jsonify({'error': error_msg}), 400
    except Exception as e:
        logger.error(f"Erro ao processar pagamento: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13f. Cancelar uma reserva
@app.route('/reservas/<int:id_reserva>/cancelar', methods=['PUT'])
@token_required
def cancelar_reserva(current_user, id_reserva):
    try:
        user_type = get_user_type(current_user)
        if not user_type:
            return jsonify({'error': 'Tipo de usuário não encontrado'}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o usuário pode cancelar esta reserva
        if user_type == 'admin':
            # Admin pode cancelar qualquer reserva
            cur.execute("""
                SELECT cliente_id FROM Reserva WHERE id_reserva = %s
            """, (id_reserva,))
        else:
            # Outros usuários só podem cancelar suas próprias reservas
            cur.execute("""
                SELECT cliente_id FROM Reserva WHERE id_reserva = %s AND cliente_id = %s
            """, (id_reserva, current_user))
        
        reserva = cur.fetchone()
        
        if not reserva:
            return jsonify({'error': 'Reserva não encontrada ou não autorizada'}), 404
        
        # Chamar procedure PL/pgSQL para cancelar reserva (aplicando regras de negócio)
        cur.execute("CALL cancelar_reserva(%s)", (id_reserva,))
        
        conn.commit()
        return jsonify({'message': 'Reserva cancelada com sucesso'}), 200
        
    except psycopg2.Error as e:
        conn.rollback()
        error_msg = str(e).split('\n')[0]
        return jsonify({'error': error_msg}), 400
    except Exception as e:
        logger.error(f"Erro ao cancelar reserva: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13g. Upload de imagens dos quartos
@app.route('/upload-imagem', methods=['POST'])
@token_required
def upload_imagem(current_user):
    # Verificar se o usuário tem permissão (admin ou rececionista)
    user_type = get_user_type(current_user)
    if user_type not in ['admin', 'rececionista']:
        return jsonify({'error': 'Acesso não autorizado'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    quarto_id = request.form.get('quarto_id')
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not quarto_id:
        return jsonify({'error': 'Room ID is required'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se o quarto existe
        cur.execute("SELECT id_quarto FROM QuartoHotel WHERE id_quarto = %s", (quarto_id,))
        if not cur.fetchone():
            return jsonify({'error': 'Quarto não encontrado'}), 404
        
        # Lê a imagem como bytes
        imagem_bytes = file.read()
        
        # Atualiza o quarto com a nova imagem
        cur.execute(
            "UPDATE QuartoHotel SET imagem = %s WHERE id_quarto = %s",
            (psycopg2.Binary(imagem_bytes), quarto_id)
        )
        
        conn.commit()
        
        return jsonify({'message': 'Image uploaded successfully'}), 200
    
    except Exception as e:
        logger.error(f"Erro no upload de imagem: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# 13h. Recuperar imagem de um quarto
@app.route('/quartos/<int:quarto_id>/imagem', methods=['GET'])
def get_imagem(quarto_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT imagem FROM QuartoHotel WHERE id_quarto = %s",
            (quarto_id,)
        )
        
        result = cur.fetchone()
        
        if not result or not result[0]:
            return jsonify({'error': 'Image not found'}), 404
        
        imagem_bytes = result[0]
        
        return send_file(
            BytesIO(imagem_bytes),
            mimetype='image/jpeg'  # Ajuste conforme o tipo de imagem
        )
    
    except Exception as e:
        logger.error(f"Erro ao recuperar imagem: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# Endpoint para listar quartos disponíveis
@app.route('/quartos/disponiveis', methods=['GET'])
def listar_quartos_disponiveis():
    data_checkin = request.args.get('data_checkin')
    data_checkout = request.args.get('data_checkout')
    
    if not data_checkin or not data_checkout:
        return jsonify({'error': 'Datas de check-in e check-out são obrigatórias'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT q.id_quarto, q.numero_quarto, q.tipo, q.preco_quarto, q.capacidade
            FROM QuartoHotel q
            WHERE q.status_quarto = 'livre'
            AND NOT EXISTS (
                SELECT 1 FROM Reserva r
                WHERE r.quarto_id = q.id_quarto
                AND r.data_checkin < %s::date
                AND r.data_checkout > %s::date
                AND r.disponivel != 'cancelado'
            )
        """, (data_checkout, data_checkin))
        
        quartos = []
        for q in cur.fetchall():
            quartos.append({
                'id_quarto': q[0],
                'numero_quarto': q[1],
                'tipo': q[2],
                'preco_quarto': float(q[3]),
                'capacidade': q[4]
            })
        
        return jsonify(quartos), 200
        
    except Exception as e:
        logger.error(f"Erro ao listar quartos disponíveis: {str(e)}")
        return jsonify({'error': 'Erro interno no servidor'}), 500
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

def registrar_auditoria(db_user, app_user, acao, detalhes=None):
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO Auditoria (db_user, app_user, acao, detalhes) VALUES (%s, %s, %s, %s)",
            (db_user, app_user, acao, detalhes)
        )

        conn.commit()
    except Exception as e:
        logger.error(f"Erro ao registrar auditoria: {str(e)}")
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()
            
    
            

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
