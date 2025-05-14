from flask import Flask, request, jsonify, send_file
import psycopg2
from psycopg2 import sql
from functools import wraps
import jwt
import datetime
import os
from werkzeug.security import generate_password_hash, check_password_hash
import io

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'sua-chave-secreta-aqui')

# Configuração do base de dados - ajuste conforme seu ambiente
DB_CONFIG = {
    'host': 'aid.estgoh.ipc.pt',
    'database': 'db2022145941',
    'user': 'a2022145941',
    'password': '1234567890'
}

# Helper functions
def get_db_connection():
    """Estabelece conexão com o base de dados"""
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Verifica o cabeçalho 'Authorization' (padrão JWT)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]  # Remove "Bearer "
        
        if not token:
            return jsonify({'message': 'Token não fornecido!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['user_id']
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Token inválido!'}), 401
        except Exception as e:
            return jsonify({'message': 'Erro ao validar token!', 'error': str(e)}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated

# Rotas de Autenticação
@app.route('/auth/register', methods=['POST'])
def register():
    """Registar novo utilizador"""
    data = request.get_json()
    required_fields = ['nome', 'email', 'senha']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Nome, email e senha são obrigatórios!'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Chamar função PL/pgSQL para registar utilizador
        cur.callproc('registar_utilizador', (
            data['nome'],
            data['email'],
            data['senha'],
            data.get('tipo', 'cliente')
        ))
        user_id = cur.fetchone()[0]
        
        conn.commit()
        return jsonify({
            'message': 'Utilizador registado com sucesso!',
            'user_id': user_id
        }), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/auth/login', methods=['POST'])
def login():
    """Autenticar utilizador e retornar token JWT"""
    data = request.get_json()
    
    if not data or not 'email' in data or not 'senha' in data:
        return jsonify({'message': 'Email e senha são obrigatórios!'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar credenciais
        cur.execute(
            "SELECT id_utilizador, nome_utilizador, email_utilizador, tipo_utilizador, senha_utilizador "
            "FROM utilizador WHERE email_utilizador = %s",
            (data['email'],)
        )
        user = cur.fetchone()
        
        if not user:
            return jsonify({'message': 'Utilizador não encontrado!'}), 404
        
        # Verificar senha (usando pgcrypto no base)
        cur.execute(
            "SELECT senha_utilizador = crypt(%s, senha_utilizador) AS match "
            "FROM utilizador WHERE id_utilizador = %s",
            (data['senha'], user[0])
        )
        password_match = cur.fetchone()[0]
        
        if not password_match:
            return jsonify({'message': 'Senha incorreta!'}), 401
        
        # Gerar token JWT
        token = jwt.encode({
            'user_id': user[0],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'])
        
        return jsonify({
            'token': token,
            'user_id': user[0],
            'nome': user[1],
            'email': user[2],
            'tipo': user[3]
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Rotas de Quartos
@app.route('/quartos', methods=['GET'])
def get_quartos():
    """Listar todos os quartos disponíveis"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT id_quarto, numero_quarto, preco_quarto, tipo, status_quarto 
            FROM quartohotel 
            WHERE status_quarto = 'disponivel'
        """)
        quartos = cur.fetchall()
        
        result = [{
            'id': q[0],
            'numero': q[1],
            'preco': float(q[2]),
            'tipo': q[3],
            'status': q[4]
        } for q in quartos]
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/quartos/<int:quarto_id>', methods=['GET'])
def get_quarto(quarto_id):
    """Obter detalhes de um quarto específico"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("""
            SELECT id_quarto, numero_quarto, preco_quarto, tipo, status_quarto 
            FROM quartohotel 
            WHERE id_quarto = %s
        """, (quarto_id,))
        quarto = cur.fetchone()
        
        if not quarto:
            return jsonify({'message': 'Quarto não encontrado!'}), 404
        
        return jsonify({
            'id': quarto[0],
            'numero': quarto[1],
            'preco': float(quarto[2]),
            'tipo': quarto[3],
            'status': quarto[4]
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Rotas de Reservas
@app.route('/reservas', methods=['POST'])
@token_required
def criar_reserva(current_user):
    """Criar nova reserva"""
    data = request.get_json()
    required_fields = ['quarto_id', 'data_checkin', 'data_checkout']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Quarto, data de check-in e check-out são obrigatórios!'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # 1. Chamar a PROCEDURE usando CALL
        cur.execute(
            "CALL criar_reserva(%s, %s, %s, %s, NULL)",  # NULL é para o parâmetro OUT
            (current_user, data['quarto_id'], data['data_checkin'], data['data_checkout'])
        )
        
        conn.commit()
        
        return jsonify({
            'message': 'Reserva criada com sucesso!',
        }), 201
        
    except Exception as e:
        conn.rollback()
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()
        
@app.route('/reservas/<int:reserva_id>', methods=['GET'])
@token_required
def get_reserva(current_user, reserva_id):
    """Obter detalhes de uma reserva específica"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Verificar se a reserva pertence ao usuário (ou se é admin/recepcionista)
        cur.execute("""
            SELECT r.id_reserva, q.numero_quarto, q.tipo, r.data_checkin, r.data_checkout, 
                   r.disponivel, r.valor_total, r.cliente_id
            FROM reserva r
            JOIN quartohotel q ON r.quarto_id = q.id_quarto
            WHERE r.id_reserva = %s
        """, (reserva_id,))
        reserva = cur.fetchone()
        
        if not reserva:
            return jsonify({'message': 'Reserva não encontrada!'}), 404
        
        # Verificar permissões
        if reserva[7] != current_user:
            # Verificar se o usuário é admin ou recepcionista
            cur.execute("""
                SELECT tipo_utilizador FROM utilizador WHERE id_utilizador = %s
            """, (current_user,))
            user_type = cur.fetchone()[0]
            
            if user_type not in ['admin', 'rececionista']:
                return jsonify({'message': 'Não autorizado!'}), 403
        
        return jsonify({
            'id': reserva[0],
            'numero_quarto': reserva[1],
            'tipo_quarto': reserva[2],
            'data_checkin': reserva[3].isoformat(),
            'data_checkout': reserva[4].isoformat(),
            'status': reserva[5],
            'valor_total': float(reserva[6])
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/reservas/<int:reserva_id>/cancelar', methods=['PUT'])
@token_required
def cancelar_reserva(current_user, reserva_id):
    """Cancelar uma reserva"""
    data = request.get_json()
    motivo = data.get('motivo', 'Não especificado')

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Chamar procedure PL/pgSQL para cancelar reserva
        cur.callproc('cancelar_reserva', (reserva_id, current_user, motivo))
        
        conn.commit()
        return jsonify({'message': 'Reserva cancelada com sucesso!'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Rotas de Pagamentos
@app.route('/pagamentos', methods=['POST'])
@token_required
def processar_pagamento(current_user):
    """Processar pagamento de uma reserva"""
    data = request.get_json()
    required_fields = ['reserva_id', 'metodo', 'valor']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Reserva, método e valor são obrigatórios!'}), 400

    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Chamar procedure PL/pgSQL para processar pagamento
        cur.callproc('processar_pagamento', (
            data['reserva_id'],
            data['metodo'],
            data['valor']
        ))
        pagamento_id = cur.fetchone()[0]
        
        conn.commit()
        return jsonify({
            'message': 'Pagamento processado com sucesso!',
            'pagamento_id': pagamento_id
        })
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

# Rotas Administrativas

def verificar_admin(user_id):
    """Verifica se o usuário é admin"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT tipo_utilizador FROM utilizador WHERE id_utilizador = %s", (user_id,))
        user_type = cur.fetchone()
        return user_type and user_type[0] == 'admin'
    except:
        return False
    finally:
        cur.close()
        conn.close()
        
@app.route('/admin/quartos', methods=['POST'])
@token_required
def adicionar_quarto(current_user):
    """Adicionar novo quarto (apenas admin)"""
    # Verificar se o usuário é admin
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute("SELECT tipo_utilizador FROM utilizador WHERE id_utilizador = %s", (current_user,))
        user_type = cur.fetchone()[0]
        
        if user_type != 'admin':
            return jsonify({'message': 'Acesso não autorizado!'}), 403
    except:
        return jsonify({'message': 'Erro ao verificar permissões!'}), 500

    data = request.get_json()
    required_fields = ['numero', 'preco', 'tipo']
    
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Número, preço e tipo são obrigatórios!'}), 400

    try:
        # Chamar procedure PL/pgSQL para adicionar quarto
        cur.callproc('adicionar_quarto', (
            data['numero'],
            data['preco'],
            data['tipo']
        ))
        
        conn.commit()
        return jsonify({'message': 'Quarto adicionado com sucesso!'}), 201
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()
        
@app.route('/upload-imagem', methods=['POST'])
@token_required
def upload_imagem(current_user):
    """Upload de imagem para um quarto"""
    # Verificar se é admin
    if not verificar_admin(current_user):
        return jsonify({'message': 'Acesso não autorizado!'}), 403
    
    if 'file' not in request.files:
        return jsonify({'message': 'Nenhum arquivo enviado!'}), 400
    
    file = request.files['file']
    quarto_id = request.form.get('quarto_id')
    
    if file.filename == '':
        return jsonify({'message': 'Nome de arquivo vazio!'}), 400
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        # Converter imagem para bytes
        imagem_bytes = file.read()
        
        # Atualizar quarto com a imagem
        cur.execute(
            "UPDATE quartohotel SET imagem = %s WHERE id_quarto = %s",
            (psycopg2.Binary(imagem_bytes), quarto_id)
        )
        
        conn.commit()
        return jsonify({'message': 'Imagem atualizada com sucesso!'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/quartos/<int:quarto_id>/imagem', methods=['GET'])
def get_imagem_quarto(quarto_id):
    """Obter imagem de um quarto"""
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT imagem FROM quartohotel WHERE id_quarto = %s",
            (quarto_id,))
        imagem = cur.fetchone()[0]
        
        if not imagem:
            return jsonify({'message': 'Imagem não encontrada!'}), 404
        
        return send_file(
            io.BytesIO(imagem),
            mimetype='image/jpeg'  # Ajustar conforme tipo real
        )
    except Exception as e:
        return jsonify({'message': str(e)}), 500
    finally:
        cur.close()
        conn.close()

@app.route('/quartos/disponibilidade', methods=['GET'])
def verificar_disponibilidade():
    quarto_id = request.args.get('quarto_id')
    checkin = request.args.get('checkin')
    checkout = request.args.get('checkout')
    
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        
        cur.execute(
            "SELECT verificar_disponibilidade(%s, %s, %s)",
            (quarto_id, checkin, checkout)
        )
        result = cur.fetchone()[0]
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()

if __name__ == '__main__':
    app.run(debug=True)
