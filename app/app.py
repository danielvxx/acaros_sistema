from flask import Flask, request, jsonify, render_template
from py2neo import Graph, DatabaseError, ClientError
from datetime import datetime
import logging
import sys
import qrcode
from io import BytesIO
import base64
from flask import send_file
from flask import jsonify
from datetime import datetime as dt, date
from neo4j.time import Date as Neo4jDate
import os
from werkzeug.utils import secure_filename
import uuid
import json
from os import environ
from time import sleep
from py2neo import Graph, DatabaseError
from dotenv import load_dotenv
import os
from flask import Flask, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Configuração da aplicação Flask
app = Flask(__name__)

app.secret_key = 'sua_chave_secreta_muito_segura'

# Dados de usuários em memória (substituir por DB depois se necessário)
USERS = {
    'admin': {
        'password': generate_password_hash('admin123'),
        'role': 'admin'
    },
    'usuario': {
        'password': generate_password_hash('senha123'),
        'role': 'user'
    }
}

# Decorator para rotas protegidas
def login_required(role="user"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'username' not in session:
                flash('Faça login para acessar esta página', 'warning')
                return redirect(url_for('login'))
            
            if role != "user" and USERS.get(session['username'], {}).get('role') != role:
                flash('Acesso não autorizado', 'danger')
                return redirect(url_for('login'))
                
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Rotas de Autenticação
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = USERS.get(username)
        
        if user and check_password_hash(user['password'], password):
            session['username'] = username
            session['role'] = user['role']
            flash('Login realizado com sucesso!', 'success')
            return redirect(url_for('menu_colonia', codigo_colonia='default'))
        
        flash('Usuário ou senha incorretos', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você foi desconectado', 'info')
    return redirect(url_for('login'))

# Rotas Protegidas
@app.route('/colonia/<codigo_colonia>')
@login_required()
def menu_colonia(codigo_colonia):
    return render_template('menu.html', 
                         colonia={'codigo_colonia': codigo_colonia},
                         username=session.get('username'))

@app.route('/admin')
@login_required(role="admin")
def admin_panel():
    return render_template('admin.html', users=USERS)

# Rota de erro
@app.errorhandler(404)
def page_not_found(e):
    return render_template('erro.html', mensagem='Página não encontrada'), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    
# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("AcarosQR")


# Adicione esta configuração no início do arquivo, após a criação do app Flask
UPLOAD_FOLDER = environ.get('UPLOAD_FOLDER', '/app/analises')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Configuração da conexão com o Neo4j
max_retries = 10
retry_delay = 5

for i in range(max_retries):
    try:
        load_dotenv()  # Carrega variáveis do .env

        graph = Graph(
        os.getenv('NEO4J_BOLT_URL'),
        auth=(os.getenv('NEO4J_USER'), os.getenv('NEO4J_PASSWORD')),
        secure=False
        )
        graph.run("RETURN 1 AS test").data()
        logger.info("Conexão com Neo4j estabelecida com sucesso")
        break
    except Exception as e:
        logger.warning(f"Tentativa {i+1}/{max_retries} - Falha na conexão com Neo4j: {str(e)}")
        if i == max_retries - 1:
            logger.critical("Número máximo de tentativas excedido. Encerrando aplicação.")
            sys.exit(1)
        sleep(retry_delay)

class Neo4jJSONEncoder(json.JSONEncoder):
    """Encoder personalizado para lidar com tipos do Neo4j"""
    def default(self, obj):
        if isinstance(obj, (dt, date, Neo4jDate)):
            return obj.isoformat()
        elif hasattr(obj, '__dict__'):
            return obj.__dict__
        return super().default(obj)

# Configurar Flask para usar nosso encoder
app.json_encoder = Neo4jJSONEncoder

from datetime import datetime, date, timedelta

@app.route('/colonia/<codigo_colonia>', methods=['GET'])
def menu_colonia(codigo_colonia):
    # Consulta principal da colônia
    colonia_result = graph.run("""
        MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
        RETURN c
    """, codigo_colonia=codigo_colonia).data()

    # Consulta do histórico corrigida
    historico_result = graph.run("""
        MATCH (c:Colonia {codigo_colonia: $codigo_colonia})-[:SOFREU_CONTAMINACAO]->(cont)
        RETURN {
            data_inicio: cont.data,
            data_resolucao: cont.data_resolucao,
            especie_original: c.especie,
            contaminante: cont.especie,
            especie_prevaleceu: cont.especie_prevaleceu,
            status: cont.status
        } AS historico
        ORDER BY cont.data DESC
    """, codigo_colonia=codigo_colonia).data()

    # Log para depuração
    logger.info(f"Histórico de contaminações encontrado: {len(historico_result)} registros")
    
    # Processar resultados
    colonia_data = dict(colonia_result[0]['c'])
    historico_processado = []
    
    for h in historico_result:
        historico = h['historico']
        # Converter Neo4jDate para string se necessário
        if hasattr(historico['data_inicio'], 'to_native'):
            historico['data_inicio'] = str(historico['data_inicio'])
        if hasattr(historico['data_resolucao'], 'to_native'):
            historico['data_resolucao'] = str(historico['data_resolucao'])
        historico_processado.append(historico)
    
    colonia_data['historico_contaminacoes'] = historico_processado

    # Buscar lotes de ração disponíveis
    racoes = graph.run("MATCH (r:Racao) RETURN r.lote as lote ORDER BY r.data_producao DESC").data()
    
    # Calcular tempo de atividade
    try:
        data_inicio = colonia_data['data_inicio']
        
        # Converter para objeto date se necessário
        if isinstance(data_inicio, str):
            data_inicio = datetime.strptime(data_inicio, "%Y-%m-%d").date()
        elif hasattr(data_inicio, 'to_native'):  # Para objetos Neo4jDate
            data_inicio = data_inicio.to_native()
            
        # Calcular dias de atividade
        if colonia_data.get('status') == 'inativa':
            data_fim_str = colonia_data.get('data_desativacao')
            if data_fim_str:
                if isinstance(data_fim_str, str):
                    data_fim = datetime.strptime(data_fim_str, "%Y-%m-%d").date()
                elif hasattr(data_fim_str, 'to_native'):
                    data_fim = data_fim_str.to_native()
                else:
                    data_fim = date.today()
            else:
                data_fim = date.today()
            dias_ativa = (data_fim - data_inicio).days
        else:
            dias_ativa = (date.today() - data_inicio).days
            
        colonia_data['dias_ativa'] = dias_ativa
    except Exception as e:
        logger.error(f"Erro ao calcular dias de atividade: {str(e)}")
        colonia_data['dias_ativa'] = "N/A"


    # --- LÓGICA DE HIERARQUIA PARA 3 GERAÇÕES (MAE, AVO, FILHAS) ---
    hierarquia_data = {
        'mae': None,
        'avo': None,
        'filhas': []
    }
    try:
        # Usando o mesmo relacionamento que em visualizar_analise
        hierarquia_result = graph.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia_atual})
            OPTIONAL MATCH (c)<-[:ORIGEM_DE]-(mae:Colonia)
            OPTIONAL MATCH (mae)<-[:ORIGEM_DE]-(avo:Colonia)
            OPTIONAL MATCH (c)-[:ORIGEM_DE]->(filhas:Colonia)
            RETURN mae, avo, collect(filhas) as filhas
        """, codigo_colonia_atual=colonia_data['codigo_colonia']).data()

        if hierarquia_result:
            result = hierarquia_result[0]
            if result['mae']:
                hierarquia_data['mae'] = dict(result['mae'])
            if result['avo']:
                hierarquia_data['avo'] = dict(result['avo'])
            hierarquia_data['filhas'] = [dict(f) for f in result['filhas'] if f is not None]

    except Exception as e:
        logger.error(f"Erro ao buscar dados da hierarquia da colônia {codigo_colonia}: {e}")
    # --- FIM DA LÓGICA DE HIERARQUIA ---

    return render_template('menu_colonia.html',
                     colonia=colonia_data,
                     historico_contaminacoes=colonia_data.get('historico_contaminacoes', []),
                     hierarquia=hierarquia_data,
                     racoes=racoes) 



@app.route('/colonia/<codigo_colonia>/realimentar', methods=['POST'])
def registrar_realimentacao(codigo_colonia):
    """Endpoint para registrar realimentação de uma colônia"""
    tx = None
    try:
        data = request.form
        params = {
            'codigo_colonia': codigo_colonia,
            'lote_racao': data.get('lote_racao'),
            'observacoes': data.get('observacoes', 'Realimentação via QR code'),
            'data_evento': data.get('data_evento', datetime.now().strftime("%Y-%m-%d"))
        }

        if not params['lote_racao']:
            return jsonify({'status': 'error', 'message': 'Parâmetro obrigatório: lote_racao'}), 400

        racao_existe = graph.evaluate(
            "MATCH (r:Racao {lote: $lote}) RETURN count(r) > 0",
            {'lote': params['lote_racao']}
        )
        if not racao_existe:
            return jsonify({'status': 'error', 'message': f'Lote de ração {params["lote_racao"]} não encontrado'}), 404

        tx = graph.begin()
        resultado = tx.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
            MATCH (r:Racao {lote: $lote_racao})
            CREATE (c)-[:REALIMENTACAO {
                data: date($data_evento),
                lote_utilizado: $lote_racao
            }]->(e:Evento {
                nome: "Realimentação",
                tipo: "realimentacao",
                descricao: $observacoes,
                data_evento: date($data_evento),
                data_registro: datetime()
            })
            CREATE (e)-[:USOU_RACAO]->(r)
            RETURN c.codigo_colonia AS colonia, r.lote AS lote, e.elementId AS evento_id
        """, params)

        dados = resultado.data()[0]
        tx.commit()

        logger.info("Realimentação registrada: %s", dados)
        return jsonify({
            'status': 'success',
            'data': {
                'colonia': dados['colonia'],
                'evento_id': dados['evento_id'],
                'lote_racao': dados['lote'],
                'timestamp': datetime.now().isoformat()
            }
        })

    except ClientError as e:
        logger.error("Erro no Cypher: %s", str(e))
        if tx:
            tx.rollback()
        return jsonify({
            'status': 'error',
            'code': e.code,
            'message': 'Erro na operação do banco de dados',
            'detalhes': str(e).split('\n', 1)[0]
        }), 400

    except Exception as e:
        logger.critical("Erro inesperado: %s", str(e))
        if tx:
            tx.rollback()
        return jsonify({'status': 'error', 'message': 'Erro interno no servidor'}), 500
    

@app.route('/colonia/<codigo_colonia>/registrar_contaminacao', methods=['POST'])
def registrar_contaminacao(codigo_colonia):
    try:
        data = request.get_json()
        contaminacao_id = str(uuid.uuid4())
        
        resultado = graph.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
            CREATE (cont:Contaminacao {
                id: $contaminacao_id,
                especie: $especie_contaminante,
                data: date($data_contaminacao),
                status: 'ativa'
            })
            CREATE (c)-[:SOFREU_CONTAMINACAO]->(cont)
            SET c.contaminada_por = $especie_contaminante,
                c.status_contaminacao = 'ativa'
            RETURN cont
        """, {
            'codigo_colonia': codigo_colonia,
            'contaminacao_id': contaminacao_id,
            'especie_contaminante': data.get('especie_contaminante'),
            'data_contaminacao': data.get('data_contaminacao', datetime.now().strftime("%Y-%m-%d"))
        }).data()

        # Converter objetos Neo4j para dicionário serializável
        cont_data = dict(resultado[0]['cont'])
        
        # Converter objetos de data para string
        for key, value in cont_data.items():
            if hasattr(value, 'isoformat'):  # Para objetos date/datetime
                cont_data[key] = value.isoformat()
            elif isinstance(value, Neo4jDate):  # Para objetos Date do Neo4j
                cont_data[key] = str(value)

        return jsonify({
            'status': 'success',
            'data': cont_data
        })

    except Exception as e:
        logger.error(f"Erro ao registrar contaminação: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/colonia/<codigo_colonia>/registrar_prevalencia', methods=['POST'])
def registrar_prevalencia(codigo_colonia):
    try:
        data = request.get_json()
        
        resultado = graph.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
            MATCH (c)-[r:SOFREU_CONTAMINACAO]->(cont:Contaminacao {status: 'ativa'})
            SET cont.status = 'resolvida',
                cont.especie_prevaleceu = $especie_prevaleceu,
                cont.data_resolucao = date($data_resolucao),
                c.especie = $especie_prevaleceu,
                c.status_contaminacao = 'resolvida'
            RETURN c, cont
        """, {
            'codigo_colonia': codigo_colonia,
            'especie_prevaleceu': data.get('especie_prevaleceu'),
            'data_resolucao': data.get('data_resolucao')
        }).data()

        cont_data = dict(resultado[0]['cont'])
        # Converter datas para string
        for key, value in cont_data.items():
            if hasattr(value, 'isoformat'):
                cont_data[key] = value.isoformat()

        return jsonify({
            'status': 'success',
            'data': cont_data
        })

    except Exception as e:
        logger.error(f"Erro ao registrar prevalência: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    
    
@app.route('/analise/<analise_id>/qr_code')
def gerar_qr_code_analise(analise_id):
    """Gera QR code para uma análise específica"""
    try:
        url = f"{request.host_url}analise/{analise_id}"
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(url)
        qr.make(fit=True)
        img = qr.make_image(fill='black', back_color='white')
        
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)
        
        return send_file(buffer, mimetype='image/png')
        
    except Exception as e:
        logger.error(f"Erro ao gerar QR code: {str(e)}")
        return render_template('erro.html', mensagem='Erro ao gerar QR code'), 500
    
from flask import jsonify
from datetime import date, datetime


@app.route('/colonia/<codigo_colonia>/listar_amostras', methods=['GET'])
def listar_amostras(codigo_colonia):
    try:
        # Query corrigida com agrupamento adequado
        query = """
            MATCH (c:Colonia {codigo_colonia: $codigo})-[:COLETOU_AMOSTRA]->(a:Amostra)
            OPTIONAL MATCH (a)-[:FOI_ANALISADA_POR]->(an:Analise)
            WITH 
                a,
                COALESCE(a.id_amostra, elementId(a)) AS id_amostra,
                elementId(a) AS element_id,
                toString(a.data_coleta) AS data_coleta,
                COALESCE(a.local_amostragem, []) AS local,
                COALESCE(a.status, 'aguardando análise') AS status,
                collect(an.id_analise) AS ids_analise
            RETURN 
                id_amostra,
                element_id,
                data_coleta,
                local,
                status,
                CASE WHEN size(ids_analise) > 0 THEN 'analisada' ELSE 'aguardando análise' END AS status_analise,
                ids_analise
            ORDER BY data_coleta DESC
        """
        
        resultados = graph.run(query, {'codigo': codigo_colonia}).data()

        # Processar resultados para facilitar uso no frontend
        for amostra in resultados:
            amostra['ids_analise'] = [id for id in amostra['ids_analise'] if id is not None]
            amostra['tem_analise'] = len(amostra['ids_analise']) > 0

        return jsonify({
            'status': 'success',
            'data': resultados
        }), 200
    except Exception as e:
        logger.error(f"Erro ao listar amostras: {str(e)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Erro ao recuperar amostras',
            'detalhes': str(e)
        }), 500
    

    
@app.route('/analise/<analise_id>', methods=['GET'])
def visualizar_analise(analise_id):
    """Endpoint para visualizar uma análise específica"""
    try:
        # Query corrigida com direção de relacionamento invertida
        query = """
            MATCH (an:Analise)
            WHERE an.id_analise = $id_analise
            OPTIONAL MATCH (an)<-[:FOI_ANALISADA_POR]-(a:Amostra)
            OPTIONAL MATCH (c:Colonia)-[:COLETOU_AMOSTRA]->(a)
            OPTIONAL MATCH (c)<-[:ORIGEM_DE]-(mae:Colonia)
            OPTIONAL MATCH (mae)<-[:ORIGEM_DE]-(avo:Colonia)
            OPTIONAL MATCH (c)-[:ORIGEM_DE]->(filhas:Colonia)
            RETURN 
                properties(an) as analise,
                properties(c) as colonia,
                properties(a) as amostra,
                properties(mae) as mae,
                properties(avo) as avo,
                [f in collect(filhas) | properties(f)] as filhas
        """
        resultado = graph.run(query, {'id_analise': analise_id}).data()
        
        if not resultado:
            logger.warning(f"Análise {analise_id} não encontrada")
            return render_template('erro.html', mensagem='Análise não encontrada'), 404
        
        dados = resultado[0]
        
        # Função para converter nós Neo4j em dicionários
        def node_to_dict(node):
            if not node:
                return None
            return dict(node)
        
        # Processar dados principais
        analise_data = node_to_dict(dados['analise'])
        amostra_data = node_to_dict(dados['amostra'])
        colonia_data = node_to_dict(dados['colonia'])
        
        # Se colônia não veio na query principal, tentar buscar diretamente
        if not colonia_data and amostra_data:
            colonia_query = """
                MATCH (c:Colonia)-[:COLETOU_AMOSTRA]->(a:Amostra)
                WHERE a.id_amostra = $amostra_id OR elementId(a) = $amostra_id
                RETURN properties(c) as colonia
            """
            amostra_id = amostra_data.get('id_amostra') or amostra_data.get('elementId')
            if amostra_id:
                colonia_result = graph.run(colonia_query, {'amostra_id': amostra_id}).data()
                if colonia_result:
                    colonia_data = node_to_dict(colonia_result[0]['colonia'])
        
        # Se ainda não tiver colônia, mostrar erro
        if not colonia_data:
            logger.error(f"Colônia não encontrada para análise {analise_id}")
            return render_template(
                'erro.html', 
                mensagem='Colônia associada não encontrada, mas análise existe'
            ), 500
        
        # Processar hierarquia
        hierarquia = {
            'mae': node_to_dict(dados['mae']),
            'avo': node_to_dict(dados['avo']),
            'filhas': [node_to_dict(f) for f in dados['filhas']] if dados['filhas'] else []
        }
        
        # Processar fotos
        fotos_processadas = []
        if analise_data and 'caminho_fotos' in analise_data:
            caminho_fotos = analise_data['caminho_fotos']
            if caminho_fotos:
                for foto in caminho_fotos.split(';'):
                    if foto.strip():
                        foto_path = foto.strip().replace(app.config['UPLOAD_FOLDER'], '').lstrip('/\\').replace('\\', '/')
                        fotos_processadas.append(foto_path)
        
        return render_template('visualizar_analise.html',
                            analise=analise_data,
                            colonia=colonia_data,
                            amostra=amostra_data,
                            hierarquia=hierarquia,
                            fotos=fotos_processadas,
                            qr_code_url=f"{request.host_url}analise/{analise_id}/qr_code")
        
    except Exception as e:
        logger.error(f"Erro ao visualizar análise {analise_id}: {str(e)}", exc_info=True)
        return render_template('erro.html', mensagem=f'Erro ao carregar análise: {str(e)}'), 500
    
@app.route('/colonia/<codigo_colonia>/coletar_amostra', methods=['POST'])
def registrar_coleta_amostra(codigo_colonia):
    """Endpoint para registrar coleta de amostra"""
    tx = None
    try:
        data = request.form
        id_amostra = str(uuid.uuid4())  # Gerar ID único para a amostra
        params = {
            'codigo_colonia': codigo_colonia,
            'id_amostra': id_amostra,
            'local_amostragem': data.getlist('local_amostragem'),
            'excipiente': data.get('excipiente'),
            'observacoes': data.get('observacoes', 'Coleta de amostra para análise'),
            'data_coleta': data.get('data_coleta', datetime.now().strftime("%Y-%m-%d")),
            'status': 'aguardando análise'
        }

        if not all([params['local_amostragem'], params['excipiente']]):
            return jsonify({
                'status': 'error',
                'message': 'Parâmetros obrigatórios: local_amostragem e excipiente'
            }), 400

        tx = graph.begin()
        resultado = tx.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
            CREATE (a:Amostra {
                id_amostra: $id_amostra,
                local_amostragem: $local_amostragem,
                excipiente: $excipiente,
                observacoes: $observacoes,
                data_coleta: date($data_coleta),
                data_registro: datetime(),
                status: $status
            })
            CREATE (c)-[:COLETOU_AMOSTRA]->(a)
            RETURN c.codigo_colonia AS colonia, a.id_amostra AS amostra_id, elementId(a) AS element_id
        """, params)

        dados = resultado.data()[0]
        tx.commit()

        logger.info("Coleta de amostra registrada: %s", dados)
        return jsonify({
            'status': 'success',
            'data': {
                'colonia': dados['colonia'],
                'amostra_id': dados['amostra_id'],
                'element_id': dados['element_id'],
                'timestamp': datetime.now().isoformat()
            }
        })
    

    except Exception as e:
        logger.error("Erro ao registrar coleta: %s", str(e))
        if tx:
            tx.rollback()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
    

@app.route('/colonia/<codigo_colonia>/registrar_analise', methods=['POST'])
def registrar_analise(codigo_colonia):
    tx = None
    try:
        request_id = request.headers.get('X-Request-ID') or request.form.get('request_id')
        if not request_id:
            logger.warning("Requisição sem ID único detectada")
            return jsonify({
                'status': 'error',
                'message': 'Requisição sem identificador único'
            }), 400

        amostra_id = request.form.get('amostra_id')
        if not amostra_id:
            return jsonify({
                'status': 'error',
                'message': 'Parâmetro obrigatório: amostra_id'
            }), 400

        # Verificar se já existe análise recente para esta amostra
        existe_analise = graph.evaluate("""
            MATCH (a:Amostra)-[:FOI_ANALISADA_POR]->(an:Analise)
            WHERE (a.id_amostra = $amostra_id OR elementId(a) = $amostra_id)
            RETURN count(an) > 0
        """, amostra_id=amostra_id)

        if existe_analise:
            return jsonify({
                'status': 'error',
                'message': 'Já existe uma análise registrada para esta amostra'
            }), 400

        # Processar upload de fotos
        fotos_paths = []
        if 'fotos_analise' in request.files:
            for file in request.files.getlist('fotos_analise'):
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                    filepath = os.path.join(
                        app.config['UPLOAD_FOLDER'],
                        codigo_colonia,
                        datetime.now().strftime("%y-%m-%d"),
                        filename
                    )
                    os.makedirs(os.path.dirname(filepath), exist_ok=True)
                    file.save(filepath)
                    fotos_paths.append(os.path.join(
                        codigo_colonia,
                        datetime.now().strftime("%y-%m-%d"),
                        filename
                    ))

        # Gerar ID único
        id_publico = str(uuid.uuid4())
        
        # Query corrigida
        query = """
            MATCH (a:Amostra)
            WHERE a.id_amostra = $amostra_id OR elementId(a) = $amostra_id
            CREATE (a)-[:FOI_ANALISADA_POR]->(an:Analise {
                id_analise: $id_publico,
                data_analise: date($data_analise),
                estagio_desenvolvimento: $estagio,
                caminho_fotos: $fotos,
                observacoes: $obs,
                data_coleta: datetime()
            })
            SET a.status = 'analisada'
            RETURN elementId(an) as analise_id, an.id_analise as id_publico
            LIMIT 1
        """
        
        # Executar em transação única
        tx = graph.begin()
        resultado = tx.run(query, {
            'amostra_id': amostra_id,
            'id_publico': id_publico,
            'data_analise': request.form.get('data_analise', datetime.now().strftime("%Y-%m-%d")),
            'estagio': request.form.get('estagio_desenvolvimento', ''),
            'fotos': ';'.join(fotos_paths) if fotos_paths else None,
            'obs': request.form.get('observacoes', '')
        }).data()  # Alterado de single() para data()

        if not resultado:
            raise ValueError("Nenhum resultado retornado pela query")

        dados = resultado[0]
        graph.commit(tx)

        # Gerar QR Code
        img = qrcode.make(f"{request.host_url}analise/{id_publico}")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code = base64.b64encode(buffer.getvalue()).decode('utf-8')

        return jsonify({
            'status': 'success',
            'data': {
                'analise_id': dados['analise_id'],
                'id_publico': id_publico,
                'qr_code_base64': qr_code,
                'analise_url': f"{request.host_url}analise/{id_publico}",
                'fotos': fotos_paths,
                'timestamp': datetime.now().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Erro ao registrar análise [ID: {request_id}]: {str(e)}", exc_info=True)
        if tx:
            graph.rollback(tx)
        return jsonify({
            'status': 'error',
            'message': 'Erro interno ao registrar análise',
            'request_id': request_id
        }), 500

@app.before_request
def log_requests():
    if request.path.endswith('registrar_analise') and request.method == 'POST':
        logger.info(f"Requisição recebida para {request.path} - ID: {request.headers.get('X-Request-ID')}")
    
@app.route('/analise/fotos/<path:filename>')
def servir_foto(filename):
    try:
        # Construir caminho seguro
        safe_path = os.path.join(app.config['UPLOAD_FOLDER'], filename.lstrip('/'))
        safe_path = os.path.abspath(safe_path)
        
        # Verificar se está dentro da pasta permitida
        if not safe_path.startswith(os.path.abspath(app.config['UPLOAD_FOLDER'])):
            return render_template('erro.html', mensagem='Acesso não permitido'), 403
        
        if not os.path.isfile(safe_path):
            return render_template('erro.html', mensagem='Foto não encontrada'), 404
        
        return send_file(safe_path)
    except Exception as e:
        logger.error(f"Erro ao servir foto: {str(e)}")
        return render_template('erro.html', mensagem='Erro ao carregar foto'), 500

@app.route('/colonia/<codigo_colonia>/criar_derivada', methods=['GET', 'POST'])
def criar_colonia_derivada(codigo_colonia):
    """Endpoint para criar uma colônia derivada de outra"""
    if request.method == 'GET':
        try:
            colonia_mae = graph.run(
                "MATCH (c:Colonia {codigo_colonia: $codigo}) RETURN c",
                {'codigo': codigo_colonia}
            ).data()
            
            if not colonia_mae:
                return render_template('erro.html', mensagem=f'Colônia mãe {codigo_colonia} não encontrada'), 404

            racoes = graph.run(
                "MATCH (r:Racao) RETURN r.lote as lote ORDER BY r.data_producao DESC"
            ).data()
            
            return render_template(
                'criar_derivada.html',
                colonia_mae=colonia_mae[0]['c'],
                racoes=racoes
            )
        
        except Exception as e:
            logger.error(f"Erro ao buscar dados para criação de colônia derivada: {str(e)}")
            return render_template('erro.html', mensagem='Erro interno no servidor'), 500
    
    elif request.method == 'POST':
        tx = None
        try:
            data = request.form
            params = {
                'codigo_mae': codigo_colonia,
                'codigo_filha': data.get('codigo_filha'),
                'data_inicio': data.get('data_inicio', datetime.now().strftime("%Y-%m-%d")),
                'lote_racao': data.get('lote_racao'),
                'observacoes': data.get('observacoes', 'Colônia derivada criada via sistema')
            }

            if not all([params['codigo_filha'], params['lote_racao']]):
                return jsonify({'status': 'error', 'message': 'Parâmetros obrigatórios: codigo_filha e lote_racao'}), 400

            tx = graph.begin()
            # Query Cypher reformulada
            query = """
                MATCH (mae:Colonia {codigo_colonia: $codigo_mae})
                CREATE (filha:Colonia { 
                    codigo_colonia: $codigo_filha,
                    especie: mae.especie,
                    data_inicio: date($data_inicio),
                    status: "ativa",
                    tipo_cultivo: "derivada",
                    numero_passagem: mae.numero_passagem + 1,
                    observacao: $observacoes
                })
                CREATE (mae)-[:ORIGEM_DE]->(filha)
                WITH mae, filha
                MATCH (r:Racao {lote: $lote_racao})
                MERGE (filha)-[:ALIMENTADA_POR]->(r)
                WITH mae, filha
                OPTIONAL MATCH (mae)-[:ORIGEM_DE]->(outras_filhas:Colonia)
                WITH mae, filha, collect(outras_filhas) AS filhos
                SET mae.descendentes = size(filhos)
                RETURN filha, mae, mae.descendentes AS total_filhos
            """
            resultado = tx.run(query, params).data()

            if not resultado:
                graph.rollback(tx)
                return jsonify({'status': 'error', 'message': 'Falha ao criar colônia derivada'}), 400

            tx.commit()
            
            # Processar resultado
            filha = dict(resultado[0]['filha'])
            mae = dict(resultado[0]['mae'])
            
            # Converter objetos date para strings
            for node in [filha, mae]:
                for key in node:
                    if hasattr(node[key], 'isoformat'):
                        node[key] = str(node[key])
            
            logger.info(f"Colônia derivada criada: {params['codigo_filha']} de {codigo_colonia}")
            return jsonify({
                'status': 'success',
                'data': {
                    'colonia_filha': filha,
                    'colonia_mae': mae,
                    'total_filhos': resultado[0]['total_filhos'],
                    'timestamp': datetime.now().isoformat()
                }
            })

        except Exception as e:
            logger.error(f"Erro ao criar colônia derivada: {str(e)}")
            if tx:
                graph.rollback(tx)
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/colonia/<codigo_colonia>/inativar', methods=['POST'])
def inativar_colonia(codigo_colonia):
    """Endpoint para inativar uma colônia"""
    tx = None
    try:
        data = request.form
        params = {
            'codigo_colonia': codigo_colonia,
            'data_desativacao': data.get('data_desativacao', datetime.now().strftime("%Y-%m-%d")),
            'motivo': data.get('motivo', 'Inativação via sistema')
        }

        tx = graph.begin()
        resultado = tx.run("""
            MATCH (c:Colonia {codigo_colonia: $codigo_colonia})
            SET c.status = "inativa",
                c.data_desativacao = date($data_desativacao),
                c.motivo_inativacao = $motivo
            RETURN c
        """, params).data()

        if not resultado:
            tx.rollback()
            return jsonify({'status': 'error', 'message': 'Colônia não encontrada'}), 404

        tx.commit()
        
        # Converter objetos date para strings
        colonia_data = dict(resultado[0]['c'])
        for key, value in colonia_data.items():
            if hasattr(value, 'isoformat'):  # Para objetos date/datetime
                colonia_data[key] = str(value)
        
        logger.info(f"Colônia {codigo_colonia} inativada")
        return jsonify({
            'status': 'success',
            'data': {
                'colonia': colonia_data,
                'timestamp': datetime.now().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Erro ao inativar colônia: {str(e)}")
        if tx:
            tx.rollback()
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/criar_colonia_inicial', methods=['GET', 'POST'])
def criar_colonia_inicial():
    """Endpoint para criar uma colônia inicial"""
    if request.method == 'GET':
        try:
            racoes = graph.run(
                "MATCH (r:Racao) RETURN r.lote as lote ORDER BY r.data_producao DESC"
            ).data()
            
            return render_template(
                'criar_inicial.html',
                racoes=racoes
            )
        
        except Exception as e:
            logger.error(f"Erro ao buscar rações: {str(e)}")
            return render_template('erro.html', mensagem='Erro interno no servidor'), 500
    
    elif request.method == 'POST':
        tx = None
        try:
            data = request.form
            params = {
                'codigo': data.get('codigo_colonia'),
                'especie': data.get('especie'),
                'data_inicio': data.get('data_inicio', datetime.now().strftime("%Y-%m-%d")),
                'lote_racao': data.get('lote_racao'),
                'tipo_cultivo': data.get('tipo_cultivo', 'novo'),
                'observacoes': data.get('observacoes', 'Colônia inicial criada via sistema')
            }

            if not all([params['codigo'], params['especie'], params['lote_racao']]):
                return jsonify({'status': 'error', 'message': 'Parâmetros obrigatórios: codigo_colonia, especie e lote_racao'}), 400

            # Verificar se colônia já existe
            existe = graph.evaluate(
                "MATCH (c:Colonia {codigo_colonia: $codigo}) RETURN count(c) > 0",
                {'codigo': params['codigo']}
            )
            if existe:
                return jsonify({'status': 'error', 'message': f'Colônia {params["codigo"]} já existe'}), 400

            tx = graph.begin()
            resultado = tx.run("""
                // Criar a ração (se não existir)
                MERGE (r:Racao {lote: $lote_racao})
                ON CREATE SET 
                    r.data_criacao = datetime(),
                    r.data_producao = date($data_inicio)

                // Criar a colônia inicial com número de passagem = 0
                CREATE (c:Colonia {
                    codigo_colonia: $codigo,
                    especie: $especie,
                    data_inicio: date($data_inicio),
                    status: "ativa",
                    observacao: $observacoes,
                    tipo_cultivo: $tipo_cultivo,
                    numero_passagem: 0
                })

                // Criar o relacionamento
                CREATE (c)-[:ALIMENTADA_POR]->(r)

                RETURN c
            """, params).data()

            if not resultado:
                tx.rollback()
                return jsonify({'status': 'error', 'message': 'Falha ao criar colônia inicial'}), 400

            tx.commit()
            
            logger.info(f"Colônia inicial criada: {params['codigo']}")
            return jsonify({
                'status': 'success',
                'data': {
                    'colonia': dict(resultado[0]['c']),
                    'timestamp': datetime.now().isoformat()
                }
            })

        except Exception as e:
            logger.error(f"Erro ao criar colônia inicial: {str(e)}")
            if tx:
                tx.rollback()
            return jsonify({'status': 'error', 'message': str(e)}), 500

if __name__ == '__main__':
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False,
        threaded=True
    )