# Importa os módulos necessários do Flask e para o banco de dados e segurança
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime
from uuid import uuid4 # Para gerar nomes de arquivo únicos
from werkzeug.utils import secure_filename # Para garantir nomes de arquivo seguros

# Inicializa a aplicação Flask
app = Flask(__name__)
# Define uma chave secreta para as sessões do Flask (MUITO IMPORTANTE para segurança!)
# Em um ambiente de produção, use uma chave mais complexa e gerada aleatoriamente.
app.secret_key = 'sua_chave_secreta_muito_segura_aqui'

# Define o caminho para o arquivo do banco de dados SQLite
DATABASE = 'maintenance_system.db'
ITEMS_PER_PAGE = 50 # Define quantos itens por página serão exibidos no estoque
CALLS_PER_PAGE = 10 # Define quantos chamados por página serão exibidos nas listas
USERS_PER_PAGE = 5 # Define quantos usuários por página serão exibidos na lista de gerenciamento

# Configurações para upload de imagens
UPLOAD_FOLDER = 'static/profile_images'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    """Verifica se a extensão do arquivo é permitida."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Funções do Banco de Dados ---

def get_db_connection():
    """
    Estabelece uma conexão com o banco de dados SQLite.
    Cria o banco de dados e as tabelas se não existirem.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # Permite acessar colunas como dicionário
    return conn

def init_db():
    """
    Inicializa o banco de dados, criando as tabelas 'users', 'calls' e 'stock_items'.
    Também cria um usuário ADMIN padrão se não houver nenhum ADM.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Garante que a pasta de uploads exista
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])

    # Cria a tabela 'users' se não existir
    # Adicionamos a coluna 'created_at' e 'profile_image'
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('ADMIN', 'USUARIO', 'TECNICO')),
            is_primary_admin INTEGER DEFAULT 0, -- 1 para ADM principal, 0 para outros
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')), -- Data de criação do usuário
            profile_image TEXT -- Nova coluna para o caminho da imagem de perfil
        )
    ''')

    # Cria a tabela 'calls' se não existir
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Aberto', -- Ex: Aberto, Em Andamento, Concluído, Cancelado
            created_at TEXT NOT NULL, -- Para armazenar a data e hora de criação
            -- Adicionamos campos para o técnico preencher
            technician_id INTEGER,
            diagnosis TEXT,
            materials TEXT,
            finished_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (technician_id) REFERENCES users (id)
        )
    ''')

    # Cria a tabela 'stock_items' se não existir
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS stock_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            quantity INTEGER NOT NULL,
            unit TEXT, -- Ex: unidades, metros, litros
            last_updated TEXT NOT NULL
        )
    ''')
    conn.commit()

    # Verifica se já existe um usuário ADMIN
    cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'ADMIN'")
    admin_count = cursor.fetchone()[0]

    if admin_count == 0:
        # Cria um usuário ADMIN padrão se não houver nenhum
        admin_password = "adminpassword" # Senha padrão para o primeiro ADM
        admin_password_hash = generate_password_hash(admin_password)
        created_at_now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, role, is_primary_admin, created_at, profile_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                ('Admin Padrão', 'admin@example.com', admin_password_hash, 'ADMIN', 1, created_at_now, None) # ADM padrão sem foto inicial
            )
            conn.commit()
            print(f"Usuário ADMIN padrão criado: admin@example.com com senha '{admin_password}'")
        except sqlite3.IntegrityError:
            print("Usuário ADMIN já existe ou houve erro ao criar.")
    conn.close()

# --- Rotas da Aplicação ---

@app.route('/')
def index():
    """
    Redireciona para a página de login.
    """
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Rota para a página de login.
    GET: Exibe o formulário de login.
    POST: Processa os dados do formulário de login.
    """
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            # Login bem-sucedido: armazena informações do usuário na sessão
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['user_role'] = user['role']
            
            # Garante que 'is_primary_admin' esteja na sessão, mesmo que seja 0
            # Acessa diretamente a coluna 'is_primary_admin' do objeto Row
            user_is_primary_admin = user['is_primary_admin'] if 'is_primary_admin' in user.keys() else 0
            session['is_primary_admin'] = user_is_primary_admin
            
            # Adiciona o caminho da imagem de perfil à sessão
            session['profile_image'] = user['profile_image'] if 'profile_image' in user.keys() else None

            print(f"DEBUG: Após login para {email}")
            print(f"DEBUG: user['is_primary_admin'] do DB: {user['is_primary_admin']}") # Acessando diretamente
            print(f"DEBUG: session['is_primary_admin'] após set: {session.get('is_primary_admin')}")
            print(f"DEBUG: session['profile_image'] após set: {session.get('profile_image')}")


            flash(f'Bem-vindo(a), {user["name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            # Login falhou
            flash('Email ou senha inválidos. Tente novamente.', 'danger')
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    """
    Página de dashboard para usuários logados.
    Verifica se o usuário está logado, caso contrário, redireciona para o login.
    Para USUARIOS, exibe os 10 últimos chamados.
    Para TECNICOS, exibe os 15 últimos chamados de todos os usuários.
    """
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))

    user_role = session['user_role']
    user_id = session['user_id']
    
    recent_calls = []
    if user_role == 'USUARIO':
        conn = get_db_connection()
        # Busca os 10 últimos chamados do usuário logado, ordenados por data de criação
        recent_calls = conn.execute(
            "SELECT * FROM calls WHERE user_id = ? ORDER BY created_at DESC LIMIT 10",
            (user_id,)
        ).fetchall()
        conn.close()
    elif user_role == 'TECNICO':
        conn = get_db_connection()
        # Busca os 15 últimos chamados de TODOS os usuários para o técnico
        # Inclui o nome do usuário que abriu o chamado
        recent_calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener 
            FROM calls c JOIN users u ON c.user_id = u.id 
            ORDER BY c.created_at DESC LIMIT 15
            """
        ).fetchall()
        conn.close()
    
    # Renderiza o template do dashboard, passando os chamados recentes
    return render_template('dashboard.html', 
                           user_name=session['user_name'], 
                           user_role=user_role,
                           recent_calls=recent_calls)

@app.route('/register_user', methods=['GET', 'POST'])
def register_user():
    """
    Rota para o Administrador registrar novos usuários.
    GET: Exibe o formulário de registro.
    POST: Processa os dados do formulário de registro.
    Apenas ADMINs podem acessar esta rota.
    O ADM principal pode criar outros ADMs, usuários e técnicos.
    ADMs secundários podem criar apenas usuários e técnicos.
    """
    # Verifica se o usuário está logado e se é um ADMIN
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem registrar novos usuários.', 'danger')
        return redirect(url_for('login'))

    # Pega o status do ADM logado da sessão
    is_primary_admin = session.get('is_primary_admin', 0) 
    print(f"DEBUG: Na rota register_user, is_primary_admin da sessão: {is_primary_admin}")


    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Data de criação
        profile_image_path = None # Inicializa o caminho da imagem como None

        # Validação básica dos campos
        if not name or not email or not password or not role:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('register_user.html', is_primary_admin=is_primary_admin)

        # Lógica de permissão para criar usuários
        if role not in ['USUARIO', 'TECNICO']:
            # Apenas o ADM principal pode registrar outros administradores.
            # A comparação agora usa o valor da sessão diretamente, que deve ser um int.
            if session.get('is_primary_admin', 0) == 0 and role == 'ADMIN':
                flash('Apenas o Administrador principal pode registrar outros administradores.', 'danger')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)
            elif role not in ['ADMIN', 'USUARIO', 'TECNICO']: # Caso tente enviar um role inválido
                flash('Tipo de usuário inválido.', 'danger')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)

        # Lidar com o upload da imagem de perfil
        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '' and allowed_file(file.filename):
                # Pega a extensão original do arquivo
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                # Gera um nome de arquivo completamente único usando apenas UUID
                unique_filename = str(uuid4()) + '.' + file_extension
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                file.save(file_path)
                # Armazena o caminho relativo para ser acessível via URL
                profile_image_path = '/' + file_path.replace('\\', '/')
            elif file.filename != '': # Se o arquivo não é vazio mas a extensão não é permitida
                flash('Tipo de arquivo de imagem não permitido. Por favor, use PNG, JPG, JPEG ou GIF.', 'warning')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)


        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        try:
            # Se o role for ADMIN, e o ADM logado for o principal, define is_primary_admin como 0 para o novo ADM
            new_user_is_primary_admin = 0
            if role == 'ADMIN' and session.get('is_primary_admin', 0) == 1:
                new_user_is_primary_admin = 0 # Novos ADMs criados pelo principal não são primários

            conn.execute(
                "INSERT INTO users (name, email, password_hash, role, is_primary_admin, created_at, profile_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, email, password_hash, role, new_user_is_primary_admin, created_at, profile_image_path)
            )
            conn.commit()
            flash(f'Usuário {name} ({role}) registrado com sucesso!', 'success')
            return redirect(url_for('manage_users')) # Redireciona para a lista de usuários
        except sqlite3.IntegrityError:
            flash('Este email já está registrado. Por favor, use outro.', 'danger')
        except Exception as e:
            flash(f'Erro ao registrar usuário: {e}', 'danger')
        finally:
            conn.close()
    
    # Para o método GET, passa o status de ADM principal para o template
    return render_template('register_user.html', is_primary_admin=is_primary_admin)

@app.route('/new_call', methods=['GET', 'POST'])
def new_call():
    """
    Rota para USUARIOS e ADMINS abrirem um novo chamado.
    GET: Exibe o formulário para abrir o chamado.
    POST: Processa os dados do formulário e cria o chamado.
    """
    if 'user_id' not in session or session['user_role'] not in ['USUARIO', 'ADMIN']:
        flash('Acesso negado. Apenas usuários e administradores podem abrir novos chamados.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        location = request.form['location']
        user_id = session['user_id']
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') # Formato de data e hora

        if not title or not description or not location:
            flash('Todos os campos (Título, Descrição, Local) são obrigatórios.', 'danger')
            return render_template('new_call.html')

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO calls (user_id, title, description, location, status, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (user_id, title, description, location, 'Aberto', created_at)
            )
            conn.commit()
            flash('Chamado aberto com sucesso!', 'success')
            
            # Redireciona para admin_calls se o usuário for ADMIN, senão para dashboard
            if session['user_role'] == 'ADMIN':
                return redirect(url_for('admin_calls'))
            else:
                return redirect(url_for('dashboard')) 
        except Exception as e:
            flash(f'Erro ao abrir o chamado: {e}', 'danger')
        finally:
            conn.close()
    
    return render_template('new_call.html')

@app.route('/view_all_calls')
def view_all_calls():
    """
    Rota para USUARIOS visualizarem todos os seus chamados.
    Apenas USUARIOS podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'USUARIO':
        flash('Acesso negado. Apenas usuários podem visualizar seus chamados.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    # Busca todos os chamados do usuário logado, ordenados por data de criação
    all_calls = conn.execute(
        "SELECT * FROM calls WHERE user_id = ? ORDER BY created_at DESC",
        (user_id,)
    ).fetchall()
    conn.close()

    return render_template('view_all_calls.html', all_calls=all_calls)

@app.route('/call_details/<int:call_id>')
def call_details(call_id):
    """
    Rota para exibir os detalhes de um chamado específico.
    Acessível por TECNICOS e pelo USUARIO que abriu o chamado.
    """
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    # Busca o chamado e o nome do usuário que o abriu
    call = conn.execute(
        """
        SELECT c.*, u.name as user_name_opener 
        FROM calls c JOIN users u ON c.user_id = u.id 
        WHERE c.id = ?
        """,
        (call_id,)
    ).fetchone()

    if not call:
        flash('Chamado não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    # Verifica se o usuário logado tem permissão para ver este chamado
    # ADMs e Técnicos podem ver qualquer chamado. Usuários só podem ver os seus.
    if session['user_role'] == 'USUARIO' and call['user_id'] != session['user_id']:
        flash('Acesso negado. Você não tem permissão para visualizar este chamado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    # Se o chamado já tiver um técnico atribuído, busca o nome dele
    technician_name = None
    if call['technician_id']:
        tech_user = conn.execute("SELECT name FROM users WHERE id = ?", (call['technician_id'],)).fetchone()
        if tech_user:
            technician_name = tech_user['name']

    conn.close()
    # Passa o user_role para o template
    return render_template('call_details.html', 
                           call=call, 
                           technician_name=technician_name,
                           user_role=session['user_role'])

@app.route('/attend_call/<int:call_id>', methods=['GET', 'POST'])
def attend_call(call_id):
    """
    Rota para o técnico atender/finalizar um chamado.
    GET: Exibe o formulário para preencher diagnóstico e materiais.
    POST: Processa os dados do formulário e atualiza o chamado.
    Apenas TECNICOS podem acessar esta rota e apenas para chamados 'Aberto' ou 'Em Andamento'.
    """
    if 'user_id' not in session or session['user_role'] != 'TECNICO':
        flash('Acesso negado. Apenas técnicos podem atender chamados.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()

    if not call:
        flash('Chamado não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    # Um técnico só pode atender chamados que estão 'Aberto' ou 'Em Andamento'
    if call['status'] not in ['Aberto', 'Em Andamento']:
        flash(f'Este chamado já está {call["status"]}. Não pode ser atendido novamente.', 'warning')
        conn.close()
        return redirect(url_for('call_details', call_id=call_id))

    if request.method == 'POST':
        diagnosis = request.form['diagnosis']
        materials = request.form['materials']
        action = request.form['action'] # 'start_attendance' ou 'finish_call'
        technician_id = session['user_id']
        finished_at = None

        if action == 'finish_call':
            if not diagnosis or not materials:
                flash('Diagnóstico e Materiais são obrigatórios para finalizar o chamado.', 'danger')
                conn.close()
                return render_template('attend_call.html', call=call)
            status = 'Concluído'
            finished_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        elif action == 'start_attendance':
            status = 'Em Andamento'
        else:
            flash('Ação inválida.', 'danger')
            conn.close()
            return render_template('attend_call.html', call=call)

        try:
            conn.execute(
                """
                UPDATE calls 
                SET status = ?, technician_id = ?, diagnosis = ?, materials = ?, finished_at = ?
                WHERE id = ?
                """,
                (status, technician_id, diagnosis, materials, finished_at, call_id)
            )
            conn.commit()
            flash(f'Chamado #{call_id} atualizado para "{status}" com sucesso!', 'success')
            return redirect(url_for('call_details', call_id=call_id))
        except Exception as e:
            flash(f'Erro ao atualizar o chamado: {e}', 'danger')
        finally:
            conn.close()
    
    # Para o método GET, exibe o formulário de atendimento
    conn.close() # Fecha a conexão após buscar o chamado
    return render_template('attend_call.html', call=call)

@app.route('/filtered_calls/<status_filter>')
def filtered_calls(status_filter):
    """
    Rota para técnicos visualizarem chamados filtrados por status.
    Apenas TECNICOS podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'TECNICO':
        flash('Acesso negado. Apenas técnicos podem visualizar chamados filtrados.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    calls = []
    title = ""

    if status_filter == 'abertos':
        calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener 
            FROM calls c JOIN users u ON c.user_id = u.id 
            WHERE c.status = 'Aberto' 
            ORDER BY c.created_at DESC
            """
        ).fetchall()
        title = "Chamados Abertos"
    elif status_filter == 'em_atendimento':
        calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener, t.name as technician_name_assigned
            FROM calls c 
            JOIN users u ON c.user_id = u.id 
            LEFT JOIN users t ON c.technician_id = t.id
            WHERE c.status = 'Em Andamento' 
            ORDER BY c.created_at DESC
            """
        ).fetchall()
        title = "Chamados em Atendimento"
    elif status_filter == 'finalizados':
        calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener, t.name as technician_name_assigned
            FROM calls c 
            JOIN users u ON c.user_id = u.id 
            LEFT JOIN users t ON c.technician_id = t.id
            WHERE c.status = 'Concluído' 
            ORDER BY c.created_at DESC
            """
        ).fetchall()
        title = "Chamados Finalizados"
    elif status_filter == 'todos': # Adicionado filtro para "Todos Chamados" para o técnico
        calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener, t.name as technician_name_assigned
            FROM calls c 
            JOIN users u ON c.user_id = u.id 
            LEFT JOIN users t ON c.technician_id = t.id
            ORDER BY c.created_at DESC
            """
        ).fetchall()
        title = "Todos os Chamados"
    else:
        flash('Filtro de status inválido.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    conn.close()
    return render_template('filtered_calls.html', calls=calls, title=title, status_filter=status_filter)

@app.route('/admin_calls')
def admin_calls():
    """
    Rota para Administradores visualizarem todos os chamados com paginação.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem visualizar todos os chamados.', 'danger')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int) # Pega o número da página da URL, padrão 1
    offset = (page - 1) * CALLS_PER_PAGE # Calcula o offset para a consulta SQL

    conn = get_db_connection()
    # Busca todos os chamados, incluindo o nome do usuário que abriu e o técnico atribuído
    calls = conn.execute(
        """
        SELECT c.*, u.name as user_name_opener, t.name as technician_name_assigned
        FROM calls c 
        JOIN users u ON c.user_id = u.id 
        LEFT JOIN users t ON c.technician_id = t.id
        ORDER BY c.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (CALLS_PER_PAGE, offset)
    ).fetchall()

    # Conta o total de chamados para calcular o número total de páginas
    total_calls = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    conn.close()

    total_pages = (total_calls + CALLS_PER_PAGE - 1) // CALLS_PER_PAGE # Calcula o total de páginas
    
    return render_template('admin_calls.html', 
                           calls=calls, 
                           title="Todos os Chamados (Administrador)",
                           page=page,
                           total_pages=total_pages)

@app.route('/manage_users')
def manage_users():
    """
    Rota para Administradores gerenciarem usuários.
    Exibe uma lista de todos os usuários com paginação e pesquisa.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem gerenciar usuários.', 'danger')
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int) # Número da página, padrão 1
    search_query = request.args.get('search', '').strip() # Termo de pesquisa, padrão vazio
    offset = (page - 1) * USERS_PER_PAGE # Calcula o offset para a consulta SQL

    conn = get_db_connection()
    
    # Construção da consulta SQL base
    # Adicionado profile_image à consulta SELECT
    base_query = "SELECT id, name, email, role, created_at, is_primary_admin, profile_image FROM users" 
    count_query = "SELECT COUNT(*) FROM users"
    query_params = []

    # Adiciona a condição de pesquisa se houver um termo
    if search_query:
        # Pesquisa por nome ou email (case-insensitive)
        base_query += " WHERE name LIKE ? OR email LIKE ?"
        count_query += " WHERE name LIKE ? OR email LIKE ?"
        query_params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    base_query += " ORDER BY name LIMIT ? OFFSET ?"
    query_params.extend([USERS_PER_PAGE, offset])

    # Executa a consulta para buscar os usuários paginados e filtrados
    users = conn.execute(base_query, query_params).fetchall()

    # Executa a consulta para contar o total de usuários (para paginação)
    # A lista de parâmetros para a contagem deve ser apenas os parâmetros de pesquisa, sem LIMIT/OFFSET
    count_query_params = [f"%{search_query}%", f"%{search_query}%"] if search_query else []
    total_users = conn.execute(count_query, count_query_params).fetchone()[0]
    conn.close()

    total_pages = (total_users + USERS_PER_PAGE - 1) // USERS_PER_PAGE # Calcula o total de páginas
    
    return render_template('manage_users.html', 
                           users=users, 
                           page=page, 
                           total_pages=total_pages,
                           search_query=search_query)

@app.route('/user_details/<int:user_id>')
def user_details(user_id):
    """
    Rota para Administradores visualizarem os detalhes de um usuário específico.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem visualizar detalhes de usuários.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT id, name, email, role, created_at, is_primary_admin, profile_image FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user:
        flash('Usuário não encontrado.', 'danger')
        return redirect(url_for('manage_users'))
    
    # Verifica se o usuário visualizado é o ADM principal
    is_viewed_user_primary_admin = user['is_primary_admin'] == 1

    # Adicionando depuração para o caminho da imagem
    print(f"DEBUG: Caminho da imagem de perfil para user_id {user_id}: {user['profile_image']}")

    return render_template('user_details.html', 
                           user=user, 
                           is_viewed_user_primary_admin=is_viewed_user_primary_admin,
                           logged_in_is_primary_admin=session.get('is_primary_admin', 0)) # Passa o status do ADM logado


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    """
    Rota para o usuário editar seu próprio perfil.
    GET: Exibe o formulário de edição com os dados atuais.
    POST: Processa a atualização do email do usuário.
    """
    if 'user_id' not in session:
        flash('Você precisa estar logado para editar seu perfil.', 'warning')
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    user = conn.execute("SELECT id, name, email, role, profile_image FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash('Usuário não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        new_email = request.form['email'].strip()
        
        if not new_email:
            flash('O email não pode ser vazio.', 'danger')
            conn.close()
            return render_template('edit_profile.html', user=user)
        
        try:
            # Verifica se o novo email já existe para outro usuário
            existing_user = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, user_id)).fetchone()
            if existing_user:
                flash('Este email já está em uso por outro usuário. Por favor, escolha outro.', 'danger')
                conn.close()
                return render_template('edit_profile.html', user=user)

            conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
            conn.commit()
            session['user_email'] = new_email # Atualiza o email na sessão
            flash('Email atualizado com sucesso!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            flash(f'Erro ao atualizar o perfil: {e}', 'danger')
        finally:
            conn.close()
            
    conn.close()
    return render_template('edit_profile.html', user=user)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    """
    Rota para o Administrador principal excluir um usuário.
    Apenas o ADM principal pode acessar esta rota.
    O ADM principal não pode excluir a si mesmo.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN' or session.get('is_primary_admin', 0) != 1:
        flash('Acesso negado. Apenas o Administrador principal pode excluir usuários.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user_to_delete = conn.execute("SELECT id, is_primary_admin FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user_to_delete:
        flash('Usuário não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('manage_users'))

    # Impede que o ADM principal exclua a si mesmo
    if user_to_delete['is_primary_admin'] == 1:
        flash('O Administrador principal não pode ser excluído.', 'danger')
        conn.close()
        return redirect(url_for('user_details', user_id=user_id))

    try:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash(f'Usuário ID {user_id} excluído com sucesso.', 'success')
    except Exception as e:
        flash(f'Erro ao excluir usuário: {e}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('manage_users'))


@app.route('/manage_stock')
def manage_stock():
    """
    Rota para gerenciar o estoque.
    Apenas ADMINs podem acessar esta rota.
    Exibe uma lista paginada de itens do estoque.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem gerenciar o estoque.', 'danger')
        return redirect(url_for('login'))
    
    page = request.args.get('page', 1, type=int) # Pega o número da página da URL, padrão 1
    offset = (page - 1) * ITEMS_PER_PAGE # Calcula o offset para a consulta SQL

    conn = get_db_connection()
    # Busca os itens do estoque com limite e offset para paginação
    stock_items = conn.execute(
        "SELECT * FROM stock_items ORDER BY name LIMIT ? OFFSET ?",
        (ITEMS_PER_PAGE, offset)
    ).fetchall()

    # Conta o total de itens para calcular o número total de páginas
    total_items = conn.execute("SELECT COUNT(*) FROM stock_items").fetchone()[0]
    conn.close()

    total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE # Calcula o total de páginas

    return render_template('manage_stock.html', 
                           stock_items=stock_items, 
                           page=page, 
                           total_pages=total_pages)

@app.route('/insert_material', methods=['GET', 'POST'])
def insert_material():
    """
    Rota para o Administrador inserir novos materiais no estoque.
    GET: Exibe o formulário de inserção.
    POST: Processa os dados do formulário e insere o material.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem inserir materiais.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        quantity = request.form['quantity']
        unit = request.form['unit'].strip()
        last_updated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not name or not quantity or not unit:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('insert_material.html')
        
        try:
            quantity = int(quantity)
            if quantity < 0:
                flash('A quantidade deve ser um número positivo.', 'danger')
                return render_template('insert_material.html')
        except ValueError:
            flash('Quantidade deve ser um número válido.', 'danger')
            return render_template('insert_material.html')

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO stock_items (name, quantity, unit, last_updated) VALUES (?, ?, ?, ?)",
                (name, quantity, unit, last_updated)
            )
            conn.commit()
            flash(f'Material "{name}" inserido com sucesso!', 'success')
            return redirect(url_for('manage_stock')) # Redireciona para a lista de estoque
        except sqlite3.IntegrityError:
            flash('Já existe um material com este nome. Considere editar o existente.', 'danger')
        except Exception as e:
            flash(f'Erro ao inserir material: {e}', 'danger')
        finally:
            conn.close()
    
    return render_template('insert_material.html')

@app.route('/edit_materials')
def edit_materials():
    """
    Rota para o Administrador visualizar e selecionar materiais para edição.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem editar materiais.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    stock_items = conn.execute("SELECT * FROM stock_items ORDER BY name").fetchall()
    conn.close()
    
    return render_template('edit_materials.html', stock_items=stock_items)

@app.route('/edit_material/<int:item_id>', methods=['GET', 'POST'])
def edit_material(item_id):
    """
    Rota para o Administrador editar um material específico.
    GET: Exibe o formulário pré-preenchido com os dados do material.
    POST: Processa a atualização do material.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem editar materiais.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    item = conn.execute("SELECT * FROM stock_items WHERE id = ?", (item_id,)).fetchone()

    if not item:
        flash('Material não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('edit_materials'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        quantity = request.form['quantity']
        unit = request.form['unit'].strip()
        last_updated = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not name or not quantity or not unit:
            flash('Todos os campos são obrigatórios.', 'danger')
            conn.close()
            return render_template('edit_material_form.html', item=item)
        
        try:
            quantity = int(quantity)
            if quantity < 0:
                flash('A quantidade deve ser um número positivo.', 'danger')
                conn.close()
                return render_template('edit_material_form.html', item=item)
        except ValueError:
            flash('Quantidade deve ser um número válido.', 'danger')
            conn.close()
            return render_template('edit_material_form.html', item=item)

        try:
            conn.execute(
                """
                UPDATE stock_items 
                SET name = ?, quantity = ?, unit = ?, last_updated = ?
                WHERE id = ?
                """,
                (name, quantity, unit, last_updated, item_id)
            )
            conn.commit()
            flash(f'Material "{name}" atualizado com sucesso!', 'success')
            return redirect(url_for('manage_stock')) # Redireciona para a lista de estoque
        except sqlite3.IntegrityError:
            flash('Já existe outro material com este nome. Por favor, use um nome diferente.', 'danger')
        except Exception as e:
            flash(f'Erro ao atualizar material: {e}', 'danger')
        finally:
            conn.close()
    
    conn.close()
    return render_template('edit_material_form.html', item=item)


@app.route('/logout')
def logout():
    """
    Rota para deslogar o usuário, limpando a sessão.
    """
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_role', None)
    session.pop('is_primary_admin', None) # Remove o status de ADM principal da sessão
    session.pop('profile_image', None) # Remove a imagem de perfil da sessão
    flash('Você foi desconectado(a).', 'info')
    return redirect(url_for('login'))

# --- Execução da Aplicação ---

if __name__ == '__main__':
    # Inicializa o banco de dados ao iniciar a aplicação
    init_db()
    # Executa a aplicação Flask em modo de depuração (para desenvolvimento)
    # Em produção, use um servidor WSGI como Gunicorn ou uWSGI.
    app.run(debug=True)
