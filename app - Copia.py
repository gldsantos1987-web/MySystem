# Importa os módulos necessários do Flask e para o banco de dados e segurança
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_from_directory
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import os
from datetime import datetime, timedelta # Importa timedelta para cálculos de data
from uuid import uuid4 # Para gerar nomes de arquivo únicos
from werkzeug.utils import secure_filename # Para garantir nomes de arquivo seguros
import json # Importar para lidar com JSON de materiais

# Inicializa a aplicação Flask
app = Flask(__name__)
# Define uma chave secreta para as sessões do Flask (MUITO IMPORTANTE para segurança!)
# Em um ambiente de produção, use uma chave mais complexa e gerada aleatoriamente.
app.secret_key = 'sua_chave_secreta_muito_segura_aqui'

# Define o caminho para o arquivo do banco de dados SQLite
DATABASE = 'maintenance_system.db'
ITEMS_PER_PAGE = 20 # Define quantos itens por página serão exibidos no estoque (alterado de 50 para 20)
CALLS_PER_PAGE = 5 # Define quantos chamados por página serão exibidos nas listas (alterado de 10 para 5)
USERS_PER_PAGE = 5 # Define quantos usuários por página serão exibidos na lista (mantido em 5)

# Configurações para upload de imagens de perfil
UPLOAD_FOLDER_PROFILE_IMAGES = 'static/profile_images'
# Configurações para upload de anexos de chamados
UPLOAD_FOLDER_ATTACHMENTS = 'static/call_attachments'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'doc', 'docx', 'txt'} # Adicionado tipos de arquivo para anexos
app.config['UPLOAD_FOLDER_PROFILE_IMAGES'] = UPLOAD_FOLDER_PROFILE_IMAGES
app.config['UPLOAD_FOLDER_ATTACHMENTS'] = UPLOAD_FOLDER_ATTACHMENTS

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
    Inicializa o banco de dados, criando as tabelas 'users', 'calls', 'stock_items' e 'notifications'.
    Também cria um usuário ADMIN padrão se não houver nenhum ADM.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Garante que as pastas de uploads existam
    if not os.path.exists(app.config['UPLOAD_FOLDER_PROFILE_IMAGES']):
        os.makedirs(app.config['UPLOAD_FOLDER_PROFILE_IMAGES'])
    if not os.path.exists(app.config['UPLOAD_FOLDER_ATTACHMENTS']):
        os.makedirs(app.config['UPLOAD_FOLDER_ATTACHMENTS'])

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
    # Adicionada a coluna 'conclusion' e 'category'
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            location TEXT NOT NULL,
            category TEXT NOT NULL, -- Nova coluna para a categoria do chamado
            status TEXT NOT NULL DEFAULT 'Aberto', -- Ex: Aberto, Em Andamento, Concluído, Cancelado
            created_at TEXT NOT NULL, -- Para armazenar a data e hora de criação
            technician_id INTEGER,
            diagnosis TEXT,
            materials TEXT, -- Agora armazenará JSON string
            conclusion TEXT, -- Nova coluna para a conclusão do chamado
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

    # Cria a tabela 'notifications' se não existir
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            link TEXT, -- Link para onde a notificação deve levar (ex: detalhes do chamado)
            is_read INTEGER DEFAULT 0, -- 0 para não lida, 1 para lida
            created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
            notification_type TEXT, -- Tipo de notificação (ex: 'new_call', 'call_update', 'user_management')
            call_id INTEGER, -- Adiciona call_id para referência direta ao chamado
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (call_id) REFERENCES calls (id)
        )
    ''')

    # Nova tabela para anexos de chamados
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS call_attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            call_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL, -- Caminho relativo para o arquivo no servidor
            upload_date TEXT NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
            uploaded_by_user_id INTEGER NOT NULL,
            FOREIGN KEY (call_id) REFERENCES calls (id),
            FOREIGN KEY (uploaded_by_user_id) REFERENCES users (id)
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
                ('Admin Padrão', 'admin@example.com', admin_password_hash, 'ADMIN', 1, created_at_now, None)
            )
            conn.commit()
            print(f"Usuário ADMIN padrão criado: admin@example.com com senha '{admin_password}'")
        except sqlite3.IntegrityError:
            print("Usuário ADMIN já existe ou houve erro ao criar.")
    conn.close()

def add_notification(user_id, message, link=None, notification_type=None, call_id=None):
    """
    Adiciona uma nova notificação ao banco de dados para um usuário específico.
    Agora aceita call_id.
    """
    conn = get_db_connection()
    try:
        print(f"DEBUG: add_notification - Inserindo: user_id={user_id}, message='{message}', call_id={call_id}")
        conn.execute(
            "INSERT INTO notifications (user_id, message, link, notification_type, call_id) VALUES (?, ?, ?, ?, ?)",
            (user_id, message, link, notification_type, call_id)
        )
        conn.commit()
        print(f"Notificação adicionada com sucesso para user_id {user_id}: '{message}'")
    except Exception as e:
        print(f"Erro ao adicionar notificação para user_id {user_id}: {e}")
    finally:
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
    Se o usuário já estiver logado, redireciona para o dashboard.
    """
    # Adição da verificação de login no início da função
    if 'user_id' in session:
        # Removida a mensagem flash para redirecionamento
        return redirect(url_for('dashboard'))

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
            # Verifica se 'profile_image' existe e não é None
            session['profile_image'] = user['profile_image'] if user and 'profile_image' in user.keys() and user['profile_image'] else None

            print(f"DEBUG: Após login para {email}")
            print(f"DEBUG: user['is_primary_admin'] do DB: {user['is_primary_admin']}")
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
    Para USUARIOS e TECNICOS, exibe os chamados "Aberto" e "Em Andamento" com paginação.
    Para ADMINS, exibe o dashboard com os gráficos.
    """
    if 'user_id' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'warning')
        return redirect(url_for('login'))

    user_role = session['user_role']
    user_id = session['user_id']
    
    recent_calls = []
    total_calls = 0
    page = request.args.get('page', 1, type=int) # Pega o número da página da URL, padrão 1
    offset = (page - 1) * CALLS_PER_PAGE # Calcula o offset para a consulta SQL

    conn = get_db_connection()

    if user_role == 'USUARIO':
        # Busca chamados "Aberto" ou "Em Andamento" do usuário logado
        recent_calls = conn.execute(
            """
            SELECT * FROM calls 
            WHERE user_id = ? AND status IN ('Aberto', 'Em Andamento') 
            ORDER BY created_at DESC 
            LIMIT ? OFFSET ?
            """,
            (user_id, CALLS_PER_PAGE, offset)
        ).fetchall()
        total_calls = conn.execute(
            "SELECT COUNT(*) FROM calls WHERE user_id = ? AND status IN ('Aberto', 'Em Andamento')",
            (user_id,)
        ).fetchone()[0]
    elif user_role == 'TECNICO':
        # Busca chamados "Aberto" ou "Em Andamento" de TODOS os usuários para o técnico
        recent_calls = conn.execute(
            """
            SELECT c.*, u.name as user_name_opener 
            FROM calls c JOIN users u ON c.user_id = u.id 
            WHERE c.status IN ('Aberto', 'Em Andamento') 
            ORDER BY c.created_at DESC 
            LIMIT ? OFFSET ?
            """,
            (CALLS_PER_PAGE, offset)
        ).fetchall()
        total_calls = conn.execute(
            "SELECT COUNT(*) FROM calls WHERE status IN ('Aberto', 'Em Andamento')"
        ).fetchone()[0]
    
    conn.close()

    total_pages = (total_calls + CALLS_PER_PAGE - 1) // CALLS_PER_PAGE # Calcula o total de páginas
    
    # Renderiza o template do dashboard, passando os chamados recentes e dados de paginação
    return render_template('dashboard.html', 
                           user_name=session['user_name'], 
                           user_role=user_role,
                           recent_calls=recent_calls,
                           page=page,
                           total_pages=total_pages)

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
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem registrar novos usuários.', 'danger')
        return redirect(url_for('login'))

    is_primary_admin = session.get('is_primary_admin', 0) 

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 
        profile_image_path = None 

        if 'profile_image' in request.files:
            file = request.files['profile_image']
            if file.filename != '' and allowed_file(file.filename):
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                unique_filename = str(uuid4()) + '.' + file_extension
                file_path = os.path.join(app.config['UPLOAD_FOLDER_PROFILE_IMAGES'], unique_filename)
                file.save(file_path)
                profile_image_path = '/' + file_path.replace('\\', '/')
            elif file.filename != '': 
                flash('Tipo de arquivo de imagem não permitido. Por favor, use PNG, JPG, JPEG ou GIF.', 'warning')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)

        if not name or not email or not password or not role:
            flash('Todos os campos são obrigatórios.', 'danger')
            return render_template('register_user.html', is_primary_admin=is_primary_admin)

        if role not in ['USUARIO', 'TECNICO']:
            if session.get('is_primary_admin', 0) == 0 and role == 'ADMIN':
                flash('Acesso negado. Apenas o Administrador principal pode registrar outros administradores.', 'danger')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)
            elif role not in ['ADMIN', 'USUARIO', 'TECNICO']: 
                flash('Tipo de usuário inválido.', 'danger')
                return render_template('register_user.html', is_primary_admin=is_primary_admin)

        password_hash = generate_password_hash(password)

        conn = get_db_connection()
        try:
            new_user_is_primary_admin = 0
            if role == 'ADMIN' and session.get('is_primary_admin', 0) == 1:
                new_user_is_primary_admin = 0 

            conn.execute(
                "INSERT INTO users (name, email, password_hash, role, is_primary_admin, created_at, profile_image) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (name, email, password_hash, role, new_user_is_primary_admin, created_at, profile_image_path)
            )
            conn.commit()
            flash(f'Usuário {name} ({role}) registrado com sucesso!', 'success')
            return redirect(url_for('manage_users')) 
        except sqlite3.IntegrityError:
            flash('Este email já está registrado. Por favor, use outro.', 'danger')
        except Exception as e:
            flash(f'Erro ao registrar usuário: {e}', 'danger')
        finally:
            conn.close()
    
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
        category = request.form['category'] 
        user_id = session['user_id']
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S') 

        if not title or not description or not location or not category: 
            flash('Todos os campos (Título, Descrição, Local, Categoria) são obrigatórios.', 'danger')
            return render_template('new_call.html')

        conn = get_db_connection()
        try:
            cursor = conn.cursor() 
            cursor.execute(
                "INSERT INTO calls (user_id, title, description, location, category, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                (user_id, title, description, location, category, 'Aberto', created_at) 
            )
            conn.commit()
            new_call_id = cursor.lastrowid 

            # Lidar com uploads de arquivos para o chamado
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                for file in files:
                    if file and allowed_file(file.filename):
                        original_filename = secure_filename(file.filename)
                        file_extension = original_filename.rsplit('.', 1)[1].lower()
                        unique_filename = str(uuid4()) + '.' + file_extension
                        file_path = os.path.join(app.config['UPLOAD_FOLDER_ATTACHMENTS'], unique_filename)
                        file.save(file_path)
                        
                        # Salvar informações do anexo no banco de dados
                        conn.execute(
                            "INSERT INTO call_attachments (call_id, filename, filepath, uploaded_by_user_id) VALUES (?, ?, ?, ?)",
                            (new_call_id, original_filename, '/' + file_path.replace('\\', '/'), user_id)
                        )
                        conn.commit()
                        flash(f'Anexo "{original_filename}" enviado com sucesso!', 'info')
                    elif file.filename != '':
                        flash(f'Tipo de arquivo não permitido para anexo: {file.filename}.', 'warning')

            flash('Chamado aberto com sucesso!', 'success')
            
            admin_and_tech_users = conn.execute("SELECT id, role FROM users WHERE role IN ('ADMIN', 'TECNICO')").fetchall()
            for user in admin_and_tech_users:
                message = f"Novo chamado: '{title}'"
                link = url_for('call_details', call_id=new_call_id)
                add_notification(user['id'], message, link, 'new_call', new_call_id)

            if session['user_role'] == 'ADMIN':
                return redirect(url_for('admin_calls'))
            else:
                return redirect(url_for('dashboard')) 
        except Exception as e:
            flash(f'Erro ao abrir o chamado: {e}', 'danger')
            print(f"Erro ao abrir chamado: {e}") 
        finally:
            conn.close()
    
    return render_template('new_call.html')

@app.route('/view_all_calls')
def view_all_calls():
    """
    Rota para USUARIOS visualizarem todos os seus chamados.
    Apenas USUARIOS podem acessar esta rota.
    Adicionado paginação.
    """
    if 'user_id' not in session or session['user_role'] != 'USUARIO':
        flash('Acesso negado. Apenas usuários podem visualizar seus chamados.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    page = request.args.get('page', 1, type=int) 
    offset = (page - 1) * CALLS_PER_PAGE 

    conn = get_db_connection()
    all_calls = conn.execute(
        "SELECT * FROM calls WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (user_id, CALLS_PER_PAGE, offset)
    ).fetchall()

    total_calls = conn.execute(
        "SELECT COUNT(*) FROM calls WHERE user_id = ?",
        (user_id,)
    ).fetchone()[0]
    conn.close()

    total_pages = (total_calls + CALLS_PER_PAGE - 1) // CALLS_PER_PAGE 

    return render_template('view_all_calls.html', 
                           all_calls=all_calls,
                           page=page,
                           total_pages=total_pages)

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

    if session['user_role'] == 'USUARIO' and call['user_id'] != session['user_id']:
        flash('Acesso negado. Você não tem permissão para visualizar este chamado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))
    
    technician_name = None
    if call['technician_id']:
        tech_user = conn.execute("SELECT name FROM users WHERE id = ?", (call['technician_id'],)).fetchone()
        if tech_user:
            technician_name = tech_user['name']

    # Buscar anexos do chamado
    attachments = conn.execute(
        "SELECT id, filename, filepath FROM call_attachments WHERE call_id = ?",
        (call_id,)
    ).fetchall()

    # Buscar técnicos disponíveis para atribuição (apenas para ADMIN/TECNICO)
    available_technicians = []
    if session['user_role'] in ['ADMIN', 'TECNICO']:
        available_technicians = conn.execute("SELECT id, name FROM users WHERE role = 'TECNICO' ORDER BY name").fetchall()

    conn.close()
    return render_template('call_details.html', 
                           call=call, 
                           technician_name=technician_name,
                           user_role=session['user_role'],
                           attachments=attachments, # Passa os anexos para o template
                           available_technicians=available_technicians, # Passa técnicos para atribuição
                           json_loads=json.loads # Passa a função json.loads diretamente
                           )

@app.route('/download_attachment/<filename>')
def download_attachment(filename):
    """
    Permite o download de um anexo.
    """
    # Você pode adicionar lógica de segurança aqui para verificar se o usuário tem permissão
    # de baixar este arquivo, por exemplo, se ele está logado e tem acesso ao chamado.
    # Por enquanto, estamos apenas servindo o arquivo.
    return send_from_directory(app.config['UPLOAD_FOLDER_ATTACHMENTS'], filename, as_attachment=True)


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

    if call['status'] in ['Concluído', 'Cancelado']:
        flash(f'Este chamado já está {call["status"]}. Não pode ser atendido novamente.', 'warning')
        conn.close()
        return redirect(url_for('call_details', call_id=call_id))

    # Lógica para GET (quando o técnico clica em "Atender/Finalizar Chamado")
    if request.method == 'GET':
        if call['status'] == 'Aberto':
            try:
                # Atribui o chamado ao técnico logado e muda o status para 'Em Andamento'
                conn.execute(
                    "UPDATE calls SET technician_id = ?, status = ? WHERE id = ?",
                    (session['user_id'], 'Em Andamento', call_id)
                )
                conn.commit()
                flash(f'Chamado #{call_id} atribuído a você e status alterado para "Em Andamento".', 'success')

                # Notificar o usuário que abriu o chamado
                message_user = f"Seu chamado: '{call['title']}' foi atribuído ao técnico {session['user_name']} e está 'Em Andamento'."
                link_user = url_for('call_details', call_id=call_id)
                add_notification(call['user_id'], message_user, link_user, 'call_update', call_id)

                # Notificar administradores
                admin_users = conn.execute("SELECT id FROM users WHERE role = 'ADMIN'").fetchall()
                for admin in admin_users:
                    message_admin = f"Chamado: '{call['title']}' foi atribuído a {session['user_name']} e está 'Em Andamento'."
                    link_admin = url_for('call_details', call_id=call_id)
                    add_notification(admin['id'], message_admin, link_admin, 'call_update', call_id)

                # Recarrega o objeto 'call' para refletir as mudanças
                call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()

            except Exception as e:
                flash(f'Erro ao iniciar atendimento do chamado: {e}', 'danger')
                print(f"Erro ao iniciar atendimento do chamado: {e}")
                conn.rollback() # Garante que as mudanças não sejam salvas em caso de erro

    # Lógica para POST (quando o técnico envia o formulário de diagnóstico/conclusão)
    if request.method == 'POST':
        diagnosis = request.form['diagnosis']
        materials_json = request.form.get('materials_used', '[]') 
        conclusion = request.form.get('conclusion', '') 
        
        try:
            materials_list = json.loads(materials_json) 
            if not isinstance(materials_list, list):
                materials_list = []
        except json.JSONDecodeError:
            flash('Erro ao processar materiais: Formato JSON inválido.', 'danger')
            materials_list = []

        action = request.form['action'] 
        technician_id = session['user_id']
        finished_at = None
        old_status = call['status'] 

        if action == 'finish_call':
            if not diagnosis: 
                flash('Diagnóstico é obrigatório para finalizar o chamado.', 'danger')
                stock_items_raw = conn.execute("SELECT * FROM stock_items").fetchall()
                stock_items = [dict(item) for item in stock_items_raw]
                conn.close()
                return render_template('attend_call.html', call=call, stock_items=stock_items)
            if not conclusion:
                flash('Conclusão é obrigatória para finalizar o chamado.', 'danger')
                stock_items_raw = conn.execute("SELECT * FROM stock_items").fetchall()
                stock_items = [dict(item) for item in stock_items_raw]
                conn.close()
                return render_template('attend_call.html', call=call, stock_items=stock_items)
            
            # Validação e Dedução de materiais do estoque
            deduction_successful = True
            for material_entry in materials_list:
                material_name = material_entry.get('name')
                quantity_used = material_entry.get('quantity')

                if material_name and quantity_used is not None:
                    try:
                        quantity_used = int(quantity_used)
                        if quantity_used <= 0:
                            continue 

                        stock_item = conn.execute("SELECT * FROM stock_items WHERE name = ?", (material_name,)).fetchone()
                        if stock_item:
                            if stock_item['quantity'] < quantity_used:
                                flash(f'Erro: Quantidade insuficiente de "{material_name}" no estoque. Disponível: {stock_item["quantity"]}, Solicitado: {quantity_used}.', 'danger')
                                deduction_successful = False
                                break 
                            
                            new_quantity = stock_item['quantity'] - quantity_used
                            conn.execute(
                                "UPDATE stock_items SET quantity = ?, last_updated = ? WHERE id = ?",
                                (new_quantity, datetime.now().strftime('%Y-%m-%d %H:%M:%S'), stock_item['id'])
                            )
                        else:
                            flash(f'Erro: Material "{material_name}" não encontrado no estoque.', 'danger')
                            deduction_successful = False
                            break
                    except ValueError:
                        flash(f'Erro: Quantidade inválida para o material "{material_name}".', 'danger')
                        deduction_successful = False
                        break
                    except Exception as e:
                        flash(f'Erro inesperado ao deduzir material "{material_name}": {e}', 'danger')
                        deduction_successful = False
                        break
            
            if not deduction_successful:
                conn.rollback() 
                stock_items_raw = conn.execute("SELECT * FROM stock_items ORDER BY name").fetchall()
                stock_items = [dict(item) for item in stock_items_raw]
                conn.close()
                return render_template('attend_call.html', call=call, stock_items=stock_items)

            status = 'Concluído'
            finished_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            # Salva a lista de materiais como JSON string
            materials_to_save = json.dumps(materials_list) 
        elif action == 'start_attendance':
            # Esta parte do 'start_attendance' via POST não deve ser mais necessária
            # pois a atribuição e mudança de status agora ocorrem no GET
            status = 'Em Andamento'
            materials_to_save = call['materials'] # Mantém os materiais existentes
            diagnosis = request.form['diagnosis'] 
            conclusion = call['conclusion'] 
        else:
            flash('Ação inválida.', 'danger')
            stock_items_raw = conn.execute("SELECT * FROM stock_items").fetchall()
            stock_items = [dict(item) for item in stock_items_raw]
            conn.close()
            return render_template('attend_call.html', call=call, stock_items=stock_items)

        try:
            conn.execute(
                """
                UPDATE calls 
                SET status = ?, technician_id = ?, diagnosis = ?, materials = ?, conclusion = ?, finished_at = ?
                WHERE id = ?
                """,
                (status, technician_id, diagnosis, materials_to_save, conclusion, finished_at, call_id) # Usa materials_to_save
            )
            conn.commit()

            # Lidar com uploads de arquivos para o chamado (para técnicos)
            if 'attachments' in request.files:
                files = request.files.getlist('attachments')
                for file in files:
                    if file and allowed_file(file.filename):
                        original_filename = secure_filename(file.filename)
                        file_extension = original_filename.rsplit('.', 1)[1].lower()
                        unique_filename = str(uuid4()) + '.' + file_extension
                        file_path = os.path.join(app.config['UPLOAD_FOLDER_ATTACHMENTS'], unique_filename)
                        file.save(file_path)
                        
                        conn.execute(
                            "INSERT INTO call_attachments (call_id, filename, filepath, uploaded_by_user_id) VALUES (?, ?, ?, ?)",
                            (call_id, original_filename, '/' + file_path.replace('\\', '/'), session['user_id'])
                        )
                        conn.commit()
                        flash(f'Anexo "{original_filename}" enviado com sucesso!', 'info')
                    elif file.filename != '':
                        flash(f'Tipo de arquivo não permitido para anexo: {file.filename}.', 'warning')

            flash(f'Chamado #{call_id} atualizado para "{status}" com sucesso!', 'success')

            message_user = f"Seu chamado: '{call['title']}'"
            link_user = url_for('call_details', call_id=call_id)
            add_notification(call['user_id'], message_user, link_user, 'call_update', call_id)

            admin_users = conn.execute("SELECT id FROM users WHERE role = 'ADMIN'").fetchall()
            for admin in admin_users:
                message_admin = f"Chamado: '{call['title']}'"
                link_admin = url_for('call_details', call_id=call_id)
                add_notification(admin['id'], message_admin, link_admin, 'call_update', call_id)

            return redirect(url_for('call_details', call_id=call_id))
        except Exception as e:
            flash(f'Erro ao atualizar o chamado: {e}', 'danger')
            conn.rollback() 
        finally:
            conn.close()
    
    # Ao carregar a página GET, converte stock_items para dicionários
    stock_items_raw = conn.execute("SELECT * FROM stock_items ORDER BY name").fetchall()
    stock_items = [dict(item) for item in stock_items_raw]
    conn.close() 
    return render_template('attend_call.html', call=call, stock_items=stock_items)


@app.route('/cancel_call/<int:call_id>', methods=['POST'])
def cancel_call(call_id):
    """
    Rota para Administradores ou Técnicos cancelarem um chamado.
    """
    if 'user_id' not in session or session['user_role'] not in ['ADMIN', 'TECNICO']:
        flash('Acesso negado. Apenas administradores ou técnicos podem cancelar chamados.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()

    if not call:
        flash('Chamado não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    if call['status'] in ['Concluído', 'Cancelado']:
        flash(f'Este chamado já está {call["status"]}. Não pode ser cancelado.', 'warning')
        conn.close()
        return redirect(url_for('call_details', call_id=call_id))

    status = 'Cancelado'
    finished_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        conn.execute(
            """
            UPDATE calls
            SET status = ?, finished_at = ?
            WHERE id = ?
            """,
            (status, finished_at, call_id)
        )
        conn.commit()
        flash(f'Chamado #{call_id} cancelado com sucesso.', 'success')

        message_user = f"Seu chamado: '{call['title']}' foi cancelado."
        link_user = url_for('call_details', call_id=call_id)
        add_notification(call['user_id'], message_user, link_user, 'call_update', call_id)

        return redirect(url_for('call_details', call_id=call_id))
    except Exception as e:
        flash(f'Erro ao cancelar o chamado: {e}', 'danger')
        print(f"Erro ao cancelar chamado: {e}")
    finally:
        conn.close()


@app.route('/filtered_calls/<status_filter>')
def filtered_calls(status_filter):
    """
    Rota para técnicos visualizarem chamados filtrados por status.
    Apenas TECNICOS podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'TECNICO':
        flash('Acesso negado. Apenas técnicos podem visualizar chamados filtrados.', 'danger')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int) 
    offset = (page - 1) * CALLS_PER_PAGE 

    conn = get_db_connection()
    calls = []
    title = ""
    total_calls = 0 

    base_query = """
        SELECT c.*, u.name as user_name_opener, t.name as technician_name_assigned
        FROM calls c 
        JOIN users u ON c.user_id = u.id 
        LEFT JOIN users t ON c.technician_id = t.id
    """
    count_query = "SELECT COUNT(*) FROM calls"
    query_params = []
    count_params = []

    if status_filter == 'abertos':
        base_query += " WHERE c.status = 'Aberto'"
        count_query += " WHERE status = 'Aberto'"
        title = "Chamados Abertos"
    elif status_filter == 'em_atendimento':
        base_query += " WHERE c.status = 'Em Andamento'"
        count_query += " WHERE status = 'Em Andamento'"
        title = "Chamados em Atendimento"
    elif status_filter == 'finalizados':
        base_query += " WHERE c.status = 'Concluído'"
        count_query += " WHERE status = 'Concluído'"
        title = "Chamados Finalizados"
    elif status_filter == 'todos': 
        title = "Todos os Chamados"
    else:
        flash('Filtro de status inválido.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    base_query += " ORDER BY c.created_at DESC LIMIT ? OFFSET ?"
    query_params.extend([CALLS_PER_PAGE, offset])

    calls = conn.execute(base_query, query_params).fetchall()
    total_calls = conn.execute(count_query, count_params).fetchone()[0] 

    conn.close()

    total_pages = (total_calls + CALLS_PER_PAGE - 1) // CALLS_PER_PAGE 

    return render_template('filtered_calls.html', 
                           calls=calls, 
                           title=title, 
                           status_filter=status_filter,
                           page=page, 
                           total_pages=total_pages) 

@app.route('/admin_calls')
def admin_calls():
    """
    Rota para Administradores visualizarem todos os chamados com paginação.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem visualizar todos os chamados.', 'danger')
        return redirect(url_for('login'))

    page = request.args.get('page', 1, type=int) 
    offset = (page - 1) * CALLS_PER_PAGE 

    conn = get_db_connection()
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

    total_calls = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    conn.close()

    total_pages = (total_calls + CALLS_PER_PAGE - 1) // CALLS_PER_PAGE 
    
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
    
    page = request.args.get('page', 1, type=int) 
    search_query = request.args.get('search', '').strip() 
    role_filter = request.args.get('role_filter', '').strip() # NOVO: Obtém o filtro de função
    offset = (page - 1) * USERS_PER_PAGE 

    conn = get_db_connection()
    
    # Modificado: Exclui o ADM principal (is_primary_admin = 1) e o próprio usuário logado
    base_query = "SELECT id, name, email, role, created_at, is_primary_admin, profile_image FROM users WHERE is_primary_admin != 1 AND id != ?" 
    count_query = "SELECT COUNT(*) FROM users WHERE is_primary_admin != 1 AND id != ?"
    query_params = [session['user_id']] # Exclui o próprio usuário logado
    
    # Se houver filtro de função, adiciona a condição
    if role_filter:
        base_query += " AND role = ?"
        count_query += " AND role = ?"
        query_params.append(role_filter)

    # Se houver busca, adiciona as condições de busca
    if search_query:
        base_query += " AND (name LIKE ? OR email LIKE ?)"
        count_query += " AND (name LIKE ? OR email LIKE ?)"
        query_params.extend([f"%{search_query}%", f"%{search_query}%"])
    
    base_query += " ORDER BY name LIMIT ? OFFSET ?"
    query_params.extend([USERS_PER_PAGE, offset])

    users = conn.execute(base_query, tuple(query_params)).fetchall()

    # Para a contagem total, remove os parâmetros de limite e offset
    count_query_params = [session['user_id']]
    if role_filter: # Inclui o filtro de função na contagem
        count_query_params.append(role_filter)
    if search_query:
        count_query_params.extend([f"%{search_query}%", f"%{search_query}%"])

    total_users = conn.execute(count_query, tuple(count_query_params)).fetchone()[0]
    conn.close()

    total_pages = (total_users + USERS_PER_PAGE - 1) // USERS_PER_PAGE 
    
    return render_template('manage_users.html', 
                           users=users, 
                           page=page, 
                           total_pages=total_pages,
                           search_query=search_query,
                           role_filter=role_filter) # NOVO: Passa o filtro de função para o template

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
    
    is_viewed_user_primary_admin = user['is_primary_admin'] == 1

    print(f"DEBUG: Caminho da imagem de perfil para user_id {user_id}: {user['profile_image']}")

    return render_template('user_details.html', 
                           user=user, 
                           is_viewed_user_primary_admin=is_viewed_user_primary_admin,
                           logged_in_is_primary_admin=session.get('is_primary_admin', 0)) 


@app.route('/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    """
    Permite que o administrador edite os dados de um usuário (nome, email, função)
    e redefina a senha.
    Apenas ADMINs podem acessar esta rota.
    O ADM principal não pode editar a função de outro ADM principal.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem editar usuários.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    user = conn.execute("SELECT id, name, email, role, is_primary_admin FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash('Usuário não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('manage_users'))

    # Previne que um ADM secundário edite outro ADM (incluindo o principal)
    if session.get('is_primary_admin', 0) == 0 and user['role'] == 'ADMIN':
        flash('Acesso negado. Você não tem permissão para editar outros administradores.', 'danger')
        conn.close()
        return render_template('edit_user_form.html', user=user)

    if request.method == 'POST':
        name = request.form['name'].strip()
        email = request.form['email'].strip()
        role = request.form['role']
        new_password = request.form.get('new_password', '').strip() # Campo opcional para nova senha

        if not name or not email or not role:
            flash('Todos os campos (Nome, Email, Função) são obrigatórios.', 'danger')
            conn.close()
            return render_template('edit_user_form.html', user=user)

        # Validação de email único (exceto para o próprio usuário sendo editado)
        existing_user_with_email = conn.execute(
            "SELECT id FROM users WHERE email = ? AND id != ?", (email, user_id)
        ).fetchone()
        if existing_user_with_email:
            flash('Este email já está em uso por outro usuário. Por favor, escolha outro.', 'danger')
            conn.close()
            return render_template('edit_user_form.html', user=user)

        # Previne que um ADM principal mude sua própria função para não-ADM
        if user['id'] == session['user_id'] and user['is_primary_admin'] == 1 and role != 'ADMIN':
            flash('O Administrador principal não pode alterar sua própria função.', 'danger')
            conn.close()
            return render_template('edit_user_form.html', user=user)

        # Prepara a query de atualização
        update_query = "UPDATE users SET name = ?, email = ?, role = ?"
        update_params = [name, email, role]

        if new_password:
            password_hash = generate_password_hash(new_password)
            update_query += ", password_hash = ?"
            update_params.append(password_hash)
            flash('Senha do usuário redefinida com sucesso!', 'info')

        update_query += " WHERE id = ?"
        update_params.append(user_id)

        try:
            conn.execute(update_query, tuple(update_params))
            conn.commit()
            flash(f'Usuário "{name}" atualizado com sucesso!', 'success')
            
            # Se o próprio usuário logado teve seu email ou nome alterado, atualiza a sessão
            if user_id == session['user_id']:
                session['user_name'] = name
                # session['user_email'] = email # Não é necessário, já que 'user_email' não é usado na sessão
                session['user_role'] = role # Atualiza a role na sessão caso o próprio ADM mude a sua
            
            return redirect(url_for('manage_users'))
        except Exception as e:
            flash(f'Erro ao atualizar usuário: {e}', 'danger')
            print(f"Erro ao atualizar usuário: {e}")
        finally:
            conn.close()
            
    conn.close()
    return render_template('edit_user_form.html', user=user)


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
            existing_user = conn.execute("SELECT id FROM users WHERE email = ? AND id != ?", (new_email, user_id)).fetchone()
            if existing_user:
                flash('Este email já está em uso por outro usuário. Por favor, escolha outro.', 'danger')
                conn.close()
                return render_template('edit_profile.html', user=user)

            conn.execute("UPDATE users SET email = ? WHERE id = ?", (new_email, user_id))
            conn.commit()
            # session['user_email'] = new_email # Não é necessário, já que 'user_email' não é usado na sessão
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


@app.route('/delete_material/<int:item_id>', methods=['POST'])
def delete_material(item_id):
    """
    Rota para o Administrador excluir um material do estoque.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem excluir materiais.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    item_to_delete = conn.execute("SELECT * FROM stock_items WHERE id = ?", (item_id,)).fetchone()

    if not item_to_delete:
        flash('Material não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('manage_stock'))

    try:
        conn.execute("DELETE FROM stock_items WHERE id = ?", (item_id,)) 
        conn.commit()
        flash(f'Material "{item_to_delete["name"]}" excluído com sucesso.', 'success')
    except Exception as e:
        flash(f'Erro ao excluir material: {e}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('manage_stock'))


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
    
    page = request.args.get('page', 1, type=int) 
    offset = (page - 1) * ITEMS_PER_PAGE 

    conn = get_db_connection()
    stock_items = conn.execute(
        "SELECT * FROM stock_items ORDER BY name LIMIT ? OFFSET ?",
        (ITEMS_PER_PAGE, offset)
    ).fetchall()

    total_items = conn.execute("SELECT COUNT(*) FROM stock_items").fetchone()[0]
    conn.close()

    total_pages = (total_items + ITEMS_PER_PAGE - 1) // ITEMS_PER_PAGE 

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
            conn.close()
            return render_template('insert_material.html')

        conn = get_db_connection()
        try:
            conn.execute(
                "INSERT INTO stock_items (name, quantity, unit, last_updated) VALUES (?, ?, ?, ?)",
                (name, quantity, unit, last_updated)
            )
            conn.commit()
            flash(f'Material "{name}" inserido com sucesso!', 'success')
            return render_template('insert_material.html') 
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
            return redirect(url_for('manage_stock')) 
        except sqlite3.IntegrityError:
            flash('Já existe outro material com este nome. Por favor, use um nome diferente.', 'danger')
        except Exception as e:
            flash(f'Erro ao atualizar material: {e}', 'danger')
        finally:
            conn.close()
    
    conn.close()
    return render_template('edit_material_form.html', item=item)


@app.route('/get_notifications')
def get_notifications():
    """
    Retorna as notificações não lidas para o usuário logado.
    Agora inclui o título do chamado, status, created_at e finished_at para cálculo do tempo relativo e expiração.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401

    user_id = session['user_id']
    conn = get_db_connection()
    notifications_raw = conn.execute(
        """
        SELECT n.id, n.message, n.link, n.is_read, n.created_at, n.notification_type,
               c.title AS call_title, c.status AS call_status, c.created_at AS call_created_at,
               c.finished_at AS call_finished_at
        FROM notifications n
        LEFT JOIN calls c ON n.call_id = c.id
        WHERE n.user_id = ?
        ORDER BY n.created_at DESC LIMIT 10
        """,
        (user_id,)
    ).fetchall()
    
    notifications_list = []
    current_time = datetime.now()

    for n in notifications_raw:
        notification_dict = dict(n)
        
        # Determine the relevant timestamp for relative time calculation
        # and check for expiration if it's a completed call notification
        if notification_dict['notification_type'] in ['new_call', 'call_update']:
            notification_dict['title'] = notification_dict['call_title']
            notification_dict['status'] = notification_dict['call_status']
            notification_dict['call_creation_time'] = notification_dict['call_created_at']
            
            # Check for expiration for 'Concluído' calls
            if notification_dict['call_status'] == 'Concluído' and notification_dict['call_finished_at']:
                try:
                    finished_dt = datetime.strptime(notification_dict['call_finished_at'], '%Y-%m-%d %H:%M:%S')
                    # Adiciona uma hora ao tempo de conclusão do chamado
                    expiration_time = finished_dt + timedelta(hours=1)
                    
                    if current_time > expiration_time:
                        # Esta notificação deve expirar, então pule-a
                        continue 
                except ValueError as e:
                    print(f"DEBUG: Erro ao parsear finished_at para notificação {notification_dict['id']}: {e}")
                    # Se a análise falhar, não a expire, apenas registre o erro
                    pass 
        else:
            # Para outros tipos de notificação, usa a mensagem original e a data de criação da notificação
            notification_dict['title'] = notification_dict['message']
            notification_dict['status'] = None
            notification_dict['call_creation_time'] = notification_dict['created_at']

        notifications_list.append(notification_dict)

    # Recalcula a contagem de não lidas com base na lista filtrada para precisão
    filtered_unread_count = sum(1 for n in notifications_list if not n['is_read'])

    conn.close()

    return jsonify({'notifications': notifications_list, 'unread_count': filtered_unread_count})

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
def mark_notification_read(notification_id):
    """
    Marca uma notificação específica como lida para o usuário logado.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?",
            (notification_id, user_id)
        )
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao marcar notificação {notification_id} como lida: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/mark_all_notifications_read', methods=['POST'])
def mark_all_notifications_read():
    """
    Marca todas as notificações não lidas como lidas para o usuário logado.
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Não autorizado'}), 401
    
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        conn.execute(
            "UPDATE notifications SET is_read = 1 WHERE user_id = ? AND is_read = 0",
            (user_id,)
        )
        conn.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Erro ao marcar todas as notificações como lidas: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        conn.close()

# --- Rotas de Relatórios do Administrador ---

@app.route('/admin/reports/technician_performance')
def technician_performance_report():
    """
    Gera um relatório de desempenho dos técnicos.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem acessar relatórios.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    technicians = conn.execute("SELECT id, name FROM users WHERE role = 'TECNICO'").fetchall()
    
    report_data = []
    for tech in technicians:
        # Chamados concluídos pelo técnico
        completed_calls = conn.execute(
            "SELECT created_at, finished_at FROM calls WHERE technician_id = ? AND status = 'Concluído'",
            (tech['id'],)
        ).fetchall()
        
        total_completed = len(completed_calls)
        total_duration_seconds = 0
        
        for call in completed_calls:
            if call['created_at'] and call['finished_at']:
                try:
                    created_dt = datetime.strptime(call['created_at'], '%Y-%m-%d %H:%M:%S')
                    finished_dt = datetime.strptime(call['finished_at'], '%Y-%m-%d %H:%M:%S')
                    duration = finished_dt - created_dt
                    total_duration_seconds += duration.total_seconds()
                except ValueError:
                    # Ignora chamados com datas inválidas
                    continue
        
        avg_resolution_time_hours = 0
        if total_completed > 0:
            avg_resolution_time_hours = (total_duration_seconds / total_completed) / 3600
        
        # Chamados em andamento atribuídos ao técnico
        in_progress_calls = conn.execute(
            "SELECT COUNT(*) FROM calls WHERE technician_id = ? AND status = 'Em Andamento'",
            (tech['id'],)
        ).fetchone()[0]

        report_data.append({
            'name': tech['name'],
            'total_completed_calls': total_completed,
            'avg_resolution_time_hours': round(avg_resolution_time_hours, 2),
            'in_progress_calls': in_progress_calls
        })
    
    conn.close()
    return render_template('technician_performance_report.html', report_data=report_data)

@app.route('/admin/reports/material_usage')
def material_usage_report():
    """
    Gera um relatório de uso de materiais.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem acessar relatórios.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    all_calls_with_materials = conn.execute(
        "SELECT materials FROM calls WHERE materials IS NOT NULL AND materials != ''"
    ).fetchall()
    conn.close()

    material_summary = {}

    for call in all_calls_with_materials:
        try:
            # Tenta carregar a string JSON
            materials_list = json.loads(call['materials'])
            if not isinstance(materials_list, list):
                continue # Pula se não for uma lista
            
            for item in materials_list:
                material_name = item.get('name')
                quantity = item.get('quantity')
                
                if material_name and isinstance(quantity, (int, float)):
                    material_summary[material_name] = material_summary.get(material_name, 0) + quantity
        except json.JSONDecodeError:
            print(f"DEBUG: Erro ao decodificar JSON de materiais para o chamado: {call['materials']}")
            continue # Pula se o JSON for inválido

    # Converte o dicionário para uma lista de dicionários para facilitar a exibição no Jinja
    report_data = [{'name': name, 'total_quantity_used': quantity} for name, quantity in material_summary.items()]
    report_data.sort(key=lambda x: x['total_quantity_used'], reverse=True) # Ordena por quantidade usada

    return render_template('material_usage_report.html', report_data=report_data)

@app.route('/admin/reports/calls_by_breakdown')
def calls_by_breakdown_report():
    """
    Gera um relatório de chamados por categoria e localização.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        flash('Acesso negado. Apenas administradores podem acessar relatórios.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    
    # Chamados por Categoria
    calls_by_category_raw = conn.execute(
        "SELECT category, COUNT(*) as count FROM calls GROUP BY category ORDER BY count DESC"
    ).fetchall()
    calls_by_category = [{'label': row['category'], 'value': row['count']} for row in calls_by_category_raw]

    # Chamados por Localização
    calls_by_location_raw = conn.execute(
        "SELECT location, COUNT(*) as count FROM calls GROUP BY location ORDER BY count DESC"
    ).fetchall()
    calls_by_location = [{'label': row['location'], 'value': row['count']} for row in calls_by_location_raw]
    
    conn.close()
    
    return render_template('calls_by_breakdown_report.html', 
                           calls_by_category=calls_by_category, 
                           calls_by_location=calls_by_location)

@app.route('/assign_technician/<int:call_id>', methods=['POST'])
def assign_technician(call_id):
    """
    Permite que um ADMIN ou TECNICO atribua um chamado a um técnico.
    """
    if 'user_id' not in session or session['user_role'] not in ['ADMIN', 'TECNICO']:
        flash('Acesso negado. Você não tem permissão para atribuir chamados.', 'danger')
        return redirect(url_for('login'))

    technician_id = request.form.get('technician_id', type=int)
    
    if not technician_id:
        flash('Técnico não selecionado.', 'danger')
        return redirect(url_for('call_details', call_id=call_id))

    conn = get_db_connection()
    call = conn.execute("SELECT * FROM calls WHERE id = ?", (call_id,)).fetchone()
    
    if not call:
        flash('Chamado não encontrado.', 'danger')
        conn.close()
        return redirect(url_for('dashboard'))

    # Se o chamado já tem um técnico e o status não é 'Aberto', não permitir reatribuição direta
    # A menos que o status seja 'Em Andamento' e o técnico seja o mesmo que está tentando reatribuir
    if call['technician_id'] and call['status'] != 'Aberto' and call['technician_id'] != session['user_id']:
        flash('Este chamado já está em andamento com outro técnico e não pode ser reatribuído diretamente.', 'warning')
        conn.close()
        return redirect(url_for('call_details', call_id=call_id))
    
    # Se o chamado está "Aberto" ou se o técnico atual está reatribuindo para si mesmo (iniciar atendimento)
    status_to_set = call['status']
    if call['status'] == 'Aberto':
        status_to_set = 'Em Andamento' # Mudar status para Em Andamento ao atribuir

    try:
        conn.execute(
            "UPDATE calls SET technician_id = ?, status = ? WHERE id = ?",
            (technician_id, status_to_set, call_id)
        )
        conn.commit()
        flash(f'Chamado #{call_id} atribuído com sucesso!', 'success')

        # Notificar o usuário que abriu o chamado
        message_user = f"Seu chamado: '{call['title']}' foi atribuído."
        link_user = url_for('call_details', call_id=call_id)
        add_notification(call['user_id'], message_user, link_user, 'call_update', call_id)

        # Notificar o técnico atribuído
        if technician_id != session['user_id']: # Evita notificar a si mesmo se for o técnico que atribuiu
            assigned_tech = conn.execute("SELECT name FROM users WHERE id = ?", (technician_id,)).fetchone()
            if assigned_tech:
                message_tech = f"Você foi atribuído ao chamado: '{call['title']}'."
                link_tech = url_for('call_details', call_id=call_id)
                add_notification(technician_id, message_tech, link_tech, 'call_update', call_id)

        return redirect(url_for('call_details', call_id=call_id))
    except Exception as e:
        flash(f'Erro ao atribuir técnico: {e}', 'danger')
        print(f"Erro ao atribuir técnico: {e}")
    finally:
        conn.close()


# --- Novas Rotas de API para Gráficos do Administrador ---

@app.route('/api/admin_dashboard_summary')
def admin_dashboard_summary():
    """
    Retorna um resumo dos chamados por status para o dashboard do administrador.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    try:
        open_calls = conn.execute("SELECT COUNT(*) FROM calls WHERE status = 'Aberto'").fetchone()[0]
        in_progress_calls = conn.execute("SELECT COUNT(*) FROM calls WHERE status = 'Em Andamento'").fetchone()[0]
        completed_calls = conn.execute("SELECT COUNT(*) FROM calls WHERE status = 'Concluído'").fetchone()[0]
        canceled_calls = conn.execute("SELECT COUNT(*) FROM calls WHERE status = 'Cancelado'").fetchone()[0] 
        
        return jsonify({
            'open': open_calls,
            'in_progress': in_progress_calls,
            'completed': completed_calls,
            'canceled': canceled_calls 
        })
    except Exception as e:
        print(f"Erro ao buscar resumo do dashboard do admin: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        conn.close()

@app.route('/api/admin_calls_by_day')
def admin_calls_by_day():
    """
    Retorna a contagem de chamados criados por dia nos últimos 30 dias.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    try:
        thirty_days_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d %H:%M:%S')

        calls_data = conn.execute(
            """
            SELECT substr(created_at, 1, 10) as call_date, COUNT(*) as count
            FROM calls
            WHERE created_at >= ?
            GROUP BY call_date
            ORDER BY call_date ASC
            """,
            (thirty_days_ago,)
        ).fetchall()

        date_counts = {row['call_date']: row['count'] for row in calls_data}
        
        all_dates = []
        for i in range(30):
            date = (datetime.now() - timedelta(days=29 - i)).strftime('%Y-%m-%d') 
            all_dates.append(date)

        formatted_data = []
        for date in all_dates:
            formatted_data.append({
                'date': date,
                'count': date_counts.get(date, 0)
            })
        
        return jsonify(formatted_data)
    except Exception as e:
        print(f"Erro ao buscar chamados por dia: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        conn.close()

@app.route('/api/admin_average_resolution_time')
def admin_average_resolution_time():
    """
    Retorna o tempo médio de resolução para chamados concluídos, e dados para um histograma de resolução.
    Apenas ADMINs podem acessar esta rota.
    """
    if 'user_id' not in session or session['user_role'] != 'ADMIN':
        return jsonify({'error': 'Acesso negado'}), 403

    conn = get_db_connection()
    try:
        completed_calls = conn.execute(
            "SELECT created_at, finished_at FROM calls WHERE status = 'Concluído' AND finished_at IS NOT NULL"
        ).fetchall()

        total_duration_seconds = 0
        durations_in_hours = [] 

        for call in completed_calls:
            try:
                created_dt = datetime.strptime(call['created_at'], '%Y-%m-%d %H:%M:%S')
                finished_dt = datetime.strptime(call['finished_at'], '%Y-%m-%d %H:%M:%S')
                duration = finished_dt - created_dt
                total_duration_seconds += duration.total_seconds()
                durations_in_hours.append(duration.total_seconds() / 3600) 
            except (ValueError, TypeError) as e:
                print(f"Erro ao parsear datas para chamado: {call} - {e}")
                continue 

        average_duration_hours = 0
        if completed_calls:
            average_duration_hours = (total_duration_seconds / len(completed_calls)) / 3600 

        bins = [0, 24, 48, 72, 168, 336, 720] 
        bin_labels = ['<1 dia', '1-2 dias', '2-3 dias', '3-7 dias', '7-14 dias', '14-30 dias', '>30 dias']
        
        if durations_in_hours:
            max_duration = max(durations_in_hours)
            if max_duration >= bins[-1]:
                bins.append(max_duration + 1) 

        histogram_data = {label: 0 for label in bin_labels}

        for duration_hours in durations_in_hours:
            assigned_to_bin = False
            for i in range(len(bins) - 1):
                if bins[i] <= duration_hours < bins[i+1]:
                    histogram_data[bin_labels[i]] += 1
                    assigned_to_bin = True
                    break
            if not assigned_to_bin and duration_hours >= bins[-1]: 
                 histogram_data[bin_labels[-1]] += 1

        histogram_list = [{"range": label, "count": histogram_data[label]} for label in bin_labels]

        return jsonify({
            'average_duration_hours': round(average_duration_hours, 2),
            'histogram_data': histogram_list
        })
    except Exception as e:
        print(f"Erro ao calcular tempo médio de resolução: {e}")
        return jsonify({'error': 'Erro interno do servidor'}), 500
    finally:
        conn.close()


@app.route('/logout')
def logout():
    """
    Rota para deslogar o usuário, limpando a sessão.
    """
    session.pop('user_id', None)
    session.pop('user_name', None)
    session.pop('user_role', None)
    session.pop('is_primary_admin', None) 
    session.pop('profile_image', None) 
    flash('Você foi desconectado(a).', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
