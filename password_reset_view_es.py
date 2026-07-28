# password_reset_view_es.py - Versión en Español para PostgreSQL
from flask import render_template, request, jsonify, flash, redirect, url_for
from flask_appbuilder import expose, has_access
from flask_appbuilder.security.decorators import protect
from flask_babel import lazy_gettext as _
from superset import appbuilder, db, security_manager
from superset.views.base import BaseSupersetView
import secrets
import string
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from flask_bcrypt import Bcrypt
from sqlalchemy import text, inspect
from sqlalchemy.exc import SQLAlchemyError
import json

logger = logging.getLogger(__name__)
bcrypt = Bcrypt()

class PlantillaEmail:
    """Gestor de plantillas de email en español"""
    
    # Plantilla por defecto en español
    DEFAULT_TEMPLATE = {
        'asunto': '{app_name} - Restablecimiento de Contraseña',
        'saludo': 'Hola {first_name or username},',
        'intro': 'Su contraseña para {app_name} ha sido restablecida por un administrador.',
        'etiqueta_password': 'Nueva Contraseña',
        'nota_importante': '⚠️ Importante: Por razones de seguridad, cambie esta contraseña inmediatamente después de iniciar sesión.',
        'boton_accion': 'Iniciar Sesión en {app_name}',
        'cierre': 'Saludos cordiales,',
        'firma': 'Equipo de {app_name}',
        'pie_pagina': 'Este es un mensaje automático. Por favor, no responda a este correo.\nSi no solicitó este restablecimiento, contacte a su administrador inmediatamente.',
        'mensaje_adicional': ''  # Para mensajes personalizados
    }
    
    def __init__(self):
        self.custom_templates = {}  # Almacenar templates personalizados en memoria
    
    def get_template(self, lang='es'):
        """Obtener plantilla (siempre español)"""
        # Si hay template personalizado, usarlo
        if lang in self.custom_templates:
            template = self.custom_templates[lang].copy()
            # Asegurar que todos los campos existan
            for key, value in self.DEFAULT_TEMPLATE.items():
                if key not in template or not template[key]:
                    template[key] = value
            return template
        return self.DEFAULT_TEMPLATE.copy()
    
    def render(self, template, **kwargs):
        """Renderizar plantilla con variables"""
        defaults = {
            'app_name': 'Superset',
            'base_url': '',
            'first_name': 'Usuario',
            'username': 'usuario',
            'email': '',
            'new_password': '',
            'mensaje_adicional': ''
        }
        defaults.update(kwargs)
        
        rendered = {}
        for key, value in template.items():
            if isinstance(value, str):
                try:
                    rendered[key] = value.format(**defaults)
                except KeyError:
                    rendered[key] = value
            else:
                rendered[key] = value
        
        return rendered
    
    def save_template(self, lang, template_data):
        """Guardar plantilla personalizada"""
        # Validar que todos los campos requeridos estén presentes
        required_fields = ['asunto', 'saludo', 'intro', 'etiqueta_password', 
                          'nota_importante', 'boton_accion', 'cierre', 'firma', 'pie_pagina']
        
        for field in required_fields:
            if field not in template_data or not template_data[field]:
                template_data[field] = self.DEFAULT_TEMPLATE[field]
        
        self.custom_templates[lang] = template_data
        return True

class PasswordResetViewES(BaseSupersetView):
    """Vista de restablecimiento de contraseña - Versión Español"""
    route_base = '/password-reset-es'
    class_permission_name = 'PasswordResetES'
    
    def __init__(self):
        super().__init__()
        self.template_manager = PlantillaEmail()
    
    def _es_admin(self):
        """Verificar si el usuario actual es administrador"""
        try:
            user = security_manager.current_user
            
            # Método 1: Atributo is_admin
            if hasattr(user, 'is_admin'):
                return user.is_admin()
            
            # Método 2: Verificar roles
            if hasattr(user, 'roles'):
                for role in user.roles:
                    if role.name in ['Admin', 'Administrator', 'admin']:
                        return True
            
            # Método 3: Método del security_manager
            if hasattr(security_manager, 'is_admin_user'):
                return security_manager.is_admin_user(user)
            
            return False
            
        except Exception as e:
            logger.error(f"Error verificando admin: {e}")
            return False
    
    def _obtener_estructura_tabla(self):
        """Obtener estructura de tabla PostgreSQL de manera segura"""
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        
        # Buscar tabla de usuarios
        user_table = None
        for table in ['ab_user', 'users', 'app_user']:
            if table in tables:
                user_table = table
                break
        
        if not user_table:
            user_table = 'ab_user'  # Default
        
        # Obtener columnas
        columns = inspector.get_columns(user_table)
        col_names = [col['name'] for col in columns]
        
        # Mapear campos disponibles
        fields = {
            'id': 'id' if 'id' in col_names else None,
            'username': 'username' if 'username' in col_names else None,
            'email': 'email' if 'email' in col_names else None,
            'first_name': 'first_name' if 'first_name' in col_names else None,
            'last_name': 'last_name' if 'last_name' in col_names else None,
            'active': 'active' if 'active' in col_names else None,
            'password': 'password' if 'password' in col_names else None,
            'changed_on': 'changed_on' if 'changed_on' in col_names else None,
            'created_on': 'created_on' if 'created_on' in col_names else None
        }
        
        # Eliminar campos no encontrados
        fields = {k: v for k, v in fields.items() if v is not None}
        
        return {
            'table': user_table,
            'fields': fields,
            'all_columns': col_names
        }
    
    @expose('/')
    @protect()
    @has_access
    def index(self):
        """Página principal del restablecedor"""
        if not self._es_admin():
            flash(_('Se requieren privilegios de administrador'), 'danger')
            return redirect(url_for('Superset.index'))
        
        return self.render_template(
            'password_reset_es.html',
            title=_('Restablecer Contraseña')
        )
    
    @expose('/buscar-usuarios', methods=['POST'])
    @protect()
    @has_access
    def buscar_usuarios(self):
        """Buscar usuarios por email, nombre o usuario"""
        if not self._es_admin():
            return jsonify({'error': 'No autorizado'}), 403
        
        search_term = request.json.get('search_term', '').strip()
        if len(search_term) < 3:
            return jsonify({'usuarios': []})
        
        try:
            table_info = self._obtener_estructura_tabla()
            table = table_info['table']
            fields = table_info['fields']
            
            # Construir consulta dinámicamente
            select_fields = []
            search_conditions = []
            
            for field in ['id', 'username', 'email', 'first_name', 'last_name', 'active']:
                if field in fields:
                    select_fields.append(fields[field])
                    if field in ['username', 'email', 'first_name', 'last_name']:
                        # PostgreSQL ILIKE para búsqueda insensible a mayúsculas
                        search_conditions.append(f"{fields[field]} ILIKE :search")
            
            if not select_fields:
                return jsonify({'error': 'No se pudieron obtener campos de usuario'}), 500
            
            query_str = f"""
                SELECT {', '.join(select_fields)}
                FROM {table}
                WHERE ({' OR '.join(search_conditions)})
                AND {fields.get('active', 'active')} = true
                ORDER BY {fields.get('first_name', 'username')}
                LIMIT 20
            """
            
            query = text(query_str)
            results = db.session.execute(query, {'search': f'%{search_term}%'}).fetchall()
            
            # Construir resultado
            usuarios = []
            for row in results:
                usuario = {}
                for idx, field_name in enumerate(select_fields):
                    if field_name == fields.get('id'):
                        usuario['id'] = row[idx]
                    elif field_name == fields.get('username'):
                        usuario['username'] = row[idx]
                    elif field_name == fields.get('email'):
                        usuario['email'] = row[idx]
                    elif field_name == fields.get('first_name'):
                        usuario['first_name'] = row[idx]
                    elif field_name == fields.get('last_name'):
                        usuario['last_name'] = row[idx]
                    elif field_name == fields.get('active'):
                        usuario['active'] = row[idx]
                
                # Asegurar campos mínimos
                if 'id' not in usuario:
                    continue
                    
                usuarios.append(usuario)
            
            return jsonify({'usuarios': usuarios})
            
        except Exception as e:
            logger.error(f"Error buscando usuarios: {e}")
            return jsonify({'error': str(e)}), 500
    
    @expose('/restablecer', methods=['POST'])
    @protect()
    @has_access
    def restablecer_password(self):
        """Restablecer contraseña de usuario"""
        if not self._es_admin():
            return jsonify({'error': 'No autorizado'}), 403
        
        user_id = request.json.get('user_id')
        email = request.json.get('email')
        notificar = request.json.get('notificar', True)
        mensaje_adicional = request.json.get('mensaje_adicional', '')
        
        if not user_id and not email:
            return jsonify({'error': 'Se requiere ID o email del usuario'}), 400
        
        try:
            table_info = self._obtener_estructura_tabla()
            table = table_info['table']
            fields = table_info['fields']
            
            # Buscar usuario
            if user_id:
                user_query = text(f"""
                    SELECT {', '.join(fields.values())}
                    FROM {table}
                    WHERE {fields['id']} = :user_id
                    AND {fields['active']} = true
                """)
                user = db.session.execute(user_query, {'user_id': user_id}).first()
            else:
                if 'email' not in fields:
                    return jsonify({'error': 'Campo email no encontrado'}), 500
                
                user_query = text(f"""
                    SELECT {', '.join(fields.values())}
                    FROM {table}
                    WHERE {fields['email']} = :email
                    AND {fields['active']} = true
                """)
                user = db.session.execute(user_query, {'email': email}).first()
            
            if not user:
                return jsonify({'error': 'Usuario activo no encontrado'}), 404
            
            # Generar nueva contraseña
            nueva_password = self._generar_password_segura()
            hashed_password = bcrypt.generate_password_hash(nueva_password).decode('utf-8')
            
            # Actualizar contraseña
            update_query = text(f"""
                UPDATE {table}
                SET {fields['password']} = :hashed_password,
                    {fields['changed_on']} = NOW()
                WHERE {fields['id']} = :user_id
            """)
            db.session.execute(update_query, {
                'hashed_password': hashed_password,
                'user_id': user[0]  # Asumimos que id es la primera columna
            })
            
            db.session.commit()
            
            # Construir info del usuario
            user_info = {
                'id': user[0],
                'username': user[list(fields.keys()).index('username')] if 'username' in fields else None,
                'email': user[list(fields.keys()).index('email')] if 'email' in fields else None,
                'first_name': user[list(fields.keys()).index('first_name')] if 'first_name' in fields else None,
                'last_name': user[list(fields.keys()).index('last_name')] if 'last_name' in fields else None
            }
            
            # Enviar email si se solicita
            email_enviado = False
            if notificar and user_info.get('email'):
                email_enviado = self._enviar_email_password(
                    email=user_info['email'],
                    username=user_info.get('username', 'Usuario'),
                    first_name=user_info.get('first_name', ''),
                    nueva_password=nueva_password,
                    mensaje_adicional=mensaje_adicional
                )
            
            return jsonify({
                'success': True,
                'mensaje': f'Contraseña restablecida para {user_info.get("username")}',
                'email_enviado': email_enviado,
                'password_temporal': nueva_password if not email_enviado else None,
                'usuario': user_info
            })
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error restableciendo password: {e}")
            return jsonify({'error': str(e)}), 500
    
    @expose('/plantilla-email', methods=['GET'])
    @protect()
    @has_access
    def obtener_plantilla_email(self):
        """Obtener plantilla de email actual"""
        if not self._es_admin():
            return jsonify({'error': 'No autorizado'}), 403
        
        template = self.template_manager.get_template('es')
        return jsonify({
            'template': template,
            'variables': {
                '{app_name}': 'Nombre de la aplicación',
                '{first_name}': 'Nombre del usuario',
                '{username}': 'Nombre de usuario',
                '{email}': 'Email del usuario',
                '{new_password}': 'Contraseña generada',
                '{base_url}': 'URL base de Superset',
                '{mensaje_adicional}': 'Mensaje adicional personalizado'
            }
        })
    
    @expose('/guardar-plantilla', methods=['POST'])
    @protect()
    @has_access
    def guardar_plantilla_email(self):
        """Guardar plantilla de email personalizada"""
        if not self._es_admin():
            return jsonify({'error': 'No autorizado'}), 403
        
        template_data = request.json.get('template', {})
        
        # Validar campos requeridos
        required = ['asunto', 'saludo', 'intro', 'etiqueta_password', 
                   'nota_importante', 'boton_accion', 'cierre', 'firma', 'pie_pagina']
        
        for field in required:
            if field not in template_data or not template_data[field]:
                return jsonify({
                    'error': f'Campo "{field}" es requerido'
                }), 400
        
        # Guardar template
        self.template_manager.save_template('es', template_data)
        
        return jsonify({
            'success': True,
            'mensaje': 'Plantilla guardada exitosamente'
        })
    
    @expose('/auditoria', methods=['GET'])
    @protect()
    @has_access
    def auditoria(self):
        """Obtener registro de auditoría"""
        if not self._es_admin():
            return jsonify({'error': 'No autorizado'}), 403
        
        try:
            # Buscar tabla de logs
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            
            log_table = None
            for table in ['ab_permission_log', 'logs', 'audit_log']:
                if table in tables:
                    log_table = table
                    break
            
            if not log_table:
                return jsonify({'logs': [], 'mensaje': 'Tabla de logs no encontrada'})
            
            # Obtener estructura de tabla de logs
            columns = inspector.get_columns(log_table)
            col_names = [col['name'] for col in columns]
            
            # Construir consulta dinámica
            select_fields = []
            if 'created_on' in col_names:
                select_fields.append('created_on')
            if 'user_id' in col_names:
                select_fields.append('user_id')
            if 'action' in col_names:
                select_fields.append('action')
            if 'resource' in col_names:
                select_fields.append('resource')
            
            if not select_fields:
                return jsonify({'logs': []})
            
            query_str = f"""
                SELECT {', '.join(select_fields)}
                FROM {log_table}
                WHERE action = 'PASSWORD_RESET' OR action LIKE '%password%'
                ORDER BY created_on DESC
                LIMIT 50
            """
            
            query = text(query_str)
            results = db.session.execute(query).fetchall()
            
            logs = []
            for row in results:
                log = {}
                for idx, field in enumerate(select_fields):
                    if field == 'created_on':
                        log['fecha'] = row[idx].isoformat() if row[idx] else None
                    elif field == 'user_id':
                        log['admin_id'] = row[idx]
                    elif field == 'action':
                        log['accion'] = row[idx]
                    elif field == 'resource':
                        log['recurso'] = row[idx]
                logs.append(log)
            
            return jsonify({'logs': logs})
            
        except Exception as e:
            logger.error(f"Error obteniendo auditoría: {e}")
            return jsonify({'error': str(e)}), 500
    
    @staticmethod
    def _generar_password_segura(length=16):
        """Generar contraseña segura"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-="
        password = [
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.digits),
            secrets.choice("!@#$%^&*()_+-=")
        ]
        password += [secrets.choice(alphabet) for _ in range(length - 4)]
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    def _enviar_email_password(self, email, username, first_name, nueva_password, mensaje_adicional=''):
        """Enviar email con nueva contraseña"""
        try:
            from superset import app
            
            # Configuración SMTP
            smtp_host = app.config.get('SMTP_HOST')
            smtp_port = app.config.get('SMTP_PORT', 587)
            smtp_user = app.config.get('SMTP_USER')
            smtp_password = app.config.get('SMTP_PASSWORD')
            smtp_tls = app.config.get('SMTP_TLS', True)
            from_email = app.config.get('SMTP_MAIL_FROM')
            app_name = app.config.get('APP_NAME', 'Superset')
            base_url = app.config.get('SUPERSET_WEBSERVER_BASE_URL', '')
            
            if not all([smtp_host, smtp_user, smtp_password, from_email]):
                logger.warning("SMTP no configurado")
                return False
            
            # Obtener plantilla
            template = self.template_manager.get_template('es')
            
            # Renderizar
            rendered = self.template_manager.render(
                template,
                app_name=app_name,
                first_name=first_name or username,
                username=username,
                email=email,
                new_password=nueva_password,
                base_url=base_url,
                mensaje_adicional=mensaje_adicional
            )
            
            # Construir email
            msg = MIMEMultipart('alternative')
            msg['From'] = from_email
            msg['To'] = email
            msg['Subject'] = rendered.get('asunto', 'Restablecimiento de Contraseña')
            
            # Versión texto plano
            texto_plano = f"""
            {rendered.get('saludo', 'Hola')}

            {rendered.get('intro', 'Su contraseña ha sido restablecida.')}

            {rendered.get('etiqueta_password', 'Nueva Contraseña')}: {nueva_password}

            {rendered.get('nota_importante', 'Importante: Cambie esta contraseña después de iniciar sesión.')}

            {rendered.get('mensaje_adicional', '')}

            {rendered.get('cierre', 'Saludos cordiales,')}
            {rendered.get('firma', 'Equipo')}

            {rendered.get('pie_pagina', '')}
            """
            
            # Versión HTML
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #f5f5f5; padding: 20px;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h2 style="color: #1a73e8; border-bottom: 2px solid #1a73e8; padding-bottom: 10px;">
                        🔐 {rendered.get('asunto', 'Restablecimiento de Contraseña')}
                    </h2>
                    
                    <p>{rendered.get('saludo', 'Hola')}</p>
                    
                    <p>{rendered.get('intro', 'Su contraseña ha sido restablecida.')}</p>
                    
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #1a73e8;">
                        <p style="margin: 0; font-size: 14px; color: #666;">
                            {rendered.get('etiqueta_password', 'Nueva Contraseña')}
                        </p>
                        <p style="margin: 5px 0 0 0; font-size: 20px; font-family: monospace; color: #d63384; word-break: break-all;">
                            {nueva_password}
                        </p>
                    </div>
                    
                    <div style="background: #fff3cd; padding: 15px; border-radius: 5px; margin: 20px 0; border: 1px solid #ffc107;">
                        <p style="margin: 0; color: #856404; font-size: 14px;">
                            {rendered.get('nota_importante', 'Importante: Cambie esta contraseña inmediatamente.')}
                        </p>
                    </div>
                    
                    {f'<p style="background: #e8f5e9; padding: 10px; border-radius: 5px;">{rendered.get("mensaje_adicional", "")}</p>' if rendered.get('mensaje_adicional') else ''}
                    
                    <p style="margin-top: 20px;">
                        <a href="{rendered.get('base_url', '')}" 
                           style="background: #1a73e8; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">
                            {rendered.get('boton_accion', 'Iniciar Sesión')}
                        </a>
                    </p>
                    
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #e9ecef;">
                    
                    <p style="color: #6c757d; font-size: 12px; text-align: center;">
                        {rendered.get('pie_pagina', '')}
                    </p>
                    
                    <p style="color: #6c757d; font-size: 12px; text-align: center; margin-top: 10px;">
                        {rendered.get('firma', '')}
                    </p>
                </div>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(texto_plano, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            # Enviar
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                if smtp_tls:
                    server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)
            
            logger.info(f"Email enviado a {email}")
            return True
            
        except Exception as e:
            logger.error(f"Error enviando email: {e}")
            return False


# Registrar la vista
appbuilder.add_view(
    PasswordResetViewES,
    "Restablecer Contraseña",
    category="Seguridad",
    category_icon="fa-lock",
    icon="fa-key"
)
