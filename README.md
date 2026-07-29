# superset6-reset-web-ui
add a web ui reset option for admins for other accounts

./superset-custom/
├── password_reset_view.py
├── superset_config.py
└── templates/
    └── password_reset_es.html
    
# SMTP

# superset_config.py - Configuración para PostgreSQL y Español

# --- Configuración Base de Datos PostgreSQL ---
SQLALCHEMY_DATABASE_URI = 'postgresql://usuario:password@host:5432/superset'

# --- Configuración SMTP (Obligatorio para enviar emails) ---
SMTP_HOST = 'smtp.gmail.com'  # o tu servidor SMTP
SMTP_PORT = 587
SMTP_USER = 'tu-email@gmail.com'
SMTP_PASSWORD = 'tu-contraseña-de-aplicacion'
SMTP_TLS = True
SMTP_MAIL_FROM = 'tu-email@gmail.com'

# --- Configuración General ---
APP_NAME = 'Superset Analytics'
SUPERSET_WEBSERVER_BASE_URL = 'http://tu-dominio.com:8088'

# --- Importar Vistas Personalizadas ---
from password_reset_view_es import PasswordResetView


Superset compose envs:
      - SUPERSET__SQLALCHEMY_DATABASE_URI=postgresql://usuario:password@postgres:5432/superset
      - SMTP_HOST=smtp.gmail.com
      - SMTP_PORT=587
      - SMTP_USER=tu-email@gmail.com
      - SMTP_PASSWORD=tu-contraseña
      - SMTP_TLS=true
      - SMTP_MAIL_FROM=tu-email@gmail.com

Superset compose vols:    
      - ./superset-custom/password_reset_view.py:/app/pythonpath/password_reset_view.py
      - ./superset-custom/superset_config.py:/app/pythonpath/superset_config.py
      - ./superset-custom/templates:/app/pythonpath/templates


URL directa reset:
      - http://tu-superset:8088/password-reset/
    
