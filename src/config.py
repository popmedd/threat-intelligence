import os
from environs import Env

env = Env()

PRJ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SQL_PATH = os.path.join(PRJ_DIR, "script/cves-create.sql")
DB_PATH = os.path.join(PRJ_DIR, "data/cves.db")

# Mail
MAIL_CACHE_PATH = f"{PRJ_DIR}/cache/mail.dat"
RECV_DIR = f"{PRJ_DIR}/recv"

HTML_PATH = f"{PRJ_DIR}/docs/index.html"
HTML_TPL_PATH = f"{PRJ_DIR}/tpl/html.html"
TABLE_TPL_PATH = f"{PRJ_DIR}/tpl/table.html"
ROW_TPL_PATH = f"{PRJ_DIR}/tpl/row.html"
