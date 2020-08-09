import time
from src import config
from src.utils import log
from src.utils.sqlite import SqliteSDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao


def to_page(top_limit=10):
    html_tpl, table_tpl, row_tpl = load_tpl()
    sdbc = SqliteSDBC(config.DB_PATH)

    tables = []
    with sdbc.conn() as conn:
        srcs = query_srcs(conn)
        for src in srcs:
            cves = query_cves(conn, src, top_limit)

            rows = []
            for cve in cves:
                row = row_tpl % {
                    "md5": cve.md5,
                    "id": cve.cves,
                    "time": cve.time,
                    "title": cve.title,
                    "url": cve.url,
                }
                rows.append(row)

            table = table_tpl % {
                "src": cves[0].src,
                "top": top_limit,
                "rows": "\n".join(rows),
            }
            tables.append(table)

    html = html_tpl % {
        "datetime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "table": "\n\n".join(tables),
    }

    create_html(html)


def load_tpl():
    html_tpl = open(config.HTML_TPL_PATH, "rb").read().decode("utf8")
    table_tpl = open(config.TABLE_TPL_PATH, "rb").read().decode("utf8")
    row_tpl = open(config.ROW_TPL_PATH, "rb").read().decode("utf8")

    return html_tpl, table_tpl, row_tpl


def create_html(html):
    with open(config.HTML_PATH, "w") as file:
        file.write(html)


def query_srcs(conn):
    sql = "SELECT %s FROM %s GROUP BY %s" % (TCves.s_src, TCves.table_name, TCves.s_src)
    srcs = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        for row in rows:
            srcs.append(row[0])
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return srcs


def query_cves(conn, src, limit):
    dao = TCvesDao()
    where = "and %s = '%s' order by %s desc limit %d" % (
        TCves.s_src,
        src,
        TCves.s_time,
        limit,
    )
    sql = TCvesDao.SQL_SELECT + where
    beans = []
    try:
        cursor = conn.cursor()
        cursor.execute(sql)
        rows = cursor.fetchall()
        for row in rows:
            bean = dao._to_bean(row)
            beans.append(bean)
        cursor.close()
    except:
        log.error("从表 [%s] 查询数据失败" % TCves.table_name)
    return beans
