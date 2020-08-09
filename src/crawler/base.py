import os
from abc import ABCMeta, abstractmethod  # python不存在抽象类的概念， 需要引入abc模块实现
from src import config
from src.utils import log
from src.utils.sqlite import SqliteSDBC
from src.bean.t_cves import TCves
from src.dao.t_cves import TCvesDao


class BaseCrawler:
    __metaclass__ = ABCMeta  # 定义为抽象类

    name_ch = "未知"
    name_en = "unknown"
    home_page = "https://exp-blog.com"

    def __init__(self, timeout=60, charset="utf-8"):
        self.timeout = timeout or 60
        self.charset = charset or "utf-8"
        self.CACHE_PATH = "%s/cache/%s.dat" % (config.PRJ_DIR, self.name_en)

    headers = {
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Connection": "keep-alive",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36",
    }

    def cves(self):
        log.info("++++++++++++++++++++++++++++++++++++++++++++")
        log.info(f"正在获取 [{self.name_ch}] 威胁情报...")
        old_cves = self.load_cache()

        try:
            new_cves = self.get_cves()
        except:
            new_cves = []
            log.error(f"获取 [{self.name_ch}] 威胁情报异常")

        dao = TCvesDao()
        sdbc = SqliteSDBC(config.DB_PATH)
        result = []
        with sdbc.conn() as conn:
            for cve in new_cves:
                if cve.MD5() not in old_cves:
                    result.append(cve)
                    self.to_cache(cve)
                    self.to_db(conn, dao, cve)

        log.info("得到 [%s] 最新威胁情报 [%s] 条" % (self.name_ch, len(result)))
        log.info("--------------------------------------------")
        return result

    @abstractmethod
    def get_cves(self):
        # 获取最新的 CVE 信息（由子类爬虫实现）
        # TODO in sub class
        return []  # CVEInfo

    def load_cache(self):
        if not os.path.exists(self.CACHE_PATH):
            with open(self.CACHE_PATH, "w+") as file:
                pass  # 创建空文件
        lines = list(map(str.strip, open(self.CACHE_PATH, "r+").read().splitlines()))

        # 缓存超过 200 时，保留最后的 100 条缓存
        if len(lines) > 200:
            lines = lines[100:]
            with open(self.CACHE_PATH, "w+") as file:
                file.write("\n".join(lines) + "\n")
        return set(lines)

    def to_cache(self, cve):
        with open(self.CACHE_PATH, "a+") as file:
            file.write(cve.MD5() + "\n")

    def to_db(self, conn, dao, cve):
        tcve = TCves()
        tcve.md5 = cve.MD5()
        tcve.src = cve.src
        tcve.cves = cve.id
        tcve.title = cve.title
        tcve.info = cve.info
        tcve.time = cve.time
        tcve.url = cve.url
        dao.insert(conn, tcve)
