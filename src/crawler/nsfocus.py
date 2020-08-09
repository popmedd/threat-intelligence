from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
import time
import requests
import re


class NsFocus(BaseCrawler):
    name_ch = "绿盟"
    name_en = "Nsfocus"
    home_page = "http://www.nsfocus.net/index.php"
    url_list = "http://www.nsfocus.net/index.php?act=sec_bug"
    url_cve = "http://www.nsfocus.net/vulndb/"

    def get_cves(self):
        response = requests.get(
            self.url_list, headers=self.headers, timeout=self.timeout
        )

        cves = []
        if response.status_code == 200:
            vul_list = re.findall(
                r"<li><span>(.*?)</span> <a href='/vulndb/(\d+)'>(.*?)</a>",
                response.content.decode("utf8"),
            )
            for vul in vul_list:
                cve = self.to_cve(vul)
                if cve.is_vaild():
                    cves.append(cve)
        else:
            log.warn(
                f"获取 [{self.name_ch}] 威胁情报失败： [HTTP Error {response.status_code:d}]"
            )
        return cves

    def to_cve(self, vul):
        cve = CVEInfo()
        cve.src = self.name_ch
        cve.url = self.url_cve + vul[1]
        cve.time = vul[0] + time.strftime(" %H:%M:%S", time.localtime())
        cve.title = re.sub(r"\(CVE-\d+-\d+\)", "", vul[2])

        rst = re.findall(r"(CVE-\d+-\d+)", vul[2])
        cve.id = rst[0] if rst else ""
        return cve


if __name__ == "__main__":
    print(NsFocus().cves())
