from src.bean.cve_info import CVEInfo
from src.crawler.base import BaseCrawler
from src.utils import log
import requests
import json
import re
import time


class Vas(BaseCrawler):
    name_ch = "斗象"
    name_en = "vas"
    home_page = "https://vas.riskivy.com/vuln"
    url_list = "https://console.riskivy.com/vas"
    url_details = "https://console.riskivy.com/vas/"
    url_cve = "https://vas.riskivy.com/vuln-detail?id="

    def get_cves(self, limit=5):
        params = {
            "title": "",
            "cve": "",
            "cnvd": "",
            "cnnvd": "",
            "order": "update",
            "has_poc": "",
            "has_repair": "",
            "bug_level": "",
            "page": 1,
            "per-page": limit,
        }

        response = requests.get(
            self.url_list, headers=self.headers, params=params, timeout=self.timeout
        )

        cves = []
        if response.status_code == 200:
            json_obj = json.loads(response.text)
            for obj in json_obj.get("data").get("items"):
                cve = self.to_cve(obj)
                if cve.is_vaild():
                    cves.append(cve)
                    # log.debug(cve)
        else:
            log.warn(
                "获取 [%s] 威胁情报失败： [HTTP Error %i]" % (self.name_ch, response.status_code)
            )
        return cves

    def to_cve(self, json_obj):
        cve = CVEInfo()
        cve.src = self.name_ch

        id = str(json_obj.get("id")) or ""
        cve.url = self.url_cve + id
        cve.title = json_obj.get("bug_title") or ""

        seconds = json_obj.get("updated_at") or 0
        localtime = time.localtime(seconds)
        cve.time = time.strftime("%Y-%m-%d %H:%M:%S", localtime)

        self.get_cve_info(cve, id)
        return cve

    def get_cve_info(self, cve, id):
        url = self.url_details + id
        response = requests.get(url, headers=self.headers, timeout=self.timeout)

        if response.status_code == 200:
            json_obj = json.loads(response.text)
            cve.id = json_obj.get("data").get("bug_cve").replace(",", ", ")
            cve.info = json_obj.get("data").get("detail").get("bug_description")
            cve.info = re.sub(r"<.*?>", "", cve.info)

        time.sleep(0.1)


if __name__ == "__main__":
    print(Vas().cves())
