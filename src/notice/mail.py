import os
import smtplib
import typing
from email.mime.text import MIMEText
from email.header import Header
from src import config
from src.utils import log


def to_mail(mail_by_github, cves, smtp, sender, password):
    content = format_content(cves)
    if mail_by_github:
        log.info("[邮件] 正在通过 Github Actions 推送威胁情报...")
        to_cache(content)

    else:
        log.info("[邮件] 正在推送威胁情报...")
        email = MIMEText(content, "html", "utf-8")  # 以 html 格式发送邮件内容
        email["From"] = sender
        receivers = load_receivers()
        email["To"] = ", ".join(receivers)  # 此处收件人列表必须为逗号分隔的 str
        log.info("[邮件] 收件人清单： %s" % receivers)

        subject = "威胁情报播报"
        email["Subject"] = Header(subject, "utf-8")

        try:
            smtpObj = smtplib.SMTP(smtp)
            smtpObj.login(sender, password)
            smtpObj.sendmail(sender, receivers, email.as_string())  # 此处收件人列表必须为 list
            log.info("[邮件] 推送威胁情报成功")
        except:
            log.error("[邮件] 推送威胁情报失败")


def format_content(cves: typing.Dict):
    src_tpl = '    <li><font color="red">%(cnt)d</font>条由 [<a href="%(url)s">%(src)s</a>] 提供</li>'
    mail_tpl = """
<h3>发现最新威胁情报<font color="red">%(total)d</font>条：</h3>
<ul>
%(src_infos)s
</ul>
<h3>详细漏洞清单如下：</h3>
<br/>
%(cve_infos)s

<br/><br/>
++++++++++++++++++++++++++++++++++++++++++++++
<br/>
<font color="red">【情报收集与播报支持】</font> https://skactor.github.io/threat-intelligence/
"""
    src_infos = []
    cve_infos = []
    total = 0
    for source, _cves in cves.items():
        cnt = len(_cves)
        total += cnt
        src_infos.append(
            src_tpl % {"cnt": cnt, "url": source.home_page, "src": source.name_ch}
        )
        list(map(lambda cve: cve_infos.append(cve.to_html()), _cves))

    content = mail_tpl % {
        "total": total,
        "src_infos": "\n".join(src_infos),
        "cve_infos": "\n".join(cve_infos),
    }
    return content


def load_receivers():
    recvs = []
    for dirPath, dirNames, fileNames in os.walk(config.RECV_DIR):
        for fileName in fileNames:
            if fileName.startswith("mail") and fileName.endswith(".dat"):
                file_path = "%s/%s" % (config.RECV_DIR, fileName)
                with open(file_path, "r") as file:
                    lines = file.readlines()
                    for line in lines:
                        line = line.strip()
                        if (not line) or line.startswith("#"):
                            continue
                        recvs.append(line)
    return recvs


def to_cache(mail_content):
    with open(config.MAIL_CACHE_PATH, "w+") as file:
        file.write(mail_content)
