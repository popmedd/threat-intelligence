import time
import git
from src import config
from src.utils import log


# 需要手动把仓库的 HTTPS 协议修改成 SSH
# git remote set-url origin git@github.com:Skactor/thread.git
def auto_commit():
    log.info("正在提交变更...")
    try:
        repo = git.Repo(config.PRJ_DIR)
        repo.git.add("*")
        repo.git.commit(
            m="[Threat-Broadcast] %s"
            % time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time()))
        )
        repo.git.push()
        log.info("提交变更成功")

    except:
        log.error("提交变更失败")
