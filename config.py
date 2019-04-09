# -*- coding: utf-8 -*-
"""
    config
    ~~~~~~~

    The program configuration file, the preferred configuration item, reads the system environment variable first.

    :copyright: (c) 2019 by staugur.
    :license: BSD, see LICENSE for more details.
"""

from os import getenv

GLOBAL = {

    "ProcessName": "xxx",
    #自定义进程名.

    "Host": getenv("xxx_host", "0.0.0.0"),
    #监听地址

    "Port": getenv("xxx_port", 5000),
    #监听端口

    "LogLevel": getenv("xxx_loglevel", "DEBUG"),
    #应用日志记录级别, 依次为 DEBUG, INFO, WARNING, ERROR, CRITICAL.
}


SSO = {

    "app_name": getenv("xxx_sso_app_name", GLOBAL["ProcessName"]),
    # Passport应用管理中注册的应用名

    "app_id": getenv("xxx_sso_app_id", "app_id"),
    # Passport应用管理中注册返回的`app_id`

    "app_secret": getenv("xxx_sso_app_secret", "app_secret"),
    # Passport应用管理中注册返回的`app_secret`

    "sso_server": getenv("xxx_sso_server", "YourPassportFQDN"),
    # Passport部署允许的完全合格域名根地址，例如作者的`https://passport.saintic.com`

    "sso_allow": getenv("xxx_sso_allow"),
    # 允许登录的uid列表，格式是: uid1,uid2,...,uidn

    "sso_deny": getenv("xxx_sso_deny"),
    # 拒绝登录的uid列表, 格式同上

    "secret_key": getenv("xxx_aes_key", "YRRGBRYQqrV1gv5A")
}
