# -*- coding: utf-8 -*-
"""
    flask-pluginkit-ssoclient
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    SSO Client, ask app config::

        app.config.update(
            PLUGINKIT_SSO = SSO_CONFIG,
            PLUGINKIT_AESKEY = AES_KEY
        )

    :copyright: (c) 2019 by staugur.
    :license: BSD, see LICENSE for more details.
"""

#: Importing these two modules is the first and must be done.
#: 首先导入这两个必须模块
from __future__ import absolute_import
#: Import the other modules here, and if it's your own module, use the relative Import. eg: from .lib import Lib
#: 在这里导入其他模块, 如果有自定义包目录, 使用相对导入, 如: from .lib import Lib
import json
from flask import current_app, Blueprint, request, jsonify, g, redirect, url_for, make_response
from ._util import SSOUtil, login_required, anonymous_required, get_redirect_url, get_referrer_url, sso_request, url_check, logger

#：Your plugin name
#：你的插件名称
__plugin_name__ = "flask-pluginkit-ssoclient"
#: Plugin describes information
#: 插件描述信息
__description__ = "SSO Client of Passport"
#: Plugin Author
#: 插件作者
__author__      = "Mr.tao <staugur@saintic.com>"
#: Plugin Version
#: 插件版本
__version__     = "0.1.0" 
#: Plugin Url
#: 插件主页
__url__         = "https://www.saintic.com"
#: Plugin License
#: 插件许可证
__license__     = "BSD"
#: Plugin License File
#: 插件许可证文件
__license_file__= "LICENSE"
#: Plugin Readme File
#: 插件自述文件
__readme_file__ = "README.md"
#: Plugin state, enabled or disabled, default: enabled
#: 插件状态, enabled、disabled, 默认enabled
__state__       = "enabled"

# 获取SSO服务端配置信息
SSO = current_app.config["PLUGINKIT_SSO"]
AESKEY = current_app.config["PLUGINKIT_AESKEY"]
# 回调函数，原set_userinfo
SETUSERINFO_CALLBACK = current_app.config["PLUGINKIT_SETUSERINFO_CALLBACK"]

# 定义sso server地址并删除SSO多余参数
sso_server = SSO.get("sso_server").strip("/")
# 实例化sso工具类
sso_util = SSOUtil(SSO, AESKEY)

# 定义蓝图
sso_blueprint = Blueprint("sso", "sso")
@sso_blueprint.route("/Login")
@anonymous_required
def Login():
    """ Client登录地址，需要跳转到SSO Server上 """
    ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or url_for("front.index", _external=True)
    if url_check(sso_server):
        return redirect("{}/sso/?sso={}".format(sso_server, sso_util.set_ssoparam(ReturnUrl)))
    else:
        return "Invalid Configuration"

@sso_blueprint.route("/Logout")
@login_required
def Logout():
    """ Client注销地址，需要跳转到SSO Server上 """
    ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or url_for("front.index", _external=True)
    return redirect("{}/signOut?ReturnUrl={}".format(sso_server, ReturnUrl))

@sso_blueprint.route("/authorized", methods=["GET", "POST"])
def authorized():
    """ Client SSO 单点登录、注销入口, 根据`Action`参数判断是`ssoLogin`还是`ssoLogout` """
    Action = request.args.get("Action")
    if Action == "ssoLogin":
        # 单点登录
        ticket = request.args.get("ticket")
        if request.method == "GET" and ticket and g.signin == False:
            resp = sso_request("{}/sso/validate".format(sso_server), dict(Action="validate_ticket"), dict(ticket=ticket, app_name=SSO["app_name"], get_userinfo=True, get_userbind=False))
            logger.debug("SSO check ticket resp: {}".format(resp))
            if resp and isinstance(resp, dict) and "success" in resp and "uid" in resp:
                if resp["success"] is True:
                    uid = resp["uid"]
                    sid = resp["sid"]
                    expire = int(resp["expire"])
                    # 判断是否允许登录
                    if sso_util.is_allowUid(uid) is True:
                        # 获取用户信息，若不需要，可将get_userinfo=True改为False，并注释下两行
                        g.userinfo = resp["userinfo"].get("data") or dict()
                        SETUSERINFO_CALLBACK(uid, g.userinfo, expire)
                        logger.debug(g.userinfo)
                        # 授权令牌验证通过，设置局部会话，允许登录
                        sessionId = sso_util.set_sessionId(uid=uid, seconds=expire, sid=sid)
                        response = make_response(redirect(get_redirect_url("front.index")))
                        response.set_cookie(key="sessionId", value=sessionId, max_age=expire, httponly=True, secure=False if request.url_root.split("://")[0] == "http" else True)
                        return response
    elif Action == "ssoLogout":
        # 单点注销
        ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or url_for("front.index", _external=True)
        NextUrl   = "{}/signOut?ReturnUrl={}".format(sso_server, ReturnUrl)
        app_name  = request.args.get("app_name")
        if request.method == "GET" and NextUrl and app_name and g.signin == True and app_name == SSO["app_name"]:
            response = make_response(redirect(NextUrl))
            response.set_cookie(key="sessionId", value="", expires=0)
            return response
    elif Action == "ssoConSync":
        # 数据同步：参数中必须包含大写的hmac_sha256(app_name:app_id:app_secret)的signature值
        signature = request.args.get("signature")
        if request.method == "POST" and signature and signature == sso_util.hmac_sha256("{}:{}:{}".format(SSO["app_name"], SSO["app_id"], SSO["app_secret"])).upper():
            try:
                data = json.loads(request.form.get("data"))
                ct = data["CallbackType"]
                cd = data["CallbackData"]
                uid = data["uid"]
                token = data["token"]
            except Exception,e:
                logger.warning(e)
            else:
                logger.info("ssoConSync with uid: {} -> {}: {}".format(uid, ct, cd))
                resp = sso_request("{}/sso/validate".format(sso_server), dict(Action="validate_sync"), dict(token=token, uid=uid))
                if resp and isinstance(resp, dict) and resp.get("success") is True:
                    # 之后根据不同类型的ct处理cd
                    logger.debug("ssoConSync is ok")
                    if ct == "user_profile":
                        g.userinfo.update(cd)
                    elif ct == "user_avatar":
                        g.userinfo["avatar"] = cd
                    return jsonify(msg="Synchronization completed", success=SETUSERINFO_CALLBACK(uid, g.userinfo), app_name=SSO["app_name"])
    return "Invalid Authorized"

#: 返回插件主类
def getPluginClass():
    return SSOClientMain

#: 插件主类, 不强制要求名称与插件名一致, 保证getPluginClass准确返回此类
class SSOClientMain(object):

    def register_bep(self):
        """注册蓝图入口, 返回蓝图路由前缀及蓝图名称"""
        bep = {"prefix": "/sso", "blueprint": sso_blueprint}
        return bep
