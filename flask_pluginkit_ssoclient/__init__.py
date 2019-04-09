# -*- coding: utf-8 -*-
"""
    flask-pluginkit-ssoclient
    ~~~~~~~~~~~~~~~~~~~~~~~~~

    SSO Client of Passport.

    You should have a config.py and SSO in it.

    In app::

        # set_userinfo is a func.
        app.config["PLUGINKIT_SETUSERINFO_CALLBACK"] = set_userinfo

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
from flask_pluginkit import PluginError
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

try:
    #: 获取SSO服务端配置信息
    from config import SSO
except ImportError:
    raise PluginError("Insufficient plugin configuration for %s" %__plugin_name__)
else:
    if "sso_server" in SSO and "app_name" in SSO and "app_id" in SSO and "app_secret" in SSO and "secret_key" in SSO:
        # 定义sso server地址并删除SSO多余参数
        sso_server = SSO.get("sso_server").strip("/")
        # 实例化sso工具类
        sso_util = SSOUtil(SSO)
    else:
        raise PluginError("Insufficient plugin configuration for %s" %__plugin_name__)

bp = Blueprint("sso","sso")
@bp.route("/Login")
@anonymous_required
def Login():
    """ Client登录地址，需要跳转到SSO Server上 """
    ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or  request.url_root
    if url_check(sso_server):
        return redirect("{}/sso/?sso={}".format(sso_server, sso_util.set_ssoparam(ReturnUrl)))
    else:
        return "Invalid Configuration"

@bp.route("/Logout")
@login_required
def Logout():
    """ Client注销地址，需要跳转到SSO Server上 """
    ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or  request.url_root
    return redirect("{}/signOut?ReturnUrl={}".format(sso_server, ReturnUrl))

@bp.route("/authorized", methods=["GET", "POST"])
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
                        # 回调函数，原set_userinfo
                        SETUSERINFO_CALLBACK = current_app.config.get("PLUGINKIT_SETUSERINFO_CALLBACK") or current_app.extensions["pluginkit"].get_config.get("SETUSERINFO_CALLBACK")
                        if SETUSERINFO_CALLBACK:
                            SETUSERINFO_CALLBACK(uid, g.userinfo, expire)
                        logger.debug(g.userinfo)
                        # 授权令牌验证通过，设置局部会话，允许登录
                        sessionId = sso_util.set_sessionId(uid=uid, seconds=expire, sid=sid)
                        response = make_response(redirect(get_redirect_url("front.index")))
                        response.set_cookie(key="sessionId", value=sessionId, max_age=expire, httponly=True, secure=False if request.url_root.split("://")[0] == "http" else True)
                        return response
    elif Action == "ssoLogout":
        # 单点注销
        ReturnUrl = request.args.get("ReturnUrl") or get_referrer_url() or  request.url_root
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
            except Exception as e:
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
                    # 回调函数，原set_userinfo
                    SETUSERINFO_CALLBACK = current_app.config.get("PLUGINKIT_SETUSERINFO_CALLBACK") or current_app.extensions["pluginkit"].get_config.get("SETUSERINFO_CALLBACK")
                    if SETUSERINFO_CALLBACK:
                        success = SETUSERINFO_CALLBACK(uid, g.userinfo)
                    else:
                        success = "No set userinfo callback"
                    return jsonify(msg="Synchronization completed", success=success, app_name=SSO["app_name"])
    return "Invalid Authorized"

#: 返回插件主类
def getPluginClass():
    return SSOClientMain

#: 插件主类, 不强制要求名称与插件名一致, 保证getPluginClass准确返回此类
class SSOClientMain(object):

    def _check_login_state(self):
        if not hasattr(g, "signin"):
            g.signin = None
        if not g.signin:
            # 登录状态标记，True表示已登录，False表示未登录
            g.signin = sso_util.verify_sessionId(request.cookies.get("sessionId"))
        # sessionId和userId
        g.sid, g.uid = sso_util.analysis_sessionId(request.cookies.get("sessionId"), "tuple") if g.signin else (None, None)

    def register_bep(self):
        """注册蓝图入口, 返回蓝图路由前缀及蓝图名称"""
        bep = {"prefix": "/sso", "blueprint": bp}
        return bep

    def register_hep(self):
        hep = dict(before_request_top_hook=self._check_login_state)
        return hep
