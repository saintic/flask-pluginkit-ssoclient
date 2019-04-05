# -*- coding: utf-8 -*-
"""
    _util
    ~~~~~

    Common function for web.

    :copyright: (c) 2019 by staugur.
    :license: BSD, see LICENSE for more details.
"""

import re
import json
import hmac
import hashlib
import logging
import requests
from functools import wraps
from SecureHTTP import AESEncrypt
from flask_pluginkit import string_types
from flask import g, request, redirect, url_for
from ._jwt import JWTUtil, JWTException

logger = logging.getLogger(__name__)
# 定义解析以逗号分隔的字符串为列表
comma_pat = re.compile(r"\s*,\s*")

class SSOUtil(object):

    def __init__(self, SSO_CONF=dict(), AES_KEY="d1d5eb327d55d83eb96ead9cdd1394e8"):
        self._SSO_DATA = SSO_CONF
        self._AES_KEY = AES_KEY
        self._jwt = JWTUtil()

    def set_ssoparam(self, ReturnUrl="/"):
        """生成sso请求参数，5min过期"""
        app_name = self._SSO_DATA.get("app_name")
        app_id = self._SSO_DATA.get("app_id")
        app_secret = self._SSO_DATA.get("app_secret")
        return AESEncrypt(self._AES_KEY, self._jwt.createJWT(payload=dict(app_name=app_name, app_id=app_id, app_secret=app_secret, ReturnUrl=ReturnUrl), expiredSeconds=300), output="hex")

    def set_sessionId(self, uid, seconds=43200, sid=None):
        """设置cookie"""
        payload = dict(uid=uid, sid=sid) if sid else dict(uid=uid)
        sessionId = self._jwt.createJWT(payload=payload, expiredSeconds=seconds)
        return AESEncrypt(self._AES_KEY, sessionId, output="hex")

    def allow_uids(self):
        """解析允许登录的uid列表"""
        if self._SSO_DATA["sso_allow"] and isinstance(self._SSO_DATA["sso_allow"], string_types):
            uids = [ uid for uid in comma_pat.split(self._SSO_DATA["sso_allow"]) if uid ]
            return uids

    def deny_uids(self):
        """解析拒绝登录的uid列表"""
        if self._SSO_DATA["sso_deny"] and isinstance(self._SSO_DATA["sso_deny"], string_types):
            uids = [ uid for uid in comma_pat.split(self._SSO_DATA["sso_deny"]) if uid and isinstance(uid, string_types) ]
            return uids
        return []

    def is_allowUid(self, uid):
        """判断uid是否允许登录，规则(按数字顺序判断，每一步返回True即刻中止并return False拒绝后续登录):
        1. uid在拒绝列表中
        2. 允许列表为True时，uid不在允许列表；允许列表为False时。
        :returns:bool:True允许登录，False拒绝登录
        """
        if uid and isinstance(uid, string_types):
            allowUids = self.allow_uids()
            denyUids = self.deny_uids()
            if uid in denyUids:
                return False
            if allowUids:
                return uid in allowUids
            else:
                return True

    def hmac_sha256(self, message):
        """HMAC SHA256 Signature"""
        return hmac.new(key=self._AES_KEY, msg=message, digestmod=hashlib.sha256).hexdigest()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.signin:
            return redirect(url_for('sso.Login'))
        return f(*args, **kwargs)
    return decorated_function


def anonymous_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.signin:
            return redirect(get_redirect_url())
        return f(*args, **kwargs)
    return decorated_function


def get_referrer_url():
    """获取上一页地址"""
    if request.referrer and request.referrer.startswith(request.host_url) and request.endpoint and not "api." in request.endpoint:
        url = request.referrer
    else:
        url = None
    return url


def get_redirect_url(endpoint="front.index"):
    """获取重定向地址
    NextUrl: 引导重定向下一步地址
    ReturnUrl: 最终重定向地址
    以上两个不存在时，如果定义了非默认endpoint，则首先返回；否则返回referrer地址，不存在时返回endpoint默认主页
    """
    url = request.args.get('NextUrl') or request.args.get('ReturnUrl')
    if not url:
        if endpoint != "front.index":
            url = url_for(endpoint)
        else:
            url = get_referrer_url() or url_for(endpoint)
    return url


def sso_request(url, params=None, data=None, timeout=5, num_retries=1):
    """定义请求函数
    @params dict: 请求查询参数
    @data dict: 提交表单数据
    @timeout int: 超时时间，单位秒
    @num_retries int: 超时重试次数
    """
    headers = {"User-Agent": "Mozilla/5.0 (X11; CentOS; Linux i686; rv:7.0.1406) Gecko/20100101 PassportClient"}
    try:
        resp = requests.post(url, params=params, headers=headers, timeout=timeout, data=data).json()
    except requests.exceptions.Timeout,e:
        if num_retries > 0:
            return sso_request(url, params=params, data=data, timeout=timeout, num_retries=num_retries-1)
    else:
        return resp


def url_check(addr):
    """检测UrlAddr是否为有效格式，例如
    http://ip:port
    https://abc.com
    """
    regex = re.compile(
        r'^(?:http)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    if addr and isinstance(addr, (str, unicode)):
        if regex.match(addr):
            return True
    return False
