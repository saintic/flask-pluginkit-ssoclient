# flask-pluginkit-ssoclient
基于Flask-PluginKit的Passport的sso客户端

### Test run

```bash
$ pip install .
$ python run.py
```

### Usage

> 1. 要求flask-pluginkit>=2.3.1
> 2. 要求项目根目录下有config.py配置文件，包含SSO配置段(dict)
> 3. 要求app.config有一个名叫PLUGINKIT_SETUSERINFO_CALLBACK的配置项，其值是函数，要求可以接收uid(str)、userinfo(dict)参数以更新用户信息
> 4. 在你的requirements.txt中填写此插件地址：`git+https://github.com/saintic/flask-pluginkit-ssoclient@master`
