from flask import Flask
from flask_pluginkit import PluginManager

def set_userinfo(uid, userinfo):
    print(uid,userinfo)

app = Flask(__name__)
app.config["PLUGINKIT_SETUSERINFO_CALLBACK"] = set_userinfo

plugin = PluginManager(app, plugin_packages=["flask_pluginkit_ssoclient"])

if __name__== "__main__":
    app.run(debug=True)