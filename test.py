from flask import Flask
from flask_pluginkit import PluginManager

app = Flask(__name__)

plugin = PluginManager(app,plugin_packages=["flask_pluginkit_ssoclient"])

dir(app.plugin_manager)

app.run(debug=True)