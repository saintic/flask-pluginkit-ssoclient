import re
import ast
from setuptools import setup


def _get_meta(meta):
    pat = re.compile(r'__%s__\s+=\s+(.*)' % meta)
    with open('flask_pluginkit_ssoclient/__init__.py', 'rb') as fh:
        meta_str = ast.literal_eval(pat.search(fh.read().decode('utf-8')).group(1))
    return str(meta_str)


def _get_author():
    mail_re = re.compile(r'(.*)\s<(.*)>')
    author = _get_meta("author")
    return (mail_re.search(author).group(1), mail_re.search(author).group(2))


(author, email) = _get_author()
setup(
    name='flask-pluginkit-ssoclient',
    version=_get_meta("version"),
    license=_get_meta("license"),
    author=author,
    author_email=email,
    url='https://github.com/saintic/flask-pluginkit-ssoclient',
    keywords="flask-pluginkit",
    description=_get_meta("description"),
    packages=['flask_pluginkit_ssoclient',],
    zip_safe=False,
    include_package_data=True,
    install_requires=[
        'Flask-PluginKit>=2.3.1',
        'SecureHTTP>=0.4.0',
        'requests'
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)