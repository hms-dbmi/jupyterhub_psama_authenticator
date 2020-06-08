import os
from jinja2 import ChoiceLoader, FileSystemLoader
from jupyterhub.handlers import BaseHandler
from jupyterhub.handlers.login import LoginHandler
from jupyterhub.handlers.login import LogoutHandler
from jupyterhub.utils import admin_only

import json

from tornado import web, gen
from tornado.escape import url_escape
from tornado.httputil import url_concat
from tornado.httpclient import AsyncHTTPClient


TEMPLATE_DIR = os.path.join(os.path.dirname(__file__), 'templates')


class LocalBase(BaseHandler):
    def __init__(self, *args, **kwargs):
        self._loaded = False
        super().__init__(*args, **kwargs)

    def _register_template_path(self):
        if self._loaded:
            return
        self.log.debug('Adding %s to template path', TEMPLATE_DIR)
        loader = FileSystemLoader([TEMPLATE_DIR])
        env = self.settings['jinja2_env']
        previous_loader = env.loader
        env.loader = ChoiceLoader([previous_loader, loader])
        self._loaded = True


class PsamaLoginHandler(LoginHandler, LocalBase):

    def get(self):
        self._register_template_path()
        self.write(self.render_template(
            'psama_login.html',
            psama_login_path=self.authenticator.psama_login_path
        ))
    
    @gen.coroutine
    def authenticate(self, data):
        self.log.error("AUTHENTICATE ROUTINE")
        self.log.info(data)

        usr_token = data['session_token']
        http_client = AsyncHTTPClient()

        try:
            response = yield http_client.fetch(
                self.authenticator.psama_token_introspection_url,
                method="POST",
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.authenticator.psama_token_introspection_token
                },
                body = json.dumps({"token": usr_token})
            )

            ret_msg = response.body if isinstance(response.body, str) \
            else response.body.decode()

            auth_result = json.loads(ret_msg)
            if auth_result['active']:
                if len(auth_result['privileges']) > 0:
                    username = auth_result['email'].replace("@", "~")
                    self.log.info("Passed Authentication for " + username )
                    return username

        except Exception as e:
            self.log.error(type(e))    # the exception instance
            self.log.error(e.args)     # arguments stored in .args
            self.log.error(e)          # __str__ allows args to be printed directly,


        # user is not authorized or an error occured, do not login
        self.log.error("Authentication failed")
        return None



class PsamaLogoutHandler(LogoutHandler, LocalBase):

    #@gen.coroutine
    async def render_logout_page(self):
        self._register_template_path()
        self.finish(self.render_template(
            'psama_logout.html',
            jupyter_login_path=self.authenticator.login_url(self.hub.base_url)
        ))

    

class TokenValidateHandler(LocalBase):
    """
    Checks a given token via introspection to see if it is valid and returns results in JSON
    """
    async def post(self):

        return_msg = {"error":False, "valid": False}

        http_client = AsyncHTTPClient()

        try:
            response = await http_client.fetch(
                self.authenticator.psama_token_introspection_url,
                method="POST",
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.authenticator.psama_token_introspection_token
                },
                body = json.dumps({"token": self.get_body_argument('token')}),
            )

            ret_msg = response.body if isinstance(response.body, str) \
            else response.body.decode()
            self.log.info(ret_msg)

            auth_result = json.loads(ret_msg)
            if auth_result['active']:
                if len(auth_result['privileges']) > 0:
                    return_msg['valid'] = True
            
        except Exception as e:
            self.log.error(type(e))    # the exception instance
            self.log.error(e.args)     # arguments stored in .args
            self.log.error(e)          # __str__ allows args to be printed directly,
            return_msg['error'] = True
            return_msg['msg'] = str(e)


        self.write(json.dumps(return_msg))
        self.finish()
