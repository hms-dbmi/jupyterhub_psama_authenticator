import os
from jinja2 import ChoiceLoader, FileSystemLoader
from jupyterhub.handlers import BaseHandler
from jupyterhub.handlers.login import LoginHandler
from jupyterhub.utils import admin_only

import json

from tornado import web
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


class LoginHandler(LoginHandler, LocalBase):

    def _render(self, login_error=None, username=None):
        self._register_template_path()
        return self.render_template(
            'token_extract_and_forward.html',
            psama_login_path=self.authenticator.psama_login_path
        )
