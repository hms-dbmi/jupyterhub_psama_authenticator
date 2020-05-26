from jupyterhub.auth import Authenticator

from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from traitlets import Bool, Integer, Unicode

from .handlers import (LoginHandler, TokenValidateHandler)

import json

class PsamaAuthenticator(Authenticator):

    psama_token_introspection_token = Unicode(
        "",
        config=True,
        help="""
        The secret token used by this authenticator to allow it to properly call the token introspection endpoint  
        """
    )
    psama_token_introspection_url = Unicode(
        "http://localhost/psama/token/inspect",
        config=True,
        help="""
        The endpoint to call for token introspection.
        """
    )
    psama_application_id = Unicode(
        "",
        config=True,
        help="""
        Identifier for the Jupyterhub application inside PIC-SURE PSAMA
        """
    )

    psama_login_path = Unicode(
        "/psamaui/login/",
        config=True,
        help="""
        This is the path component of a URL that is used to access the PIC-SURE PSAMA process.
        It is suffixed with "?redirection_url={{automatically_set}}".        
        """
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @gen.coroutine
    def authenticate(self, handler, data):

        usr_token = data['session_token']
        http_client = AsyncHTTPClient()

        try:
            response = yield http_client.fetch(
                self.psama_token_introspection_url,
                method="POST",
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer " + self.psama_token_introspection_token
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


    def get_handlers(self, app):
        native_handlers = [
            (r'/login', LoginHandler),
            (r'/check_token', TokenValidateHandler),
        ]
        return native_handlers

