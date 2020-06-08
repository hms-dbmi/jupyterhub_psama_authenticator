import json
from traitlets import Bool, Integer, Unicode
from tornado import gen
from tornado.httpclient import AsyncHTTPClient
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from .handlers import (PsamaLoginHandler, PsamaLogoutHandler, TokenValidateHandler)

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

    def auto_login(self):
        return False

    def login_url(self, base_url):
        return url_path_join(base_url, 'psama_login')

#    def logout_url(self, base_url):
#        return url_path_join(base_url, 'psama_logout')
 
    def get_handlers(self, app):
        return [
            (r'/psama_login', PsamaLoginHandler),
            (r'/logout', PsamaLogoutHandler),
            (r'/check_token', TokenValidateHandler),
        ]

