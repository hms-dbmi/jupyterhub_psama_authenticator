from jupyterhub.auth import Authenticator

from tornado import gen
from traitlets import Bool, Integer, Unicode

from .handlers import (LoginHandler, TokenValidateHandler)


class PsamaAuthenticator(Authenticator):

    psama_token_introspection_token = Unicode(
        "",
        config=True,
        help="""
        The secret token used by this authenticator to allow it to properly call the token introspection endpoint  
        """
    )
    psama_token_introspection_path = Unicode(
        "/psama/token/inspect",
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
        username = self.normalize_username(data['username'])
        password = data['password']

        user = self.get_user(username)
        if not user:
            return

        if self.allowed_failed_logins:
            if self.is_blocked(username):
                return

        validations = [
            user.is_authorized,
            user.is_valid_password(password)
        ]

        if all(validations):
            self.successful_login(username)
            return username

    def get_user(self, username):
        return None

    def user_exists(self, username):
        return self.get_user(username) is not None

    def validate_username(self, username):
        invalid_chars = [',', ' ']
        if any((char in username) for char in invalid_chars):
            return False
        return super().validate_username(username)

    def get_handlers(self, app):
        native_handlers = [
            (r'/login', LoginHandler),
            (r'/check_token', TokenValidateHandler),
        ]
        return native_handlers

