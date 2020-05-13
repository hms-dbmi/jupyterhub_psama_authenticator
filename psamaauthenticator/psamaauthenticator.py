import bcrypt
import dbm
import os
from datetime import datetime
from jupyterhub.auth import Authenticator
from pathlib import Path

from sqlalchemy import inspect
from tornado import gen
from traitlets import Bool, Integer, Unicode

from .handlers import (AuthorizationHandler, ChangeAuthorizationHandler,
                       ChangePasswordHandler, LoginHandler, SignUpHandler)
from .orm import UserInfo


class PsamaAuthenticator(Authenticator):

    int_config_traitlet = Integer(
        config=True,
        default=0,
        help="""
        description goes here
        """
    )
    bool_config_traitlet = Bool(
        config=True,
        default_value=True,
        help="""
        description goes here
        """
    )
    str_config_traitlet = Unicode(
        '',
        config=True,
        help="""
        description goes here 
        """
    )
    psama_token_introspection_token = Unicode(
        '',
        config=True,
        help="""
        The secret token used by this authenticator to allow it to properly call the token introspection endpoint  
        """
    )
    psama_token_introspection_endpoint = Unicode(
        '',
        config=True,
        help="""
        The endpoint to call for token introspection IE. "http(s)://hostname/token/inspect"
        """
    )
    psama_application_id = Unicode(
        '',
        config=True,
        help="""
        Path to store the db file of FirstUse with username / pwd hash in
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
        return UserInfo.find(self.db, self.normalize_username(username))

    def user_exists(self, username):
        return self.get_user(username) is not None

    def create_user(self, username, pw, **kwargs):
        username = self.normalize_username(username)

        if self.user_exists(username):
            return

        if not self.is_password_strong(pw) or \
           not self.validate_username(username):
            return

        if not self.enable_signup:
            return

        encoded_pw = bcrypt.hashpw(pw.encode(), bcrypt.gensalt())
        infos = {'username': username, 'password': encoded_pw}
        infos.update(kwargs)
        if username in self.admin_users or self.open_signup:
            infos.update({'is_authorized': True})

        try:
            user_info = UserInfo(**infos)
        except AssertionError:
            return

        self.db.add(user_info)
        self.db.commit()
        return user_info

    def validate_username(self, username):
        invalid_chars = [',', ' ']
        if any((char in username) for char in invalid_chars):
            return False
        return super().validate_username(username)

    def get_handlers(self, app):
        native_handlers = [
            (r'/login', LoginHandler),
            (r'/signup', SignUpHandler),
            (r'/authorize', AuthorizationHandler),
            (r'/authorize/([^/]*)', ChangeAuthorizationHandler)
        ]
        return native_handlers

    def delete_user(self, user):
        user_info = self.get_user(user.name)
        if user_info is not None:
            self.db.delete(user_info)
            self.db.commit()
        return super().delete_user(user)

