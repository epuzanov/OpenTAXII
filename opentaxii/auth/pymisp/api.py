import jwt
import structlog
import pymisp

from datetime import datetime, timedelta

from opentaxii.auth import OpenTAXIIAuthAPI
from opentaxii.entities import Account as AccountEntity
from opentaxii.exceptions import UnauthorizedException
from opentaxii.local import context

__all__ = ['PyMISPAPI']


log = structlog.getLogger(__name__)


class PyMISPAPI(OpenTAXIIAuthAPI):
    """PyMISP implementation of OpenTAXII Auth API.

    Implementation will work with MISP Server.

    :param str misp_url: MISP Server URL
    :param str misp_apikey: MISP APIKEY
    :param bool verify_sql=True: if True, if False tust Cerificate.
    :param str secret: secret string used for token generation
    :param int token_ttl_secs: TTL for JWT token, in seconds.
    """
    def __init__(self,
            misp_url,
            misp_apikey,
            verify_ssl=True,
            secret=None,
            token_ttl_secs=None):

        self.misp = pymisp.ExpandedPyMISP(misp_url, misp_apikey, verify_ssl)
        self.misp.global_pythonify = True
        if not secret:
            raise ValueError('Secret is not defined for %s.%s' % (
                self.__module__, self.__class__.__name__))
        self.secret = secret
        self.token_ttl_secs = token_ttl_secs or 60 * 60  # 60min

    def authenticate(self, username, password):
        log.info("TRACE: authenticate")
        try:
            account = pymisp.ExpandedPyMISP(
                self.misp.root_url, password, self.misp.ssl).get_user()["User"]
            if account["email"] != username or "error" in account:
                raise UnauthorizedException
        except:
            return
        exp = datetime.utcnow() + timedelta(minutes=self.token_ttl_secs)
        return jwt.encode(
            {'account_id': account["id"], 'exp': exp},
            self.secret)

    def get_account(self, token):
        log.info("TRACE: get_account")
        try:
            payload = jwt.decode(token, self.secret)
        except jwt.ExpiredSignatureError:
            log.warning('Invalid token used', token=token)
            return
        except jwt.DecodeError:
            log.warning('Can not decode a token', token=token)
            return
        account_id = payload.get('account_id')
        if not account_id:
            return
        misp=pymisp.ExpandedPyMISP(self.misp.root_url,account_id,self.misp.ssl)
        misp.global_pythonify = True
        user = misp.get_user()
        if not hasattr(user, "id"):
            return
        roles = {r.id:r for r in self.misp.roles()}
        return self._user_to_account(user, roles)

    def delete_account(self, username):
        log.info("TRACE: delete_account")
        pass

    def get_accounts(self):
        log.info("TRACE: get_accounts")
        misp = self._getPyMISP()
        try:
            roles = {r.id:r for r in misp.roles()}
            organisations = {o.id:o.name for o in misp.organisations()}
            return [self._user_to_account(user, roles,
                organisations[user.org_id]) for user in misp.users()]
        except:
            return []

    def update_account(self, obj, password):
        log.info("TRACE: update_account")
        return obj

    def _user_to_account(self, user, roles, org=None):
        log.info("TRACE: _user_to_account")
        role = roles[user.role_id]
        if not org:
            misp = self._getPyMISP()
            org = misp.get_organisation(user.org_id).name
        account = AccountEntity(
            id=user.id,
            username=user.email,
            is_admin=role.perm_site_admin,
            permissions={},
            authkey=user.authkey)
        if not account.is_admin:
            if role.perm_auth:
                if role.perm_sighting:
                    account.permissions[org] = "modify"
                else:
                    account.permissions[org] = "read"
        return account

    def _getPyMISP(self, pythonify=True):
        if context.account and context.account.details.get("authkey"):
            misp = pymisp.ExpandedPyMISP(
                self.misp.root_url,
                context.account.details["authkey"],
                self.misp.ssl)
            misp.global_pythonify = pythonify
        else:
            misp = self.misp
        return misp
