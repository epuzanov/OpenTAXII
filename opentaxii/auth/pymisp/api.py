import jwt
import structlog
from .spymisp import SimplifiedPyMISP as PyMISP

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

    :param url: URL of the MISP instance you want to connect to
    :param ssl: can be True or False (to check ot not the validity of the
                certificate. Or a CA_BUNDLE in case of self signed certificate
                (the concatenation of all the *.crt of the chain)
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict
    :param cert: Client certificate
    :param tool: The software using PyMISP, used to set a unique user-agent
    :param str secret: secret string used for token generation
    :param int token_ttl_secs: TTL for JWT token, in seconds.
    """

    def __init__(self, **kwargs):
        kwargs.pop("key", None)
        if not kwargs.get("url"):
            raise ValueError('MISP URL is not defined for %s.%s' % (
                self.__module__, self.__class__.__name__))
        self.secret = kwargs.pop("secret", None)
        if not self.secret:
            raise ValueError('Secret is not defined for %s.%s' % (
                self.__module__, self.__class__.__name__))
        self.token_ttl_secs = kwargs.pop("token_ttl_secs", 60 * 60) # 60min
        self.misp_kwargs = kwargs

    def authenticate(self, username, password):
        log.info("TRACE: authenticate")
        try:
            user = PyMISP(key=password, **self.misp_kwargs
                ).get_user().get("User", {})
            if user.get("email") != username or not user.get("authkey"):
                raise UnauthorizedException
        except:
            return
        exp = datetime.utcnow() + timedelta(minutes=self.token_ttl_secs)
        return jwt.encode(
            {'account_id': user["authkey"], 'exp': exp},
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
        misp = PyMISP(key=account_id, **self.misp_kwargs)
        user = misp.get_user().get("User", {})
        if not user.get("id"):
            return
        roles = {r["Role"]["id"]:r["Role"] for r in misp.roles()}
        tags=[t for t in misp.tags() if t["name"][:17]=="taxii:collection="]
        account = self._user_to_account(user, roles, tags)
        account.details["misp"] = misp
        return account

    def delete_account(self, username):
        log.info("TRACE: delete_account")
        pass

    def get_accounts(self):
        log.info("TRACE: get_accounts")
        misp = context.account.details["misp"]
        try:
            roles = {r["Role"]["id"]:r["Role"] for r in misp.roles()}
            tags = [t for t in misp.tags() if t["name"][:15]=="taxii:collectio"]
            return [self._user_to_account(user["User"], roles, tags
                ) for user in misp.users()]
        except:
            return []

    def update_account(self, obj, password):
        log.info("TRACE: update_account")
        return obj

    def _user_to_account(self, user, roles, tags):
        log.info("TRACE: _user_to_account")
        role = roles[user["role_id"]]
        account = AccountEntity(
            id=user["id"],
            username=user["email"],
            is_admin=role["perm_site_admin"],
            permissions={})
        if role["perm_auth"]:
            if role["perm_sighting"]:
                perm = "modify"
            else:
                perm = "read"
            account.permissions["default"] = perm
            for tag in tags:
                if (role["perm_site_admin"] or (role["perm_admin"]
                        and tag["org_id"] in ('0', user["org_id"]))
                        or (tag["org_id"] in ('0', user["org_id"])
                        and tag["user_id"] in ('0', user["id"]))):
                    collection_id = tag["name"][17:].strip('"')
                    account.permissions[collection_id] = perm
        return account
