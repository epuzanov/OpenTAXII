import sys
import ssl as SSL
import json
from datetime import date, datetime
from six.moves import urllib

class SimplifiedPyMISP(object):
    """Simplified Python API for MISP

    :param url: URL of the MISP instance you want to connect to
    :param key: API key of the user you want to use
    :param ssl: can be True or False (to check ot not the validity of the
                certificate. Or a CA_BUNDLE in case of self signed certificate
                (the concatenation of all the *.crt of the chain)
    :param debug: Write all the debug information to stderr
    :param proxies: Proxy dict
    :param cert: Client certificate
    :param auth: The auth parameter is passed directly to requests AuthBase
    :param tool: The software using PyMISP, used to set a unique user-agent
    """

    def __init__(self, url, key, ssl=True, debug=False, proxies={}, cert=None,
            auth=None, tool=''):

        if url and url[-1] != "/":
            url += "/"
        self.root_url = url
        u_agent = "SPyMISP 0.0.1 - Python "
        u_agent += ".".join(str(x) for x in sys.version_info[:2])
        if tool:
            u_agent += " - %s"%tool
        handlers = []
        ctx = SSL.create_default_context()
        if not ssl:
            ctx.check_hostname = False
            ctx.verify_mode = SSL.CERT_NONE
        if isinstance(cert, tuple):
            ctx.load_cert_chain(*cert)
        elif isinstance(cert, str):
            ctx.load_cert_chain(cert)
        debuglevel = 1 if debug else 0
        handlers.append(urllib.request.HTTPHandler(debuglevel=debuglevel))
        handlers.append(urllib.request.HTTPSHandler(debuglevel=debuglevel,
            context=ctx))
        handlers.append(urllib.request.ProxyHandler(proxies))
        if auth:
            pwd_mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            pwd_mgr.add_password(None, url, getattr(auth, "username", ""), 
                getattr(auth, "password", ""))
            if auth.__class__.__name__ == "HTTPBasicAuth":
                handlers.append(urllib.request.HTTPBasicAuthHandler(pwd_mgr))
            elif auth.__class__.__name__ == "HTTPProxyAuth":
                handlers.append(urllib.request.ProxyBasicAuthHandler(pwd_mgr))
            elif auth.__class__.__name__ == "HTTPDigestAuth":
                handlers.append(urllib.request.HTTPDigestAuthHandler(pwd_mgr))
            else:
                handlers.append(urllib.request.HTTPBasicAuthHandler(pwd_mgr))
        self._opener = urllib.request.build_opener(*handlers)
        self._opener.addheaders = [("Authorization",key),("User-Agent",u_agent),
            ("Content-Type","application/json"),("Accept","application/json")]

    def _open(self, request, as_json=True):
        try:
            result = self._opener.open(request)
            for ct_part in (result if hasattr(result, "getheader"
                ) else result.info()).getheader("Content-Type", "").split(";"):
                if ct_part.strip().lower().startswith("charset"):
                    charset = ct_part.split("=")[-1].strip().lower()
                    break
            else:
                charset = "utf-8"
            if as_json:
                return json.load(result, encoding=charset)
            else:
                return result.read().decode(charset)
        except urllib.error.URLError as e:
            if isinstance(e.reason, Exception) and hasattr(e.reason, "reason"):
                e = e.reason
            if isinstance(request, urllib.request.Request):
                request = request.get_full_url()
            return {'errors': (1, {'name': e.reason, 'message': e.reason,
                'url': request})}
        except urllib.error.HTTPError as e:
            if isinstance(request, urllib.request.Request):
                request = request.get_full_url()
            return {'errors': (e.code, {'name': e.reason, 'message': e.reason,
                'url': request})}
        except Exception as e:
            return {'errors': e}

    def search(self, controller="events", **kwargs):
        "Search in the MISP instance"
        kwargs["returnFormat"] = kwargs.pop("return_format", "json")
        kwargs["type"] = kwargs.pop("type_attribute", None)
        kwargs["quickFilter"] = kwargs.pop("quick_filter", None)
        kwargs["from"] = kwargs.pop("date_from", None)
        kwargs["to"] = kwargs.pop("date_to", None)
        kwargs["withAttachments"] = kwargs.pop("with_attachments", None)
        kwargs["enforceWarninglist"] = kwargs.pop("enforce_warninglist", None)
        kwargs["includeEventUuid"] = kwargs.pop("include_event_uuid", None)
        kwargs["includeEventTags"] = kwargs.pop("include_event_tags", None)
        kwargs["sgReferenceOnly"] = kwargs.pop("sg_reference_only", None)
        kwargs["includeContext"] = kwargs.pop("include_context", None)
        kwargs["includeSightings"] = kwargs.pop("include_sightings", None)
        kwargs["includeCorrelations"] = kwargs.pop("include_correlations", None)
        for key in list(kwargs.keys()):
            if kwargs[key] is None:
                del kwargs[key]
            elif isinstance(kwargs[key], bool):
                kwargs[key] = 1 if kwargs[key] else 0
            elif isinstance(kwargs[key], datetime):
                kwargs[key] = kwargs[key].isoformat()
            elif isinstance(kwargs[key], date):
                kwargs[key] = datetime.combine(kwargs[key],
                    datetime.max.time()).isoformat()
        req = urllib.request.Request(self.root_url + controller + "/restSearch",
            data=json.dumps(kwargs).encode("utf-8"))
        req.add_header("Content-Type","application/json")
        if kwargs["returnFormat"] == "json":
            return self._open(req, True).get("response", [])
        else:
            as_json = False
            if kwargs["returnFormat"] in ("stix", "xml"):
                req.add_header("Accept", "application/xml")
            else:
                req.add_header("Accept", "text/plain")
            return self._open(req, False)

    def add_event(self, event, **kwargs):
        """Add a new event on a MISP instance"""
        req = urllib.request.Request(self.root_url + "events",
            data = json.dumps(event).encode("utf-8"))
        return self._open(req)

    def update_event(self, event, event_id=None, **kwargs):
        """Update an event on a MISP instance"""
        if event_id is None:
            event_id = event.get("id")
        req = urllib.request.Request(self.root_url + "events/" + event_id,
            data = json.dumps(event).encode("utf-8"))
        return self._open(req)

    def delete_event(self, event, **kwargs):
        """Delete an event from a MISP instance"""
        req = urllib.request.Request(self.root_url+"events/delete/"+event["id"])
        req.get_method = lambda: "DELETE"
        return self._open(req)

    def roles(self, **kwargs):
        """Get the list of existing roles."""
        return self._open(self.root_url + "roles")

    def tag(self, event_id, tag, **kwargs):
        """Get the list of existing tags."""
        return self._open(self.root_url + "tags").get("Tag", [])

    def tag(self, misp_entity, tag):
        """Tag an event or an attribute. misp_entity can be a UUID"""
        if isinstance(misp_entity, dict):
            uuid = misp_entity.get("uuid")
        else:
            uuid = misp_entity
        to_post = {'uuid': uuid, 'tag': tag}
        req = urllib.request.Request(self.root_url + "tags/attachTagToObject",
            data = json.dumps(to_post).encode("utf-8"))
        return self._open(req)

    def untag(self, misp_entity, tag):
        """Untag an event or an attribute. misp_entity can be a UUID"""
        if isinstance(misp_entity, dict):
            uuid = misp_entity.get("uuid")
        else:
            uuid = misp_entity
        to_post = {'uuid': uuid, 'tag': tag}
        req = urllib.request.Request(self.root_url + "tags/removeTagFromObject",
            data = json.dumps(to_post).encode("utf-8"))
        return self._open(req)

    def tags(self, **kwargs):
        """Get the list of existing tags."""
        return self._open(self.root_url + "tags").get("Tag", [])

    def get_tag(self, tag, **kwargs):
        """Get a tag by id."""
        req = urllib.request.Request(self.root_url + "tags/view/" + tag["id"])
        return self._open(req)

    def add_tag(self, tag, **kwargs):
        """Add a new tag on a MISP instance"""
        req = urllib.request.Request(self.root_url + "tags/add",
            data = json.dumps(tag).encode("utf-8"))
        return self._open(req)

    def enable_tag(self, tag, **kwargs):
        """Enable a tag."""
        tag["hide_tag"] = False
        return self.update_tag(tag, **kwargs)

    def disable_tag(self, tag, **kwargs):
        """Disable a tag."""
        tag["hide_tag"] = True
        return self.update_tag(tag, **kwargs)

    def update_tag(self, tag, tag_id=None, **kwargs):
        """Edit only the provided parameters of a tag."""
        if tag_id is None:
            tag_id = tag.get("id")
        req = urllib.request.Request(self.root_url + "tags/edit/" + tag_id,
            data = json.dumps(tag).encode("utf-8"))
        return self._open(req)

    def delete_tag(self, tag, **kwargs):
        """Delete an attribute from a MISP instance"""
        req = urllib.request.Request(self.root_url + "tags/delete/" + tag["id"])
        req.get_method = lambda: "POST"
        return self._open(req)

    def users(self, **kwargs):
        """Get all users."""
        return self._open(self.root_url + "admin/users")

    def get_user(self, user="me", **kwargs):
        '''Get a user. `me` means the owner of the API key doing the query.'''
        return self._open(self.root_url + "users/view/" + user)
