import structlog
import six
from .converters import stix_indicators, misp_events

from datetime import datetime
from opentaxii.local import context
from opentaxii.taxii import entities
from opentaxii.persistence import OpenTAXIIPersistenceAPI

__all__ = ['PyMISPAPI']

log = structlog.getLogger(__name__)

class PyMISPAPI(OpenTAXIIPersistenceAPI):
    """PyMISP implementation of OpenTAXII Persistence API.

    Implementation will work with MISP Server.

    :param str base_url="/services": OpenTAXII Services base URL.
    :param str protocol_binding=None: if None enable both bindings protocols.
    :param str content_binding=None:  if None accept all content.
    :param int result_size=10: number of returned blocks.
    :param int max_result_count=10000: maximum returned blocks.
    :param bool to_ids=True: to_ids value.
    """

    def __init__(self, **kwargs):

        base_url = kwargs.get("base_url", "/services")
        protocol_binding = kwargs.get("protocol_binding")
        content_binding = kwargs.get("content_binding")
        result_size = kwargs.get("result_size", 10)
        max_result_count = kwargs.get("max_result_count", 10000)
        protocol_bindings = [
            "urn:taxii.mitre.org:protocol:http:1.0",
            "urn:taxii.mitre.org:protocol:https:1.0"]
        content_bindings = [
            "urn:stix.mitre.org:xml:1.1.1",
            "urn:custom.example.com:json:0.0.1"]
        if protocol_binding:
            protocol_bindings = [protocol_binding]
        if content_binding:
            content_bindings = [content_binding]
        self.to_ids = kwargs.get("to_ids", True)
        self.tag = "taxii:collection=\"%s\""
        self.services = {
            "inbox": entities.ServiceEntity(
                id="inbox",
                type="inbox",
                properties={
                    "address": "%s/inbox"%base_url,
                    "description": "MISP Inbox Service",
                    "destination_collection_required": True,
                    "accept_all_content": False,
                    "authentication_required": True,
                    "supported_content": content_bindings,
                    "protocol_bindings": protocol_bindings
                }
            ),
            "discovery": entities.ServiceEntity(
                id="discovery",
                type="discovery",
                properties={
                    "address": "%s/discovery"%base_url,
                    "description": "MISP Discovery Service",
                    "advertised_services": [
                        "inbox",
                        "discovery",
                        "collection_management",
                        "poll"],
                    "protocol_bindings": protocol_bindings
                }
            ),
            "collection_management": entities.ServiceEntity(
                id="collection_management",
                type="collection_management",
                properties={
                    "address": "%s/collection-management"%base_url,
                    "description": "MISP Collection Management Service",
                    "authentication_required": True,
                    "protocol_bindings": protocol_bindings
                }
            ),
            "poll": entities.ServiceEntity(
                id="poll",
                type="poll",
                properties={
                    "address": "%s/poll"%base_url,
                    "description": "MISP Poll Service",
                    "subscription_required": False,
                    "max_result_count": max_result_count//result_size or 1,
                    "max_result_size": result_size,
                    "authentication_required": True,
                    "protocol_bindings": protocol_bindings
                }
            )
        }

    def get_services(self, collection_id=None):
        log.info("TRACE: get_services")
        return self.services.values()

    def get_service(self, service_id):
        log.info("TRACE: get_service")
        return self.services.get(service_id)

    def update_service(self, entity):
        log.info("TRACE: update_service")
        return entity

    def create_service(self, entity):
        log.info("TRACE: create_service")
        return entity

    def get_collections(self, service_id=None):
        log.info("TRACE: get_collections %s"%service_id)
        if service_id == "discovery" or not context.account:
            return []
        return [self.get_collection(name, service_id
            ) for name in context.account.permissions.keys()]

    def get_collection(self, name, service_id=None):
        log.info("TRACE: get_collection")
        if name != "default":
            description="MISP collection for Tag: %s"%(self.tag%name)
        else:
            description = "Default MISP Collection"
        content_bindings = self.services[service_id].properties.get(
            "supported_content", [])
        return entities.CollectionEntity(
            id=name,
            name=name,
            available=True,
            description=description,
            accept_all_content=False,
            supported_content=content_bindings)

    def update_collection(self, entity):
        log.info("TRACE: update_collection")
        if entity.name == "default":
            return
        misp = context.account.details["misp"]
        for tag in misp.tags():
            if tag["name"] == self.tag%entity.id:
                tag["name"] = self.tag%entity.name
                misp.update_tag(tag)
                entity.id = entity.name
                break
        return entity

    def delete_collection(self, collection_name):
        log.info("TRACE: delete_collection")
        if collection_name == "default":
            return
        misp = context.account.details["misp"]
        for tag in misp.tags():
            if tag["name"] == self.tag%collection_name:
                misp.delete_tag(tag)
                break

    def delete_service(self, service_id):
        log.info("TRACE: delete_service")
        pass

    def get_content_blocks_count(self, collection_id=None, start_time=None,
                                 end_time=None, bindings=None):

        log.info("TRACE: get_content_blocks_count")
        return len([e for e in context.account.details["misp"].search(
            date_from=start_time if start_time else None,
            date_to=end_time if end_time else None,
            tags=self.tag%collection_id if collection_id != "default" else None,
            to_ids=self.to_ids,
            metadata=True,
            ) if event.get("Event", {}).get("attribute_count", "0") != "0"])

    def get_content_blocks(self, collection_id=None, start_time=None,
                           end_time=None, bindings=None, offset=0, limit=None):

        log.info("TRACE: get_content_blocks")

        misp_evts = context.account.details["misp"].search(
            return_format = "stix",
            date_from=start_time if start_time else None,
            date_to=end_time if end_time else None,
            tags=self.tag%collection_id if collection_id != "default" else None,
            to_ids=self.to_ids,
            limit=limit,
            page=(int(offset / limit + 1) if limit else None)).encode("utf-8")

        blocks = []
        for stix, timestamp in stix_indicators(six.BytesIO(misp_evts)):
            log.info("TRACE: get_content_blocks event %s"%bindings)
            blocks.append(entities.ContentBlockEntity(stix, timestamp,
                content_binding=entities.ContentBindingEntity(
                    "urn:stix.mitre.org:xml:1.1.1")))
        return blocks

    def create_collection(self, entity):
        log.info("TRACE: create_collection")
        tag = {"name": self.tag%entity.name, "exportable": False}
        context.account.details["misp"].add_tag(tag)
        return entity

    def set_collection_services(self, collection_id, service_ids):
        log.info("TRACE: set_collection_services")
        pass

    def create_inbox_message(self, entity):
        log.info("TRACE: create_inbox_message")
        return entity

    def create_content_block(self, entity, collection_ids=None,
                             service_id=None):
        log.info("TRACE: create_content_block")
        for event in misp_events(six.BytesIO(entity.content.encode("utf-8"))):
            misp = context.account.details["misp"]
            event_id = event.get("uuid", "")
            if not (event_id and misp.search(uuid=event_id, metadata=True)):
                for e in misp.search(eventinfo=event["info"], metadata=True):
                    if e.get("Event", {}).get("uuid"):
                        event_id = e["Event"]["uuid"]
                        event["Event"]["id"] = e["Event"]["id"]
                        event["Event"]["uuid"] = event_id
                        break
                else:
                    event_id = None
            if event_id:
                misp.update_event(event, event_id)
            else:
                event_id = misp.add_event(event).get("Event", {}).get("uuid")
            for collection_id in collection_ids or []:
                if collection_id != "default":
                    misp.tag(event_id, self.tag%collection_id)

        return entities.ContentBlockEntity(
            entity.content,
            entity.timestamp_label,
            content_binding=entity.content_binding,
            inbox_message_id=entity.inbox_message_id)

    def create_result_set(self, entity):
        log.info("TRACE: create_result_set %s"%entity)
        if "result_sets" not in context.account.details:
            context.account.details["result_sets"]
        context.account.details["result_sets"][entity.id] = entity
        return entity

    def get_result_set(self, result_set_id):
        log.info("TRACE: get_result_set %s"%result_set_id)
        return context.account.details["result_sets"][result_set_id]
        try:
            id, start, end = result_set_id.split("_")
            start = datetime.utcfromtimestamp(int(start)) if not "0" else None
            end = datetime.utcfromtimestamp(int(end)) if not "0" else None
            timeframe = (start, end)
        except:
            timeframe = (None, None)
        content_bindings = self.services["poll"].properties.get(
            "supported_content", [])
        return entities.ResultSetEntity(
            id=result_set_id,
            collection_id=self.get_collections("poll")[0].id,
            content_bindings=content_bindings,
            timeframe=timeframe)

    def get_subscription(self, subscription_id):
        log.info("TRACE: get_subscription")
        for subscription in self.get_subscriptions("poll"):
            if subscription.subscription_id == subscription_id:
                return subscription

    def get_subscriptions(self, service_id):
        log.info("TRACE: get_subscriptions")
        return []

    def update_subscription(self, entity):
        log.info("TRACE: update_subscription")
        return entity

    def create_subscription(self, entity):
        log.info("TRACE: create_subscription")
        return entity

    def delete_content_blocks(self, collection_name, start_time, end_time=None,
            with_messages=False):
        log.info("TRACE: delete_content_blocks")
        return 0
