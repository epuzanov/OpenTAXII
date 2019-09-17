import structlog
import six
import pymisp
import misp_stix_converter

from datetime import datetime
from opentaxii.local import context
from opentaxii.taxii import entities
from opentaxii.persistence import OpenTAXIIPersistenceAPI

__all__ = ['PyMISPAPI']

log = structlog.getLogger(__name__)

class PyMISPAPI(OpenTAXIIPersistenceAPI):
    """PyMISP implementation of OpenTAXII Persistence API.

    Implementation will work with MISP Server.

    Note: this implementation ignores ``context.account`` and does not have
    any access rules.

    :param str misp_url: MISP Server URL
    :param str misp_apikey: MISP APIKEY
    :param bool verify_sql=True: if True, if False tust Cerificate.
    :param str base_url="/services": OpenTAXII Services base URL
    :param str protocol_binding=None: if 'http' enable HTTP, if 'https' enable HTTPS
                                      if None enable both bindings protocols.
    :param str content_binding="xml": Prossible values 'xml' and 'json'
    :param int max_result_count=10000: maximum returned blocks
    """

    def __init__(self,
            misp_url,
            misp_apikey,
            verify_ssl=True,
            base_url="/services",
            protocol_binding=None,
            content_binding="xml",
            max_result_count=10000):

        result_size = 100
        protocol_bindings = []
        if not protocol_binding or protocol_binding == "http":
            protocol_bindings.append("urn:taxii.mitre.org:protocol:http:1.0")
        if not protocol_binding or protocol_binding == "https":
            protocol_bindings.append("urn:taxii.mitre.org:protocol:https:1.0")
        if not content_binding or content_binding == "json":
            self.content_binding = entities.ContentBindingEntity(
                "urn:custom.example.com:json:0.0.1")
        else:
            self.content_binding = entities.ContentBindingEntity(
                "urn:stix.mitre.org:xml:1.1.1")
        self.misp = pymisp.ExpandedPyMISP(misp_url, misp_apikey, verify_ssl)
        self.misp.global_pythonify = True
        self.org = self.misp.get_organisation(self.misp.get_user().org_id).name
        self.services = {
            "inbox": entities.ServiceEntity(
                id="inbox",
                type="inbox",
                properties={
                    "address": "%s/inbox"%base_url,
                    "description": "MISP Inboxi Service",
                    "destination_collection_required": True,
                    "accept_all_content": True,
                    "authentication_required": True,
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
        collections = []
        if service_id != "discovery":
            collections.append(self.get_collection(self.org, service_id=None))
        return collections

    def get_collection(self, name, service_id=None):
        log.info("TRACE: get_collection")
        return entities.CollectionEntity(
            id=self.org,
            name=self.org,
            available=True,
            description="Collection for MISP Organization: %s"%self.org,
            accept_all_content=False,
            supported_content=[self.content_binding])

    def update_collection(self, entity):
        log.info("TRACE: update_collection")
        return entity

    def delete_collection(self, collection_name):
        log.info("TRACE: delete_collection")
        pass

    def delete_service(self, service_id):
        log.info("TRACE: delete_service")
        pass

    def get_content_blocks_count(self, collection_id=None, start_time=None,
                                 end_time=None, bindings=None):

        log.info("TRACE: get_content_blocks_count")
        return len([e for e in self.misp.search(
            date_from=start_time.isoformat() if start_time else None,
            date_to=end_time.isoformat() if end_time else None,
            metadata=True) if e.Org.name == collection_id])

    def get_content_blocks(self, collection_id=None, start_time=None,
                           end_time=None, bindings=None, offset=0, limit=None):

        log.info("TRACE: get_content_blocks %s"%context.account.details)

        misp_evts = self.misp.search(
            date_from=start_time.isoformat() if start_time else None,
            date_to=end_time.isoformat() if end_time else None,
            limit=limit,
            page=(int(offset / limit + 1) if limit else None))

        blocks = []
        for event in misp_evts:
            if event.Org.name == collection_id:
                log.info("TRACE: get_content_blocks event %s"%event)
                stix = pymisp.tools.stix.make_stix_package(event, to_xml=True)
                blocks.append(entities.ContentBlockEntity(stix, event.timestamp,
                    content_binding=self.content_binding))
        return blocks

    def create_collection(self, entity):
        log.info("TRACE: create_collection")
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

        event = pymisp.tools.stix.load_stix(entity.content)

        if (len(event.attributes) > 0):
            evt_attributes = [(a.type, a.value) for a in event.attributes]
            misp_evts = self.misp.search(eventinfo=event.info)
            if misp_evts:
                for attr in misp_evts[0].attributes:
                    if (attr.type, attr.value) not in evt_attributes:
                        self.misp.delete_attribute(attr)
                return self.misp.update_event(event, misp_evts[0].id)
            else:
                return self.misp.add_event(event)

        return entities.ContentBlockEntity(
            entity.content,
            entity.timestamp_label,
            content_binding=entity.content_binding,
            inbox_message_id=entity.inbox_message_id)

    def create_result_set(self, entity):
        log.info("TRACE: create_result_set %s"%entity)
        start = (entity.timeframe[0] or datetime.utcfromtimestamp(0)).timestamp()
        end = (entity.timeframe[1] or datetime.utcfromtimestamp(0)).timestamp()
        entity.id = "%s_%s_%s"%(entity.id, int(start), int(end))
        return entity

    def get_result_set(self, result_set_id):
        log.info("TRACE: get_result_set %s"%result_set_id)
        try:
            id, start, end = result_set_id.split("_")
            start = datetime.utcfromtimestamp(int(start)) if not "0" else None
            end = datetime.utcfromtimestamp(int(end)) if not "0" else None
            timeframe = (start, end)
        except:
            timeframe = (None, None)
        return entities.ResultSetEntity(
            id=result_set_id,
            collection_id=self.get_collections("pull")[0].id,
            content_bindings=[self.content_binding],
            timeframe=timeframe)

    def get_subscription(self, subscription_id):
        log.info("TRACE: get_subscription")
        for subscription in self.get_subscriptions("pull"):
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
