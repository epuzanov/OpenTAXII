import copy
import json
from datetime import datetime as dt
import xml.etree.cElementTree as etree

def processAddressObj(properties, attribute, as_object):
    for el in properties.iter():
        if el.tag.endswith("Address_Value"):
            attribute["value"] = el.text
            break
    else:
        return attribute
    category = properties.attrib.get("category")
    is_dst = properties.attrib.get("is_destination") == "true"
    is_src = properties.attrib.get("is_source") == "true"
    if category == "e-mail":
        attribute["type"] = "email-dst" if is_dst or not is_src else "email-src"
    elif category == "ipv4-addr":
        attribute["type"] = "ip-src" if is_src or not is_dst else "ip-dst"
    elif category == "ipv6-addr":
        attribute["type"] = "ip-src" if is_src or not is_dst else "ip-dst"
    return attribute

def processNetworkConnectionObj(properties, attribute, as_object):
    for el in properties.iter():
        if el.tag.endswith("Hostname_Value"):
            attribute["type"] = "hostname"
            attribute["value"] = el.text
            break
        elif el.tag.endswith("Destination_Socket_Address"):
            attr = {"type": "ip-dst"}
        elif el.tag.endswith("Source_Socket_Address"):
            attr = {"type": "ip-src"}
        elif el.tag.endswith("Address_Value"):
            if el.attrib.get("condition", "Equals") == "Equals":
                attribute["value"] = el.text
            break
    return attribute

def processFileObj(properties, attribute, as_object):
    attributes = []
    for el in properties.iter():
        if el.tag.endswith("Hashes"):
            for _hash in el.iter(tag="{http://cybox.mitre.org/common-2}Hash"):
                attr = {}
                for h_el in _hash.iter():
                    if h_el.tag.endswith("Type"):
                        attr["type"] = h_el.text.lower()
                        if attr["type"] not in ("md5","sha1","sha256","ssdeep"):
                            attr["type"] = "other"
                    elif h_el.tag.endswith("Simple_Hash_Value"):
                        if attr.get("type", "other") == "other":
                            attr["type"] = {32:"md5",40:"sha1",64:"sha256"
                                }.get(len(h_el.text), "other")
                        attr["object_relation"] = attr["type"]
                        attr["value"] = h_el.text
                        attr["distribution"] = "5"
                if attr.get("type", "other") != "other":
                    attributes.append(attr)
        elif el.tag.endswith("File_Name"):
            attributes.append({
                "value": el.text,
                "type": "filename",
                "object_relation": "filename",
                "distribution": "5",
                "to_ids": False,
                "disable_correlation": False})
        elif el.tag.endswith("File_Extension"):
            attributes.append({
                "value": el.text,
                "type": "pattern-in-file",
                "object_relation": "pattern-in-file",
                "distribution": "5",
                "to_ids": False,
                "disable_correlation": True})
        elif el.tag.endswith("Size_In_Bytes"):
            attributes.append({
                "value": el.text,
                "type": "size-in-bytes",
                "object_relation": "size-in-bytes",
                "distribution": "5",
                "to_ids": False,
                "disable_correlation": True})
    if len(attributes) == 1 and not as_object:
        attribute["type"] = attributes[0]["type"]
        attribute["value"] = attributes[0]["value"]
        if "to_ids" in attributes[0]:
            attribute["to_ids"] = attributes[0]["to_ids"]
        if "disable_correlation" in attributes[0]:
            attribute["disable_correlation"]=attributes[0]["disable_correlation"]
        if "object_relation" in attributes[0]:
            del attributes[0]["object_relation"]
    elif len(attributes) > 1 or as_object:
        attributes.append({"object_relation":"state","type":"text","value":""})
        attributes.append({"object_relation":"file-encoding","type":"text",
            "value":""})
        attribute.pop("type", None)
        attribute["Attribute"] = attributes
        attribute["name"] = "file"
        attribute["meta-category"] = "file"
        attribute["template_uuid"] = "688c46fb-5edb-40a3-8273-1af7923e2215"
        attribute["template_version"] = "16"
        attribute["distribution"] = "5"
    return attribute

def processEmailObj(properties, attribute, as_object):
    attributes = []
    refs = []
    for el in properties.iter():
        if el.tag.endswith("Header"):
            for h_el in el.iter():
                attr = {"value":h_el.text, "to_ids":False, "distribution":"5",
                        "disable_correlation": True}
                if h_el.tag.endswith("To"):
                    attr["type"] = "email-dst"
                    attr["object_relation"] = "email-dst"
                elif h_el.tag.endswith("From"):
                    attr["type"] = "email-src"
                    attr["object_relation"] = "email-src"
                    attr["to_ids"] = True,
                    attr["disable_correlation"] = False
                elif h_el.tag.endswith("Subject"):
                    attr["type"] = "email-subject"
                    attr["object_relation"] = "email-subject"
                if "type" in attr:
                    attributes.append(attr)
        elif el.tag.endswith("Raw_Header"):
            attributes.append({"value":el.text, "type":"email-header",
                "object_relation":"email-header", "to_ids":False,
                "disable_correlation": True})
        elif el.tag.endswith("Attachments"):
            for a_el in el.iter():
                if a_el.tag.endswith("File"):
                    o_ref = a_el.attrib.get("object_reference", "")
                    if len(o_ref) > 35:
                        refs.append({"referenced_uuid":o_ref[-36:],
                            "relationship_type":"Attachment"})
    if len(attributes) == 1 and not refs and not as_object:
        attribute["type"] = attributes[0]["type"]
        attribute["value"] = attributes[0]["value"]
        if "to_ids" in attributes[0]:
            attribute["to_ids"] = attributes[0]["to_ids"]
        if "disable_correlation" in attributes[0]:
            attribute["disable_correlation"]=attributes[0]["disable_correlation"]
        if "object_relation" in attributes[0]:
            del attributes[0]["object_relation"]
    elif len(attributes) > 1 or refs or as_object:
        attribute.pop("type", None)
        attribute["Attribute"] = attributes
        attribute["ObjectReference"] = refs
        attribute["name"] = "email"
        attribute["meta-category"] = "network"
        attribute["template_uuid"] = "a0c666e0-fc65-4be8-b48f-3423d788b552"
        attribute["template_version"] = "13"
        attribute["distribution"] = "5"
    return attribute

def stix_reports(xml_file):
    for event, el in etree.iterparse(xml_file, ("end", "start-ns")):
        if event == "end":
            if element.tag == "{http://stix.mitre.org/stix-1}Package":
                element.tag = "{http://stix.mitre.org/stix-1}STIX_Package"
                yield etree.tostring(element)
        elif event == "start-ns":
            etree.register_namespace(*element)

def stix_indicators(xml_file):
    for event, el in etree.iterparse(xml_file, ("start", "end", "start-ns")):
        if event == "start":
            if el.tag == "{http://stix.mitre.org/common-1}Indicator":
                indicator = etree.SubElement(indicators,
                    "{http://stix.mitre.org/stix-1}Indicator")
                for attr in el.attrib.items():
                    indicator.set(*attr)
            elif el.tag=="{http://stix.mitre.org/Incident-1}Related_Indicators":
                indicators = etree.SubElement(package,
                    "{http://stix.mitre.org/stix-1}Indicators")
            elif el.tag in ("{http://stix.mitre.org/stix-1}STIX_Package"
                    "{http://stix.mitre.org/stix-1}Package"):
                package = etree.Element("{http://stix.mitre.org/stix-1}STIX_Package")
                for attr in el.attrib.items():
                    package.set(*attr)
        elif event == "end":
            if el.tag in ("{http://stix.mitre.org/Indicator-2}Title",
                    "{http://stix.mitre.org/Indicator-2}Description",
                    "{http://stix.mitre.org/Indicator-2}Observable"):
                indicator.append(copy.deepcopy(el))
                el.clear()
            elif el.tag == "{http://stix.mitre.org/Incident-1}Title":
                header = etree.SubElement(package,
                    "{http://stix.mitre.org/stix-1}STIX_Header")
                etree.SubElement(header,
                    "{http://stix.mitre.org/stix-1}Title").text = el.text
                etree.SubElement(header,
                    "{http://stix.mitre.org/stix-1}Package_Intent",
                    attrib={"{http://www.w3.org/2001/XMLSchema-instance}type":
                        "stixVocabs:PackageIntentVocab-1.0"}).text="Indicators"
            elif el.tag == "{http://stix.mitre.org/stix-1}Package":
                yield etree.tostring(package)
        elif event == "start-ns":
            etree.register_namespace(*el)

def misp_events(xml_file):
    return_stix_pakage = True
    as_object = False
    isotime = dt.now().isoformat()
    for event, el in etree.iterparse(xml_file, ("start", "end", "start-ns")):
        if event == "start":
            if el.tag in ("{http://stix.mitre.org/stix-1}Indicator",
                    "{http://stix.mitre.org/Incident-1}Related_Indicator",
                    "{http://cybox.mitre.org/cybox-2}Related_Object"):
                isotime = el.attrib.get("timestamp", isotime)
                attr = {}
            elif el.tag == "{http://cybox.mitre.org/cybox-2}Related_Objects":
                saved_attr = attr
                as_object = True
            elif el.tag in ("{http://stix.mitre.org/stix-1}Package",
                    "{http://stix.mitre.org/stix-1}STIX_Package"):
                isotime = el.attrib.get("timestamp", isotime)
                misp_event = {"Attribute": [],
                    "Object": [],
                    "analysis": "0",
                    "distribution": "3",
                    "info": "",
                    "threat_level_id": "2"
                    }
        elif event == "end":
            if el.tag in ("{http://stix.mitre.org/stix-1}Indicator",
                    "{http://stix.mitre.org/Incident-1}Related_Indicator",
                    "{http://cybox.mitre.org/cybox-2}Related_Object"):
                timestamp = dt.fromisoformat(isotime).timestamp()
                if el.tag.endswith("Related_Object") and "id" in el.attrib:
                    attr["uuid"] = el.attrib.get("id")[-36:]
                if "Attribute" in attr:
                    attr.pop("value", None)
                    to_ids = attr.pop("to_ids", True)
                    d_c = attr.pop("disable_correlation", True)
                    for idx in range(len(attr["Attribute"])):
                        if "to_ids" not in attr["Attribute"][idx]:
                            attr["Attribute"][idx]["to_ids"] = to_ids
                        if "disable_correlation" not in attr["Attribute"][idx]:
                            attr["Attribute"][idx]["disable_correlation"] = d_c
                        if "distribution" not in attr["Attribute"][idx]:
                            attr["Attribute"][idx]["distribution"] = "5"
                        attr["Attribute"][idx]["timestamp"] = timestamp
                    attr["timestamp"] = timestamp
                    misp_event["Object"].append(attr)
                elif "value" in attr and attr.get("type") != "other":
                    if "to_ids" not in attr:
                        attr["to_ids"] = True
                    if "disable_correlation" not in attr:
                        attr["disable_correlation"] = False
                    if "distribution" not in attr:
                        attr["distribution"] = "5"
                    attr["timestamp"] = timestamp
                    misp_event["Attribute"].append(attr)
                el.clear()
            elif el.tag == "{http://cybox.mitre.org/cybox-2}Properties":
                _type = el.attrib.get(
                    "{http://www.w3.org/2001/XMLSchema-instance}type")
                if _type == "URIObj:URIObjectType":
                    attr["type"] = "url"
                elif _type == "HostnameObj:HostnameObjectType":
                    attr["type"] = "hostname"
                elif _type == "DomainNameObj:DomainNameObjectType":
                    attr["type"] = "domain"
                elif _type == "AddressObj:AddressObjectType":
                    attr = processAddressObj(el, attr, as_object)
                elif _type == "FileObj:FileObjectType":
                    attr = processFileObj(el, attr, as_object)
                elif _type == "EmailMessageObj:EmailMessageObjectType":
                    attr = processEmailObj(el, attr, as_object)
                elif _type =="NetworkConnectionObj:NetworkConnectionObjectType":
                    attr = processNetworkConnectionObj(el, attr, as_object)
            elif el.tag == "{http://stix.mitre.org/common-1}Value":
                attr["to_ids"] = el.text == "High"
            elif el.tag.endswith("}Value"):
                attr["value"] = el.text
            elif el.tag == "{http://cybox.mitre.org/cybox-2}Object":
                if "id" in el.attrib:
                    attr["uuid"] = el.attrib.get("id")[-36:]
            elif el.tag == "{http://cybox.mitre.org/cybox-2}Related_Objects":
                attr = saved_attr
                as_object = False
            elif el.tag == "{http://cybox.mitre.org/cybox-2}Title":
                attr["comment"] = el.text
            elif el.tag == "{http://stix.mitre.org/Incident-1}Title":
                misp_event["info"] = el.text
            elif el.tag == "{http://stix.mitre.org/stix-1}Title":
                if not misp_event["info"]:
                    misp_event["info"] = el.text
            elif el.tag == "{http://stix.mitre.org/stix-1}Package":
                misp_event["timestamp"] = dt.fromisoformat(isotime).timestamp()
                if not misp_event["info"]:
                    misp_event["info"] = "STIX Indicators"
                return_stix_pakage = False
                yield json.dumps(misp_event, indent=4, sort_keys=True)
            elif el.tag == "{http://stix.mitre.org/stix-1}STIX_Package":
                misp_event["timestamp"] = dt.fromisoformat(isotime).timestamp()
                if return_stix_pakage:
                    if not misp_event["info"]:
                        misp_event["info"] = "STIX Indicators"
                    yield json.dumps(misp_event, indent=4, sort_keys=True)
        elif event == "start-ns":
            etree.register_namespace(*el)
