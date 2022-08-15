"""
Fetch and parse
"""
from _qualys import fetch
from _qualys import parse

def Qualys(config):
    if config.verbose:
        print("*** Fetching required sources and parsing")
    fetcher = fetch.Fetch(config)
    parser  = parse.Parse(config)
    fetcher.get_host_detection_report()

    if config.verbose:
        print("*** Combining data and extracting vulnerabilities")
    detections = fetcher.host_detection_report_to_dict()
    hosts      = list(detections["HOST_LIST_VM_DETECTION_OUTPUT"]['RESPONSE']['HOST_LIST']['HOST'])
    container  = parser.extract_host_info(hosts)

    if config.verbose:
        print("*** Its ready")
    for vuln_id in container:
        print(vuln_id, container[vuln_id])