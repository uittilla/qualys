
vuln_test_dict = {'CATEGORY': 'Backdoors and trojan horses',
                  'COMPLIANCE_LIST': {'COMPLIANCE': [{'DESCRIPTION': 'Insuring that Malware is '
                                                                     'not present on hosts '
                                                                     'addresses section(s) '
                                                                     '164.306 and 164.312 '
                                                                     'requirements for securing '
                                                                     'critical system files and '
                                                                     'services and insuring '
                                                                     'system integrity.',
                                                      'SECTION': '164.306 and 164.312',
                                                      'TYPE': 'HIPAA'},
                                                     {'DESCRIPTION': 'Malicious Software '
                                                                     'Prevention, Detection and '
                                                                     'Correction\n'
                                                                     'Ensure that preventive, '
                                                                     'detective and corrective '
                                                                     'measures are in place '
                                                                     '(especially up-to-date '
                                                                     'security patches and '
                                                                     'virus control) across the '
                                                                     'organization to protect '
                                                                     'information systems and '
                                                                     'technology from Malware '
                                                                     '(viruses, worms, spyware, '
                                                                     'spam, internally '
                                                                     'developed fraudulent '
                                                                     'software, etc.).',
                                                      'SECTION': 'DS5.9',
                                                      'TYPE': 'CobIT'}]},
                  'CONSEQUENCE': 'If a backdoor is present on your system, then unauthorized '
                                 'users can log in to your system undetected, execute '
                                 'unauthorized commands, and leave the host vulnerable to other '
                                 'unauthorized users. Malicious users may also use your host to '
                                 'access other hosts to perform a coordinated Denial of Service '
                                 'attack.  \n'
                                 '<P>\n'
                                 'Some well-known backdoors are &quot;BackOrifice&quot;, '
                                 '&quot;Netbus&quot; and &quot;Netspy&quot;.  You should be '
                                 'able to find more information on these backdoors on the <A '
                                 'HREF="http://www.cert.org" TARGET="_blank">CERT Coordination '
                                 "Center's Web site (www.cert.org)</A>.",
                  'CVSS': {'ACCESS': {'COMPLEXITY': '1', 'VECTOR': '3'},
                           'AUTHENTICATION': '1',
                           'BASE': {'#text': '7.5', '@source': 'service'},
                           'EXPLOITABILITY': '3',
                           'IMPACT': {'AVAILABILITY': '2',
                                      'CONFIDENTIALITY': '2',
                                      'INTEGRITY': '2'},
                           'REMEDIATION_LEVEL': '3',
                           'REPORT_CONFIDENCE': '3',
                           'TEMPORAL': '6.8',
                           'VECTOR_STRING': 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/RL:W/RC:C'},
                  'CVSS_V3': {'ATTACK': {'COMPLEXITY': '1', 'VECTOR': '1'},
                              'BASE': '8.3',
                              'EXPLOIT_CODE_MATURITY': '3',
                              'IMPACT': {'AVAILABILITY': '2',
                                         'CONFIDENTIALITY': '2',
                                         'INTEGRITY': '2'},
                              'PRIVILEGES_REQUIRED': '1',
                              'REMEDIATION_LEVEL': '3',
                              'REPORT_CONFIDENCE': '3',
                              'SCOPE': '2',
                              'TEMPORAL': '7.9',
                              'USER_INTERACTION': '1',
                              'VECTOR_STRING': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L/E:F/RL:W/RC:C'},
                  'DIAGNOSIS': 'There are known backdoors that use specific port numbers. At '
                               'least one of these ports was found open on this host.  This may '
                               "indicate the presence of a backdoor; however, it's also "
                               'possible that this port is being used by a legitimate service, '
                               'such as a Unix or Windows RPC.',
                  'DISCOVERY': {'REMOTE': '1'},
                  'LAST_SERVICE_MODIFICATION_DATETIME': '2020-07-13T23:06:41Z',
                  'PATCHABLE': '0',
                  'PCI_FLAG': '1',
                  'PUBLISHED_DATETIME': '1999-01-01T08:00:00Z',
                  'QID': '1000',
                  'SEVERITY_LEVEL': '4',
                  'SOFTWARE_LIST': {'SOFTWARE': {'PRODUCT': 'none', 'VENDOR': 'none'}},
                  'SOLUTION': 'Call a security specialist and test this host for backdoors.  If '
                              'a backdoor is found, then the host may need to be re-installed.',
                  'THREAT_INTELLIGENCE': {'THREAT_INTEL': [{'#text': 'Easy_Exploit', '@id': '5'},
                                                           {'#text': 'No_Patch', '@id': '8'},
                                                           {'#text': 'Wormable', '@id': '11'},
                                                           {'#text': 'Privilege_Escalation',
                                                            '@id': '13'},
                                                           {'#text': 'Unauthenticated_Exploitation',
                                                            '@id': '14'}]},
                  'TITLE': 'Potential UDP Backdoor',
                  'VULN_TYPE': 'Potential Vulnerability'
                  }


def test_qualys_kb(mock_Qualys_KB):
    assert mock_Qualys_KB().get_qkb_entry()['1000'] == vuln_test_dict

def test_qualys_hosts(mock_Qualys_Hosts):
    detections = mock_Qualys_Hosts().get_host_entries()
    hosts = list(detections["HOST_LIST_VM_DETECTION_OUTPUT"]['RESPONSE']['HOST_LIST']['HOST'])
    assert hosts is type(list())
