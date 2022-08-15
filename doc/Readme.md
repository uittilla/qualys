#### Author: Ibbo
# Qualys

## Intro
This application is designed to amalgamate various information sources 
into a suitable format giving the user a distinct list of environmental 
vulnerabilities

These entries can then be tracked via a suitable medium mysql/apache, 
jira/Insights using the status field as the indicator

Please read: https://blog.qualys.com/product-tech/2021/03/02/qualys-api-best-practices-knowledgebase-api


## Technical
Developed and tested with python3.8+

#### Program entry
```
pip -r requirements.txt
python qualys.py --help
usage: qualys.py [-h] [-p] [-f] [-v]

Qualys Vulnerability Tracking

optional arguments:
  -h, --help     show this help message and exit
  -p, --publish  Fetch qualys data and prepare it for consumption
  -f, --fullrun  Enact a full qualys kb run
  -v, --verbose  Increase output verbosity
```

If running for the 1st time you should use -f as this will obtain the full QKB

By default fetching the QKB happens daily for any updates in the past week. 
It has been noticed that does not capture all the updates so it is prudent 
to do a full run at least weekly to keep things uptodate

### The moving parts
* QKB: https://qualysapi.qualys.eu/api/2.0/fo/knowledge_base/vuln/
* VMD: https://qualysapi.qualys.eu/api/2.0/fo/asset/host/vm/detection
* NVD: https://nvd.nist.gov/feeds/json/cve/1.1/

First Cve data is pulled and stored into sqlite, Next comes the QKB also stored into sqlite
Last comes the vm detection list and this is parsed and combined with both the QKB and CVE information

### Qualys Knowldge Base Sample Entry (json)

```{
	'QID': '11955',
	'VULN_TYPE': 'Potential Vulnerability',
	'SEVERITY_LEVEL': '3',
	'TITLE': 'Version Control System Files Exposed by the Web Server',
	'CATEGORY': 'CGI',
	'LAST_SERVICE_MODIFICATION_DATETIME': '2018-05-25T03:30:36Z',
	'PUBLISHED_DATETIME': '2018-04-25T22:48:55Z',
	'PATCHABLE': '0',
	'SOFTWARE_LIST': {
		'SOFTWARE': {
			'PRODUCT': 'None',
			'VENDOR': 'multi-vendor'
		}
	},
	'DIAGNOSIS': 'Git, Bazaar, Mercurial and Subversion are distributed version control systems.<P>\nThe web server on the remote host allows read access to a version control system or a git repository. This vulnerability can be leveraged to download contents from the server that should otherwise be private.<P>\nQID Detection Logic:<BR>\nThis unauthenticated QID tries to find the existence of /.git, /.git/config, /.svn, /.svn/entries, /.hg and /.bzr files on a webserver.',
	'CONSEQUENCE': 'Successful exploitation allows a remote, unauthenticated attacker to gain access to sensitive information on the targeted system.',
	'SOLUTION': 'Customers are advised to restrict access to the sub versioning directory.',
	'CORRELATION': {
		'EXPLOITS': {
			'EXPLT_SRC': {
				'SRC_NAME': 'Qualys',
				'EXPLT_LIST': {
					'EXPLT': {
						'REF': 'CVE-2018-00000',
						'DESC': 'Google Dork',
						'LINK': 'https://www.exploit-db.com/ghdb/4601/'
					}
				}
			}
		}
	},
	'CVSS': {
		'BASE': {
			'@source': 'service',
			'#text': '5.0'
		},
		'TEMPORAL': '4.8',
		'VECTOR_STRING': 'CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N/E:F/RL:U/RC:C',
		'ACCESS': {
			'VECTOR': '3',
			'COMPLEXITY': '1'
		},
		'IMPACT': {
			'CONFIDENTIALITY': '2',
			'INTEGRITY': '1',
			'AVAILABILITY': '1'
		},
		'AUTHENTICATION': '1',
		'EXPLOITABILITY': '3',
		'REMEDIATION_LEVEL': '4',
		'REPORT_CONFIDENCE': '3'
	},
	'CVSS_V3': {
		'BASE': '5.3',
		'TEMPORAL': '5.2',
		'VECTOR_STRING': 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N/E:F/RL:U/RC:C',
		'ATTACK': {
			'VECTOR': '1',
			'COMPLEXITY': '1'
		},
		'IMPACT': {
			'CONFIDENTIALITY': '2',
			'INTEGRITY': '1',
			'AVAILABILITY': '1'
		},
		'PRIVILEGES_REQUIRED': '1',
		'USER_INTERACTION': '1',
		'SCOPE': '1',
		'EXPLOIT_CODE_MATURITY': '3',
		'REMEDIATION_LEVEL': '4',
		'REPORT_CONFIDENCE': '3'
	},
	'PCI_FLAG': '1',
	'THREAT_INTELLIGENCE': {
		'THREAT_INTEL': [{
			'@id': '1',
			'#text': 'Zero_Day'
		}, {
			'@id': '3',
			'#text': 'Active_Attacks'
		}, {
			'@id': '5',
			'#text': 'Easy_Exploit'
		}, {
			'@id': '8',
			'#text': 'No_Patch'
		}]
	},
	'DISCOVERY': {
		'REMOTE': '1',
		'ADDITIONAL_INFO': 'Exploit Available'
	}
}
```

### Host detection sample entry
```
<HOST>
    <ID>100008049</ID>
    <IP>194.145.126.135</IP>
    <TRACKING_METHOD>IP</TRACKING_METHOD>
    <NETWORK_ID>0</NETWORK_ID>
    <OS><![CDATA[Networks]]></OS>
    <LAST_SCAN_DATETIME>2022-07-10T05:07:59Z</LAST_SCAN_DATETIME>
    <LAST_VM_SCANNED_DATE>2022-07-10T05:07:10Z</LAST_VM_SCANNED_DATE>
    <LAST_VM_SCANNED_DURATION>3744</LAST_VM_SCANNED_DURATION>
    <DETECTION_LIST>
      <DETECTION>
        <QID>13607</QID>
        <TYPE>Potential</TYPE>
        <SEVERITY>3</SEVERITY>
        <PORT>443</PORT>
        <PROTOCOL>tcp</PROTOCOL>
        <SSL>1</SSL>
        <RESULTS><![CDATA[Host:194.145.126.135:443 is vulnerable to TLS triple handshake]]></RESULTS>
        <STATUS>Active</STATUS>
        <FIRST_FOUND_DATETIME>2019-11-25T03:50:01Z</FIRST_FOUND_DATETIME>
        <LAST_FOUND_DATETIME>2022-07-10T05:07:10Z</LAST_FOUND_DATETIME>
        <TIMES_FOUND>137</TIMES_FOUND>
        <LAST_TEST_DATETIME>2022-07-10T05:07:10Z</LAST_TEST_DATETIME>
        <LAST_UPDATE_DATETIME>2022-07-10T05:07:59Z</LAST_UPDATE_DATETIME>
        <IS_IGNORED>0</IS_IGNORED>
        <IS_DISABLED>0</IS_DISABLED>
        <LAST_PROCESSED_DATETIME>2022-07-10T05:07:59Z</LAST_PROCESSED_DATETIME>
      </DETECTION>
      <DETECTION>
        <QID>38794</QID>
        <TYPE>Confirmed</TYPE>
        <SEVERITY>1</SEVERITY>
        <PORT>443</PORT>
        <PROTOCOL>tcp</PROTOCOL>
        <SSL>1</SSL>
        <RESULTS><![CDATA[TLSv1.1 is supported]]></RESULTS>
        <STATUS>Active</STATUS>
        <FIRST_FOUND_DATETIME>2021-01-24T00:13:25Z</FIRST_FOUND_DATETIME>
        <LAST_FOUND_DATETIME>2022-07-10T05:07:10Z</LAST_FOUND_DATETIME>
        <TIMES_FOUND>79</TIMES_FOUND>
        <LAST_TEST_DATETIME>2022-07-10T05:07:10Z</LAST_TEST_DATETIME>
        <LAST_UPDATE_DATETIME>2022-07-10T05:07:59Z</LAST_UPDATE_DATETIME>
        <IS_IGNORED>0</IS_IGNORED>
        <IS_DISABLED>0</IS_DISABLED>
        <LAST_PROCESSED_DATETIME>2022-07-10T05:07:59Z</LAST_PROCESSED_DATETIME>
      </DETECTION>
    </DETECTION_LIST>
</HOST>
```

### Sample vulnerability
```
'172.16.168.67:105936:0' = {
	'ip': '172.16.168.67',
	'qid': '105936',
	'port': 0,
	'status': 'Active',
	'times_found': '10',
	'results': 'Vulnerable version of OpenSSH Detected:\n\nOpenSSH_7.4p1, OpenSSL 1.0.2k-fips  26 Jan 2017',
	'first_found': '2022-04-26T04:00:51Z',
	'last_found': '2022-06-21T07:27:04Z',
	'diagnosis': "OpenSSH is the premier connectivity tool for remote login with the SSH protocol.  <P>\n\nscp in OpenSSH through 8.6p1 allows command injection in the scp.c toremote function, as demonstrated by backtick characters in the destination argument. <P>\nAffected Versions:<BR>\n8.6p1 and prior versions of OpenSSH <P>\n\n\nQID Detection Logic:<BR>\nThe QID checks for the vulnerable versions of OpenSSH and checks the presence of scp command by executing 'which scp'<P>\nNote : Affected version checked till 8.6p1 as per PoC.",
	'consequence': 'Successful exploitation could disclose sensitive information.<P>',
	'solution': 'No solution available from Linux vendors yet.<P>Workaround:<BR>As per upstream, because of the way scp is based on a historical protocol called rcp which relies on that style of argument passing and therefore encounters expansion problems. Making changes to how the scp command line works breaks the pattern used by scp consumers. Upstream therefore recommends the use of rsync in the place of scp for better security. More details about supported alternatives available at <A HREF="https://access.redhat.com/articles/5284081" TARGET="_blank">Red Hat guide</A>.',
	'vuln_type': 'Vulnerability',
	'impact': {
		'CONFIDENTIALITY': '3',
		'INTEGRITY': '3',
		'AVAILABILITY': '3'
	},
	'title': 'OpenSSH Command Injection Vulnerability (Generic)',
	'discovery': '0',
	'base': '7.8',
	'temporal': '7.6',
	'cvss_vector': 'CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H/E:F/RL:U/RC:C',
	'cve_id': 'CVE-2020-15778',
	'cvss_scores': {
		'base': '7.8',
		'temporal': '7.6',
		'environmental': '7.6',
		'severeties': "('High', 'High', 'High')"
	},
	'env_score': 7.6,
	'vuln_score': 'High',
	'breach_date': '2022-05-26',
	'patchable': '0',
	'vendor_ref': ''
}

```