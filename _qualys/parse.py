"""
Parses the given reports and produces a distict list of vulnerable/ fixed hosts
"""
import json

from datetime import datetime, timedelta
from cvss import CVSS3

class Parse():

    def __init__(self, config, sqllite, cvss2):
        """
        Parse
        :param config:
        """
        self.sql = sqllite.SqlLite(config.sqlite3_file, config)
        self.cvss = cvss2
        self.config = config


    def get_mappings(self, ip, vuln, qkb):
        """
        Merge all required elements that make this vulnerability
        :param ip:
        :param vuln:
        :param qkb:
        :return:
        """
        new_vuln = dict()
        new_vuln['ip']          = ip
        new_vuln['qid']         = vuln['QID']
        new_vuln['port']        = vuln['PORT'] if 'PORT' in vuln else 0
        new_vuln['status']      = vuln['STATUS']
        new_vuln['times_found'] = vuln['TIMES_FOUND']
        new_vuln['first_found'] = vuln['FIRST_FOUND_DATETIME']
        new_vuln['last_found']  = vuln['LAST_FOUND_DATETIME']
        new_vuln['results']     = vuln['RESULTS'] if 'RESULTS' in vuln else ''

        new_vuln['diagnosis']   = qkb['DIAGNOSIS']
        new_vuln['consequence'] = qkb['CONSEQUENCE'] if 'CONSEQUENCE' in qkb else ''
        new_vuln['solution']    = qkb['SOLUTION']
        new_vuln['vuln_type']   = qkb['VULN_TYPE']

        new_vuln['impact']      = self.get_impact(qkb)
        new_vuln['title']       = self.get_title(qkb)
        new_vuln['discovery']   = self.get_discovery(qkb)
        new_vuln['base']        = self.get_cvss_base(qkb)
        new_vuln['temporal']    = self.get_cvss_temporal(qkb)
        new_vuln['cvss_vector'] = self.get_cvss_vector(qkb)
        new_vuln['cve_id']      = self.get_cve_id(qkb)
        new_vuln['patchable']   = self.get_patchable(qkb)
        new_vuln['vendor_ref']  = self.get_vendor_ref(qkb)
        new_vuln['kernel']      = self.get_running_kernel(qkb)

        if new_vuln['cvss_vector'].startswith('CVSS:2.0'):
            if new_vuln['cve_id']:
                new_vuln['cvss_vector'] = self.sql.query(self.config.query_nvd_cve, new_vuln['cve_id'])
            else:
                new_vuln['cvss_vector'] = self.cvss.convert_cvss2(new_vuln['cvss_vector'])
            new_vuln['transformed'] = 1

        new_vuln['cvss3_scores'] = self.get_scores(new_vuln['cvss_vector'])
        new_vuln['env_score']    = self.get_environmental_score(new_vuln['cvss3_scores'])
        new_vuln['vuln_score']   = self.get_vulnerabiility_priority(new_vuln['env_score'])
        new_vuln['breach_date']  = self.get_breach_date(float(new_vuln['env_score']), new_vuln['first_found'])

        return new_vuln


    def get_qkb(self, id):
        """
        Extracts the qkb entry from mysql
        This is a tuple and needs extracting accordingly
        :param id:
        :return:
        """
        qkb = tuple(self.sql.query(self.sql.sql_queries['qualys_kb'], id))
        return json.loads(qkb[0].decode('utf-8'))


    def extract_host_info(self, host_list):
        """
        1:M / H/N(V)
        Each host can have one or more vulnerabilities
        Map each as seprate using the following keys
        IP:QID:Port giving a unique identity
        :param host_list:
        :return:
        """
        container = dict()
        for host in host_list:
            if 'IP' in host:
                for vuln in host['DETECTION_LIST']['DETECTION']:
                    if type(vuln) is dict:
                        qkb = self.get_qkb(vuln['QID'])
                        wanted = self.get_mappings(host['IP'], vuln, qkb)

                        if self.config.all_hosts:
                            if wanted['qid'] not in container:
                                container[wanted['qid']] = wanted

                            if 'ip_list' not in container[wanted['qid']]:
                                container[wanted['qid']]['ip_list'] = [ {
                                    "ip": wanted['ip'],
                                    "port": wanted['port'],
                                    "status": wanted['status']
                                } ]
                            else:
                                container[wanted['qid']]['ip_list'].append({
                                        "ip": wanted['ip'],
                                        "port": wanted['port'],
                                        "status": wanted['status']
                                    } )

                        else:
                            item_key = ":".join([str(wanted['ip']), str(wanted['qid']), str(wanted['port'])])
                            container[item_key] = wanted

        return container


    def get_running_kernel(self, qkb):
        """
        Detect if this vuln affects the running kernel
        :param qkb:
        :return:
        """
        if 'AFFECT_RUNNING_KERNEL' in qkb:
            return qkb['AFFECT_RUNNING_KERNEL']

        return 0


    def get_impact(self, qkb):
        """
        Extract the CIA data
        :param qkb:
        :return:
        """
        if 'CVSS_V3' in qkb and 'IMPACT' in qkb['CVSS_V3']:
            return qkb['CVSS_V3']['IMPACT']
        elif 'CVSS' in qkb and 'IMPACT' in qkb['CVSS']:
            return qkb['CVSS']['IMPACT']

        return {}


    def get_vendor_ref(self, qkb):
        """
        Extracts or creates a vendor reference
        :param qkb:
        :return:
        """
        if 'Vendor Reference' in qkb:
            return qkb['Vendor Reference']
        else:
            return ''


    def get_discovery(self, vuln):
        """
        Extracts the discovery method
        :param vuln:
        :return:
        """
        return vuln['DISCOVERY']['REMOTE']


    def get_cvss_base(self, vuln):
        """
        Extract CVSS Base CVSS3 preferred
        :param vuln:
        :return:
        """
        if 'CVSS_V3' in vuln and 'BASE' in vuln['CVSS_V3']:
            return vuln['CVSS_V3']['BASE']
        elif 'CVSS' in vuln and 'BASE' in vuln['CVSS']:
            if '#text' in vuln['CVSS']['BASE']:
                return vuln['CVSS']['BASE']['#text']
            else:
                return vuln['CVSS']['BASE']

        return 0


    def get_cvss_temporal(self, vuln):
        """
        Extract CVSS temporal CVSS3 preferred
        :param vuln:
        :return:
        """
        if 'CVSS_V3' in vuln and 'TEMPORAL' in vuln['CVSS_V3']:
            return vuln['CVSS_V3']['TEMPORAL']
        elif 'CVSS' in vuln and 'TEMPORAL' in vuln['CVSS']:
            return vuln['CVSS']['TEMPORAL']

        return 0


    def get_cvss_vector(self, vuln):
        """
        Extract the CVSS vector CVSS3 preferred
        :param vuln:
        :return:
        """
        if 'CVSS_V3' in vuln and 'VECTOR_STRING' in vuln['CVSS_V3']:
            return vuln['CVSS_V3']['VECTOR_STRING']
        elif 'CVSS' in vuln and 'VECTOR_STRING' in vuln['CVSS']:
            return vuln['CVSS']['VECTOR_STRING']

        return 0


    def get_title(self, vuln):
        """
        Extracts the title of the vulnerability
        :param vuln:
        :return:
        """
        if 'TITLE' in vuln:
            return vuln['TITLE']

        return 0


    def get_patchable(self, vuln):
        """
        Can be fixed by patching
        :param vuln:
        :return: bool
        """
        return vuln['PATCHABLE']


    def get_cve_id(self, vuln):
        """
        Extracts a cve-id. Used with nvd to obtain CVSS3 vector should the vector be CVSS2
        :param vuln:
        :return: cve_id
        """
        if 'CVE_LIST' in vuln:
            if type(vuln['CVE_LIST']['CVE']) is dict:
                return vuln['CVE_LIST']['CVE']['ID']
            else:
                return vuln['CVE_LIST']['CVE'][0]['ID']

        elif 'CORRELATION' in vuln:
            if 'EXPLOITS' in vuln['CORRELATION']:
                if type(vuln['CORRELATION']['EXPLOITS']['EXPLT_SRC']['EXPLT_LIST']['EXPLT']) is dict:
                    return vuln['CORRELATION']['EXPLOITS']['EXPLT_SRC']['EXPLT_LIST']['EXPLT']['REF']
                else:
                    return vuln['CORRELATION']['EXPLOITS']['EXPLT_SRC']['EXPLT_LIST']['EXPLT'][0]['REF']

        return 0


    def get_breach_date(self, score, date):
        """
        Date of breach
        @param score:
        @param date:
        @return:
        """
        if score < 4:
            days = 365
        elif 4 <= score < 7:
            days = 90
        elif score >= 7:
            days = 30

        date = datetime.strptime(date, '%Y-%m-%dT%H:%M:%SZ')
        date = date + timedelta(days=days)

        return date.strftime('%Y-%m-%d')


    def get_environmental_score(self, scores):
        """
        Environmental is the preferred score
        @param scores:
        @return:
        """
        score = 0
        if 'environmental' in scores:
            score = float(scores['environmental'])
        elif 'temporal' in scores:
            score = float(scores['temporal'])
        elif 'base' in scores:
            score = float(scores['base'])

        return score


    def get_vulnerabiility_priority(self, score):
        """
        Score the vulnerability based upon its score
        :param score: see get_environmental_score
        :return rate:
        """
        rate = 'Critical'

        if score < 4:
            rate = 'low'
        elif 4 <= score < 7:
            rate = 'medium'
        elif 7 <= score < 9:
            rate = 'High'

        return rate


    def get_scores(self, vector):
        """
        Use vector to obtain CVSS scoring
        @param vector:
        @return:
        """
        if vector is not None:
            if vector.startswith(self.config.cvss3_pattern):
                c = CVSS3(vector)
            else:
                c = CVSS3('/'.join([self.config.cvss3_tag, vector]))

            return {
                "base": str(c.base_score),
                "temporal": str(c.temporal_score),
                "environmental": str(c.environmental_score),
                "severeties": str(c.severities())
            }

        return { "base": 0, "temporal": 0, "environmental": 0, "severeties": 0 }