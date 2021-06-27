#!/usr/bin/python
'''
Version 20160627a

Copyright 2015 Apex Technology Consulting Ltd.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''
import re
import logging
import time
from optparse import OptionParser

#from argparse import ArgumentParser

parent_cmd = re.compile(r'^[a-z]')

def timestamp():
    current_time = time.gmtime()
    return '%s%s%s%s%s' % (current_time.tm_year, current_time.tm_mon, current_time.tm_mday, current_time.tm_hour, current_time.tm_min)

def output_ssl_lab():
    command = 'cp /config/ssl/ssl.crt/default.crt /root/\ncp /config/ssl/ssl.key/default.key /root/\ntmsh -c "'
    keys = [item.key for item in SSLProxy.all_objs.values()]
    certs = [item.cert for item in SSLProxy.all_objs.values()]
    chains = [item.chaingroup for item in SSLProxy.all_objs.values()]
    for key in set(keys):
        if key:
            command += 'install /sys crypto key %s from-local-file /root/default.key;\n' % (key[:-4])
    for cert in set(certs):
        if cert:
            command += 'install /sys crypto cert %s from-local-file /root/default.crt;\n' % (cert[:-4])
    for chain in set(chains):
        if chain and not chain.startswith('#'): 
            command += 'install /sys crypto cert %s from-local-file /root/default.crt;\n' % (chain[:-4])
    command = command[:-2] + '"'
    return command



def find_policy_map_class(class_map):
    try:
        return PolicyMapClass.all_objs[class_map]
    except:
        error = '#ERROR: No Policy Map Class found for \n\t{}'.format(class_map)
        ace2f5.error_blocks.append(error)
        print(error)
        return

def find_policy_lb(policy_map_class):
    try:
        return  PolicyLB.all_objs[policy_map_class.lb_policy]
    except:
        error = '#ERROR: No Policy LB found in Policy Map Class \n{}'.format(policy_map_class)
        ace2f5.error_blocks.append(error)
        print(error)
        return

def find_sticky_serverfarm(sticky_serverfarm):
    try:
        return Sticky.all_objs[sticky_serverfarm]
    except:
        error = '#ERROR: No Sticky Serverfarm found for \n{}'.format(sticky_serverfarm)
        ace2f5.error_blocks.append(error)
        print(error)
        return

def find_serverfarm(serverfarm):
    try:
        return ServerfarmHost.all_objs[serverfarm]
    except:
        try:
            return ServerfarmRedirect.all_objs[serverfarm]
        except:
            error = '#ERROR: No Serverfarm found for \n{}'.format(serverfarm)
            ace2f5.error_blocks.append(error)
            print(error)
            return

def find_ssl_proxy(ssl_proxy):
    try:
        return SSLProxy.all_objs[ssl_proxy]
    except:
        error = '#ERROR: No SSL Proxy found for \n{}'.format(ssl_proxy)
        ace2f5.error_blocks.append(error)
        print(error)
        return

def find_probe(probe):
    try:
        return Probe.all_objs[probe]
    except:
        error = '#ERROR: No Probe found for \n{}'.format(probe)
        ace2f5.error_blocks.append(error)
        print(error)

def find_parameter_map(parameter_map):
    try:
        return ParameterMapCon.all_objs[parameter_map]
    except:
        try:
            return ParameterMapSSL.all_objs[parameter_map]
        except:
            error = '#ERROR: No Parameter Map found for \n{}'.format(parameter_map)
            ace2f5.error_blocks.append(error)
            print(error)

def find_rserver(rserver):
    try:
        return RserverHost.all_objs[rserver[0]]
    except:
        try:
            return RserverRedirect.all_objs[rserver[0]]
        except:
            error = '#ERROR: No RServer found for \n{}'.format(rserver)
            ace2f5.error_blocks.append(error)
            print(error)

def list_dedup(data_list):
    counter = len(data_list) - 1
    dup_list = []
    data = []
    while counter > 0:
        data_item = data_list[counter]
        i_count = 0
        for i in data_list[:counter - 1]:
            if data_item == i:
                dup_list.append(i_count)
            i_count = i_count + 1
        counter = counter - 1
    for i in dup_list:
        data_list.remove(data_list[i])
    return data_list

def dedupe(items):
    seen = set()
    for item in items:
        if item not in seen:
            yield item
            seen.add(item)

def print_ace_conf_to_file(ace_dict, f):
    for key, value in ace_dict.items():
        print('\n######## ACE ########', file=f)
        print(value.config, file=f)
        print('######## F5 ########', file=f)
        print(value.f5conf, file=f)
        if value.error:
            print(value.get_error(), file=f)

def print_f5_conf_to_file(ace_dict, f):
    for key, value in ace_dict.items():
        print(value.f5conf, file=f)

def get_block_name(str):
    *_, name = str.splitlines()[0].split()
    return name


def get_description(str):
    _, *description = str.strip().split()
    return 'description \"' + ' '.join(description) + '\"'


def build_name_dict(list):
    name_dict = {}
    for item in list:
        name_dict[get_block_name(item)] = item
    return name_dict


def comp_dict(dict1={}, dict2={}):
    for key in dict1:
        if key in dict2.keys():
            print('--/o/--\n' + dict1[key] + '\n' + dict2[key])


def status_code_to_re(status_list=[]):
    '''
    DOCUMENT this
    '''
    if len(status_list) == 1 and '-' not in status_list[0]:
        return status_list[0]
    temp_list = []
    for status in status_list:
        if '-' in status:
            temp_code = ''
            # status code is a range, split
            codes = status.split('-')
            for count in range(3):
                if codes[0][count] != codes[1][count]:
                    temp_code += '[%s-%s]' % (codes[0][count], codes[1][count])
                else:
                    temp_code += codes[0][count]
            temp_list.append(temp_code)
        else:
            temp_list.append(status)
    return '(%s)' % ('|'.join(temp_list))


def policymapclass_vlan(policy_map_class):
    vlans = []
    for interface in InterfaceVlan.all_objs.values():
        for service_policy in interface.service_policy:
            if policy_map_class.policy_map_parent.name == service_policy:
                vlans.append(interface.vlan)
    return vlans


def get_net_mask(str):
    if str == "255.255.255.255":
        return "32"
    if str == "255.255.255.254":
        return "31"
    if str == "255.255.255.252":
        return "30"
    if str == "255.255.255.248":
        return "29"
    if str == "255.255.255.240":
        return "28"
    if str == "255.255.255.224":
        return "27"
    if str == "255.255.255.192":
        return "26"
    if str == "255.255.255.128":
        return "25"
    if str == "255.255.255.0":
        return "24"
    if str == "255.255.254.0":
        return "23"
    if str == "255.255.252.0":
        return "22"
    if str == "255.255.248.0":
        return "21"
    if str == "255.255.240.0":
        return "20"
    if str == "255.255.224.0":
        return "19"
    if str == "255.255.192.0":
        return "18"
    if str == "255.255.128.0":
        return "17"
    if str == "255.255.0.0":
        return "16"
    if str == "255.254.0.0":
        return "15"
    if str == "255.252.0.0":
        return "14"
    if str == "255.248.0.0":
        return "13"
    if str == "255.240.0.0":
        return "12"
    if str == "255.224.0.0":
        return "11"
    if str == "255.192.0.0":
        return "10"
    if str == "255.128.0.0":
        return "9"
    if str == "255.0.0.0":
        return "8"
    if str == "0.0.0.0":
        return "0"


class aceconf:
    '''
    Root class to take Cisco ACE configuraiton file and create list of objects for configuration mapping.
        _create_ace_objects funtion passes each configuration block to the correct class based on the starting string.
    '''
    find_blocks = lambda self, str: [block for block in self.conf_blocks if block.startswith(str)]
    def _create_ace_objects(self, block):
        '''
        Takes a single block of Cisco ACE config and passes to correct class, each class is designed to have a .all_objs var
        which stores all the classes objects.
        i.e. object namespace is not required simply pass Cisco ACE config block to the class and the class will add to its
             own .all_objs list 
        '''
        if block.startswith('crypto chaingroup'):
            CryptoChaingroup(block)
        elif block.startswith('access-list'):
            ACL(block)
        elif block.startswith('interface vlan'):
            InterfaceVlan(block)
        elif block.startswith('probe dns'):
            ProbeDNS(block)
        elif block.startswith('probe tcp'):
            ProbeTCP(block)
        elif block.startswith('probe http'):
            ProbeHTTP(block)
        elif block.startswith('probe icmp'):
            ProbeICMP(block)
        elif block.startswith('probe smtp'):
            ProbeSMTP(block)
        elif block.startswith('parameter-map type ssl'):
            ParameterMapSSL(block)
        elif block.startswith('parameter-map type connection'):
            ParameterMapCon(block)
        elif block.startswith('action-list'):
            ActionList(block)
        elif block.startswith('rserver host'):
            RserverHost(block)
        elif block.startswith('rserver redirect'):
            RserverRedirect(block)
        elif block.startswith('ssl-proxy'):
            SSLProxy(block)
        elif block.startswith('serverfarm host'):
            ServerfarmHost(block)
        elif block.startswith('serverfarm redirect'):
            ServerfarmRedirect(block)
        elif block.startswith('sticky ip'):
            StickyIP(block)
        elif block.startswith('sticky http-cookie'):
            StickyHTTP(block)
        elif block.startswith('sticky http-header'):
            StickyHTTPHeader(block)
        elif block.startswith('sticky radius'):
            StickyRADIUS(block)
        elif block.startswith('class-map match-any'):
            ClassMap(block)
        elif block.startswith('class-map match-all'):
            ClassMap(block)
        elif block.startswith('class-map tppe http'):
            ClassMap(block)
        elif block.startswith('policy-map type loadbalance'):
            PolicyLB(block)
        elif block.startswith('policy-map multi-match'):
            policy_map_multi = PolicyMapMultiMatch(block)
            class_block = ''
            for line in block.splitlines():
                    if line.startswith('  class'):
                        if class_block != '':
                            PolicyMapClass(class_block, policy_map_multi)
                        class_block = line + '\n'
                    elif line.startswith('    '):
                        class_block = class_block + line + '\n'
            if class_block != '':
                PolicyMapClass(class_block, policy_map_multi)
        elif block.startswith('ip route'):
            ipRoute(block)
        # If any blockes are not found they are added to the 'ace2f5.error_blocks' list
        else:
            self.error_blocks.append(block)

    def __init__(self, file):
        '''
        Take Cisco ACE configuration file and splits into list of configuration blocks.
        Pops each block for config block list and passes to self._create_ace_objects() for creation of ACE-to-F5 Objects
        '''
        self.conf_blocks = []
        self.error_blocks = []
        # Clears block var ready for configuration split
        block = ''
        file = open(file, 'rt')
        # Take each line from file and split into blocks bases on the spacing at the start of each line.
        for line in file:
            # Regex match for line starting with [a-z], i.e. not a 'space', 'tab' or '#'
            if parent_cmd.match(line):
                # As new root configuration block found adds 'block' to list of blocks, clears the 'block' var and add first line
                if block != '':
                    self.conf_blocks.append(block)
                block = line
            # If line doesn't start with [a-z] line is part of block so adds the line to the 'block' var
            elif line.startswith('  '):
                block = block + line
        # Adds final block to list of blocks
        self.conf_blocks.append(block)
        # pops each config block, in reverse order, from list of blocks and sends to self._create_ace_objects(block) for Object creatation
        while self.conf_blocks:
            self._create_ace_objects(self.conf_blocks.pop(0))
        file.close()
        # Add ERROR message for checking file output
        self.error_blocks.append('\n### Conversion ERRORS ###\n')
    
    def __str__(self):
        return ' '.join(self.conf_blocks)


class ConfigBlock():
    '''
    name - str
    description - str
    '''
    mapped_lines = ['description']
    
    def __init__(self, config):
        self.config = config
        self.error = ''
        self.ace_type = self.config.split()[0]
        *_, self.name = config.splitlines()[0].split()
        try:
            _, *self.description = [line for line in config.splitlines(
            ) if line.strip().startswith('description')][0].split()
            self.description = 'description "%s"' % (
                ' '.join(self.description))
        except:
            self.description = ''
        self.f5conf = '#TODO: ACE Object %s not mapped\n' % (self.name)

    def add_error(self, error):
        if not self.error:
            self.error = '###### ERRORS #######'
        for line in error.splitlines():
            self.error += '\n#  %s' % (error)

    def get_error(self):
        return self.error

    def log_unmapped_lines(self):
        lines_not_mapped = ''
        for line in self.config.splitlines()[1:]:
            if line.strip().split()[0] not in self.mapped_lines and \
                ' '.join(line.strip().split()[0:1]) not in self.mapped_lines:
                lines_not_mapped += '\n\t%s' % (line)
        if lines_not_mapped:
            log_msg = 'Line not mapped for type: %s, name: %s:%s' % (self.ace_type, self.name, lines_not_mapped)
            logging.debug(log_msg)

    def __str__(self):
        return self.config

class PolicyMapMultiMatch(ConfigBlock):
    all_objs = {}

    def __init__(self, config):
        super().__init__(config)
        self.raw_config = config
        self.vlans = []
        self._find_vlan()
        self._set_config()
        PolicyMapMultiMatch.all_objs[self.name] = self
    def _find_vlan(self):
        for interface in InterfaceVlan.all_objs.values():
            for service_policy in interface.service_policy:
                if self.name == service_policy:
                    self.vlans.append(interface.vlan)
        return self.vlans
    def _set_config(self):
        self.config = self.config.splitlines()[0]
        if self.vlans:
            for vlan in self.vlans:
                self.config += '\n{}'.format(vlan)

class ClassMap(ConfigBlock):
    '''
    config - str
    name - str
    description - str
    type - str
    vips - list of dict (ip, protocol, port)
    urls - list
    source_ip - list
    '''
    all_objs={}
    mapped_lines = ConfigBlock.mapped_lines + [
        'match virtual-address',
        'match http',
        'match source-address']

    def __init__(self, config):
        super().__init__(config)
        #ConfigBlock.__init__(self, config)
        _, *self.type, _ = config.splitlines()[0].split()
        self.type = ' '.join(self.type)

        if self.type.startswith('match'):
            self.vips = []
            for line in config.splitlines():
                if line.find('virtual-address') != -1:
                    _, _, _, vip, *service = line.split()
                    if len(service) == 1 and service[0] == 'any':
                        self.vips.append(
                            {'ip': vip, 'protocol': 'any', 'port': '*'})
                    elif len(service) == 2 and service[1] == 'any':
                        self.vips.append(
                            {'ip': vip, 'protocol': service[0], 'port': '*'})
                    else:
                        if service[-1] == 'www':
                            port = 'http'
                        else:
                            port = service[-1]
                        self.vips.append(
                            {'ip': vip, 'protocol': service[0], 'port': port})
        elif self.type.startswith('type http'):
            self.urls = []
            self.source_ip = []
            for line in config.splitlines():
                if line.find('match http url') != -1:
                    *_, url = line.split()
                    self.urls.append(url)
                elif line.find('match source-address') != -1:
                    *_, ip, subnet = line.split()
                    self.source_ip.append('source %s/%s' % (ip, get_net_mask(subnet)))
        ClassMap.all_objs[self.name] = self
        self.log_unmapped_lines()

    def find_policy_map_class(self):
        self.policy_map_class = find_policy_map_class(self.name)

    def __str__(self):
        return self.config

    def log_unmapped_lines(self):
        lines_not_mapped = ''
        for line in self.config.splitlines()[1:]:
            items = line.strip().split()
            if items[1] == 'match' and ' '.join(items[1:3]) in self.mapped_lines:
                pass
            elif line.strip().split()[0] not in self.mapped_lines and \
            ' '.join(line.strip().split()[0:1]) not in self.mapped_lines:
                lines_not_mapped += '\n\t%s' % (line)
        if lines_not_mapped:
            log_msg = 'Line not mapped for type: %s, name: %s:%s' % (self.ace_type, self.name, lines_not_mapped)
            logging.debug(log_msg)

class PolicyMapClass(ConfigBlock):
    '''
    config - str
    name - str
    description - str
    inservice - bool
    ssl - bool
    ssl_proxy str
    lb_policy - str
    parameter_map - list
    '''
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'loadbalance vip',
        'loadbalance policy',
        'ssl-proxy',
        'appl-parameter',
        'nat dynamic']

    def __init__(self, config, policy_map_parent):
        '''http://www.cisco.com/c/en/us/td/docs/interfaces_modules/services_modules/ace/vA5_1_0/command/reference/ACE_cr/policy.html#wp2348434
        appl-parameter http advanced-options <name>
        connection advanced-options <name>
        inspect {dns [maximum-length bytes]} | {ftp [strict policy name1 | sec-param conn_parammap_name1]} | 
            {http [policy name4 | url-logging]} | 
            {icmp [error]} | 
            ils | 
            {rtsp [sec-param conn_parammap_name3]} | 
            {sip [sec-param conn_parammap_name4] [policy name5]} | 
            {skinny [sec-conn_parammap_name5] [policy name6]}
        loadbalance policy <name>
        loadbalance vip advertise (RHI)
        loadbalance vip icmp-reply (ICMP)
        loadbalance vip inservice (enabled)
        loadbalance vip udp-fast-age
        nat dynamic <nat id> vlan <vlan id>
        nat static
        ssl-proxy {client | server} <ssl_service_name>
        '''
        super().__init__(config)
        self.policy_map_parent = policy_map_parent
        self.inservice = False
        self.ssl = False
        self.snat = False
        self.parameter_map = []
        for line in config.splitlines():
            if line.strip().startswith('loadbalance vip inservice'):
                self.inservice = True
            elif line.strip().startswith('loadbalance policy'):
                *_, self.lb_policy = line.split()
            elif line.strip().startswith('loadbalance vip icmp-reply'):
                pass
            elif line.strip().startswith('ssl-proxy server'):
                self.ssl = True
                *_, self.ssl_proxy = line.split()
            elif line.strip().startswith('appl-parameter') or line.strip().startswith('action '):
                *_, parameter_map = line.split()
                self.parameter_map.append(parameter_map)
            elif line.strip().startswith('nat dynamic'):
                # nat dynamic <nat id> vlan <vlan id>
                # take <nat id> and <vlan id> and lookup 'interface vlan <vlan id>' config block, 'nat-pool <nat id> ...' for NAT configurtion
                #   '<nat ip 1> <nat ip 2> netmask <netmask> [pat]'
                self.snat = True
                *_, self.nat_id, _, self.vlan_id = line.strip().split()
                self.snat_pool = 'snatpool_%s_%s' % (self.vlan_id, self.nat_id)
                 
                pass
        self.config = self.policy_map_parent.config + '\n' + self.config
        PolicyMapClass.all_objs[self.name] = self
    def __str__(self):
        return '{}\n{}'.format(self.policy_map_parent.config.splitlines()[0], self.config)

class PolicyLB(ConfigBlock):
    '''
    config - str
    name - str
    description - str
    serverfarm
    backup_serverfarm
    self.sticky - bool
    sticky_serverfarm - str
    '''
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        self.sticky = False
        for line in config.splitlines():
            if line.strip().startswith('serverfarm'):
                if 'backup' in line:
                    _, self.serverfarm, _, self.backup_serverfarm = line.split()
                else:
                    _, self.serverfarm = line.split()
            elif line.strip().startswith('sticky-serverfarm'):
                self.sticky = True
                _, self.sticky_serverfarm = line.split()
        PolicyLB.all_objs[self.name] = self

    def __str__(self):
        return self.config

class Probe(ConfigBlock):
    '''Default Probe class contains detail values all probes must have
        F5 up-interval = self.interval
            default -> 15
        F5 timeout = (self.interval * self.faildetect) + 1
            default -> (15 * 3) + 1 = 46
        F5 interval = passdetect_interval
            default -> 60
        F5 time-until-up = (self.passdetect_interval * self.passdetect_count)
            default -> (60 * 3) = 180'''
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'probe',
        'port',
        'interval',
        'passdetect',
        'faildetect',
        'receive',
        'ip',
        'open']

    def __init__(self, config):
        ConfigBlock.__init__(self, config)
        self.interval = 15
        self.faildetect = 3
        self.passdetect_interval = 60
        self.passdetect_count = 3
        self.receive = '10'
        self.port = '*'
        self.ip_address = '*'
        for line in config.splitlines():
            if line.strip().startswith('description'):
                self.description = get_description(line)
            elif line.strip().startswith('probe'):
                *_, self.type, self.name = line.split()
            elif line.strip().startswith('port'):
                *_, self.port = line.split()
            elif line.strip().startswith('interval'):
                *_, interval = line.split()
                self.interval = int(interval)
            elif line.strip().startswith('passdetect interval'):
                *_, interval = line.split()
                self.passdetect_interval = int(interval)
            elif line.strip().startswith('passdetect count'):
                *_, count = line.split()
                self.passdetect_count = int(count)
            elif line.strip().startswith('faildetect'):
                *_, faildetect = line.split()
                self.faildetect = int(faildetect)
            elif line.strip().startswith('receive'):
                *_, self.receive = line.split()
            elif line.strip().startswith('ip address'):
                *_, self.ip_address = line.split()
        self._f5conf_defaults()
        Probe.all_objs[self.name] = self
    
    def __str__(self):
        return self.config

    def _f5conf_defaults(self):
        self.f5conf = []
        self.f5conf.append('ltm monitor %s %s {' % (self.type, self.name))
        self.f5conf.append('    %s' % (self.description))
        self.f5conf.append('    defaults-from /Common/%s' % (self.type.lower()))
        self.f5conf.append('    interval %d' % (self.passdetect_interval))
        self.f5conf.append('    up-interval %d' % (self.interval))
        self.f5conf.append('    timeout %d' %
                           ((self.interval * self.faildetect) + 1))
        self.f5conf.append('    time-until-up %d' %
                           (self.passdetect_interval * self.passdetect_count))
        if self.ip_address != '*' or self.port != '*':
            self.f5conf.append('    destination %s:%s' %
                               (self.ip_address, self.port))

    def _tmsh_script_defaults(self):
        pass

class ProbeDNS(Probe):
    mapped_lines = Probe.mapped_lines + [
        'domain',
        'expect']

    def __init__(self, config):
        super().__init__(config)
        for line in config.splitlines():
            if line.strip().startswith('domain'):
                *_, self.domain = line.split()
                self.f5conf.append('    qname %s' % (self.domain))
            elif line.strip().startswith('expect address'):
                *_, self.recv = line.split()
                self.f5conf.append('    recv %s' % (self.recv))
        self.f5conf = self.f5conf + ['}\n#TODO: Check probe to montior manually.']
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()

class ProbeTCP(Probe):
    def __init__(self, config):
        super().__init__(config)
        self.f5conf = self.f5conf + ['}']
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()

    def f5_output(self):
        '''Returns the F5 configuration from the ACE TCP Probe configuration block
        '''
        return self.f5conf

class ProbeSMTP(Probe):
    def __init__(self, config):
        super().__init__(config)
        self.f5conf = self.f5conf + ['}\n#TODO: Check probe to montior manually.']
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()
        
    def f5_output(self):
        '''Returns the F5 configuration from the ACE SMTP Probe configuration block
        '''
        return self.f5conf

class ProbeICMP(Probe):
    def __init__(self, config):
        super().__init__(config)
        self.f5conf = self.f5conf + ['}']
        self.f5conf = '\n'.join(self.f5conf)
        self.f5conf = self.f5conf.replace(' icmp ', ' gateway-icmp ', 1)
        self.f5conf = self.f5conf.replace('defaults-from /Common/icmp', 'defaults-from /Common/gateway_icmp', 1)
        self.log_unmapped_lines()

    def f5_output(self):
        '''Returns the F5 configuration from the ACE ICMP Probe configuration block
        '''
        return self.f5conf

class ProbeHTTP(Probe):
    '''Extracts attributes from Cisco ACE probe http or https configuration block and converts to F5 configuration.
    '''
    mapped_lines = Probe.mapped_lines + [
        'request',
        'expect',
        'credentials']

    def __init__(self, config):
        super().__init__(config)
        #Probe.__init__(self, config)
        self.status_list = []
        for line in config.splitlines():
            if line.strip().startswith('request method'):
                *_, url = line.split()
                if url.startswith('http'):
                    _, _, hostname, *uri = url.split('/')
                    uri = '/' + '/'.join(uri)
                    self.send = 'send "GET %s HTTP/1.1\\r\\nHost: %s\\r\\nConnection: Close\\r\\n\\r\\n"' % (
                        uri, hostname)
                else:
                    self.send = 'send "GET %s HTTP/1.1\\r\\nHost: \\r\\nConnection: Close\\r\\n\\r\\n" #/TODO: Missing Hostname' % (
                        url)
            elif line.strip().startswith('expect status'):
                _, _, recv1, recv2 = line.split()
                if recv1 == recv2:
                    self.status_list.append(recv1)
                else:
                    self.status_list.append('%s-%s' % (recv1, recv2))
                self.recv = 'recv "HTTP/[0-2].[0-9] %s" #TODO: check HTTP response codes' % (status_code_to_re(self.status_list))
            elif line.strip().startswith('expect regex'):
                '''
                    probe http SVGS2_INET_HTTP_VOYAGER_CONTENT_01
                        description Voyager Internet Web Service
                        interval 30
                        passdetect interval 20
                        request method get url http://bank.testing.com/vlbstatus/vlbstatus.aspx
                        connection term forced
                        open 1
                        expect regex "Online"
                '''
                _, _, *recv = line.split()
                recv = ' '.join(recv)
                if hasattr(self, 'recv'):
                    self.recv = self.recv.replace('"', '')
                    self.recv = self.recv.replace(
                        '#TODO: check HTTP response codes', '')
                    recv = recv.replace('"', '')
                    self.recv = '"%s.*%s" #TODO: check' % (self.recv.strip(), recv.strip())
                else:
                    self.recv = 'recv %s #TODO: check' % (recv.strip())
            elif line.strip().startswith('credentials'):
                _, user, password = line.split()
                self.creds = '#TODO: set username and password, %s:%s' % (user, password)
        self._f5conf_local()

    def __str__(self):
        '''Returns Cisco ACE and F5 configuraiton code blocks to allow for easy compare.
        '''
        return '##### ACE #####\n%s##### F5 #####\n%s\n' % (self.config, self.f5conf)

    def _f5conf_local(self):
        if 'send' in dir(self):
            self.f5conf.append('    ' + self.send)
        if 'recv' in dir(self):
            self.f5conf.append('    ' + self.recv)
        if 'creds' in dir(self):
            self.f5conf.append('    ' + self.creds)
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()

    def f5_output(self):
        '''Returns the F5 configuration from the ACE HTTP and HTTPS Probe configuration block
        '''
        return '\n'.join(self.f5conf)


class RserverHost(ConfigBlock):
    '''Takes Cisco ACE 'rserver host' object and splits into attributes for conversion into F5 'node' configuration
    '''
    all_objs={}
    rserver_monitors=[]
    mapped_lines = ConfigBlock.mapped_lines + [
        'rserver',
        'ip',
        'description',
        'probe',
        'fail-on-all',
        'inservice']

    def __init__(self, config):
        '''Takes 'rserver host' configuration string and sets default object attributes.
        The follows shows the lines exepted from the Cisco ACE 'rserver host' object string
        rserver host <name>
        ip address <ip>
        description <description string>
        probe <name>
        probe <name>
        fail-on-all
        con-limit max <int> min <int> #TO BE COMPLETED
        rate-limit connection <int> | bandwidth <int> #TO BE COMPLETED
        weight <int> #TO BE COMPLETED
        inservice
        '''

        super().__init__(config)
        self.probe_list = []
        self.fail_on_all = False
        self.inservice = False
        self.ip_address = '#TODO: ERROR Missing IP Address'
        for line in config.splitlines():
            if line.strip().startswith('rserver'):
                *_, self.name = line.split()
            elif line.strip().startswith('ip address'):
                *_, self.ip_address = line.split()
            elif line.strip().startswith('description'):
                _, *desc = line.split()
                self.description = 'description "%s"' % (' '.join(desc))
            elif line.strip().startswith('probe'):
                *_, probe = line.split()
                self.probe_list.append(probe)
            elif line.strip().startswith('fail-on-all'):
                self.fail_on_all = True
            elif line.strip().startswith('inservice'):
                self.inservice = True
        if self.probe_list:
            for probe in self.probe_list:
                RserverHost.rserver_monitors.append(probe)
        self._f5conf_defaults()
        RserverHost.all_objs[self.name] = self
    def __str__(self):
        '''Returns Cisco ACE and F5 configuraiton code blocks to allow for easy compare.
        '''
        return '##### ACE #####\n%s##### F5 #####\n%s\n' % (self.config, '\n'.join(self.f5conf))

    def _f5conf_defaults(self):
        self.f5conf = []
        self.f5conf.append('ltm node %s {' % (self.name))
        if self.description:
            self.f5conf.append('    ' + self.description)
        self.f5conf.append('    address %s' % (self.ip_address))
        if self.probe_list and not self.fail_on_all:
            self.f5conf.append('    monitor %s' %
                               (' and '.join(self.probe_list)))
        elif self.probe_list and self.fail_on_all:
            self.f5conf.append('    monitor min 1 of { %s }' % (
                ' and '.join(self.probe_list)))
        if self.inservice == False:
            self.f5conf.append('    state user-down')
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()

    def f5_output(self):
        '''Returns the F5 configuration from the ACE 'rserver host' configuration block'''
        return self.f5conf

class SSLProxy(ConfigBlock):
    '''
    config - str
    name - str
    description - str
    key - str
    cert - str
    chaingroup - str
    ssl_advanced - str
    '''
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'key',
        'cert',
        'chaingroup',
        'ssl']

    def __init__(self, config):
        super().__init__(config)
	    #ConfigBlock.__init__(self, config)
        self.ssl_advanced = 'clientssl'
        self.cert = '#TODO: Missing CERT in config'
        self.key = '#TODO: Missing KEY in config'
        self.chaingroup = '#TODO: No Changegroup in config, remove this line'
        for line in config.splitlines():
            if line.strip().startswith('key'):
                self._setkey(line)
            elif line.strip().startswith('cert'):
                self._setcert(line)
            elif line.strip().startswith('chaingroup'):
                self._setchaingroup(line)
            elif line.strip().startswith('ssl advanced-options'):
                *_, self.ssl_advanced = line.split()
        self._f5conf_local()
        SSLProxy.all_objs[self.name] = self

    def _setkey(self, line):
        *_, key = line.split()
        if key.lower().endswith('.pem') or key.lower().endswith('.key'):
            self.key = '%s.key' % (key[:-4])
        elif key.lower().endswith('.key'):
            self.key = key
        else:
            self.key = '%s.key' % (key)

    def _setcert(self, line):
        *_, cert = line.split()
        if cert.lower().endswith('.pem') or cert.lower().endswith('.cer'):
            self.cert = '%s.crt' % (cert[:-4])
        elif cert.lower().endswith('.crt'):
            self.cert = cert
        else:
            self.cert = '%s.crt' % (cert)

    def _setchaingroup(self, line):
        *_, chaingroup = line.split()
        self.chaingroup = '%s.crt' % (chaingroup)

    def __str__(self):
        return self.config

    def _f5conf_local(self):
        self.f5conf = 'ltm profile client-ssl %s {' % (self.name)
        self.f5conf += '\n    defaults-from /Common/%s' % (self.ssl_advanced)
        self.f5conf += '\n    key %s' % (self.key)
        self.f5conf += '\n    cert %s' % (self.cert)
        self.f5conf += '\n    chain %s\n}' % (self.chaingroup)
        self.log_unmapped_lines()

class CryptoChaingroup(ConfigBlock):
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'cert']

    def __init__(self, config):
        super().__init__(config)
        for line in self.config.splitlines():
            if line.strip().startswith('cert'):
                _, self.cert = line.split()
        CryptoChaingroup.all_objs[self.name] = self
        self.log_unmapped_lines()

class ACL(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        _, self.name, line_type, *line_config = config.strip().split()

        if line_type == 'remark':
            self.description = 'description "%s"' % (' '.join(line_config))
        # Translate "any" to "0.0.0.0 0.0.0.0" and "host a.b.c.d" to "a.b.c.d 255.255.255.255"
        elif line_type == 'line':
            self.line_config = re.sub('host (([0-9]{1,3}\.){3}[0-9]{1,3})', '\g<1> 255.255.255.255', ' '.join(line_config)).replace('any', '0.0.0.0 0.0.0.0')
            #print(self.name, self.line_config)
        if self.name in ACL.all_objs.keys():
            ACL.all_objs[self.name].config = ACL.all_objs[self.name].config + config
        else:
            ACL.all_objs[self.name] = self


class ParameterMapSSL(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        ParameterMapSSL.all_objs[self.name] = self
        self.log_unmapped_lines()

class ParameterMapCon(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        ParameterMapCon.all_objs[self.name] = self
        self.log_unmapped_lines()

class ActionList(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        ActionList.all_objs[self.name] = self
        self.log_unmapped_lines()

class ServerfarmHost(ConfigBlock):
    '''
    serverfarm host T1-PROD-TEST-international-444
      description test.appint.com website port 443 - 444
      probe PROBE-UK-T1-PRD-ECOMM-HTTP
      rserver lllweb01-v3 444
        inservice
      rserver lllweb02-v3 444
        inservice
    '''
    all_objs = {}
    serverfarm_any_monitors = []
    mapped_lines = ConfigBlock.mapped_lines + [
        'probe',
        'rserver',
        'ip',
        'fail-on-all',
        'inservice']

    def __init__(self, config):
        super().__init__(config)
        self.probes = []
        self.rservers = []
        self.f5conf = []
        self.lb_method = ''
        for line in self.config.splitlines():
            if line.strip().startswith('probe'):
                *_, probe = line.split()
                self.probes.append(probe)
            elif line.strip().startswith('rserver'):
                if len(line.split()) == 3:
                    _, rserver, port = line.split()
                else:
                    _, rserver = line.split()
                    port = 'any'
                self.rservers.append((rserver, port))
        if self.probes:
            no_port = False
            for rserver, port in self.rservers:
                if port == 'any':
                    no_port = True
                    break
            if no_port == True:
                for probe in self.probes:
                    ServerfarmHost.serverfarm_any_monitors.append(probe)
        self._f5conf_local()
        ServerfarmHost.all_objs[self.name] = self
        self.log_unmapped_lines()
        
    def _f5conf_local(self):
        '''
        ltm pool SF01-SR-T1-TD-NLP-i31ses04-80 {
            description NLP TD SES Servers
            monitor PROBE-SR-T1-TD-NLP-i31ses04-443
            members { i31ses04-29:80  { address 10.140.27.224 }}
        }'''
        self.f5conf = []
        self.f5conf.append('ltm pool %s {' % (self.name))
        self.f5conf.append('    %s' % (self.description))
        monitors = []
        for probe in self.probes:
            monitors.append(probe)
        if monitors:
            self.f5conf.append('    monitor %s' % (' and '.join(monitors)))
        members = []
        for rserver in self.rservers:
            members.append('%s:%s' % (rserver[0], rserver[1]))
        if members:
            self.f5conf.append('    members { \n        %s\n    }' % ('\n        '.join(members)))
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)


class ServerfarmRedirect(ConfigBlock):
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'rserver',
        'inservice']

    def __init__(self, config):
        super().__init__(config)
        self.rserver = ''
        for line in self.config.splitlines():
            if line.strip().startswith('rserver'):
                _, self.rserver= line.split()
        self._f5conf_local()
        ServerfarmRedirect.all_objs[self.name] = self
    def _f5conf_local(self):
        self.f5conf = []
        self.f5conf.append('ltm rule %s {' % (self.name))
        if self.description:
            self.f5conf.append('    # %s' % (self.description))
        if self.rserver:
            rserver = RserverRedirect.all_objs[self.rserver]
        for line in rserver.config.splitlines():
            if line.strip().startswith('webhost-redirection'):
                *_, self.redirect, self.http_code = line.split()
                self.redirect = self.redirect.replace('%h','[HTTP::host]')
                self.redirect = self.redirect.replace('%p','[HTTP::uri]')
                self.f5conf.append('  when HTTP_REQUEST {')
                self.f5conf.append('    HTTP::respond %s noserver Location \"%s\"\n  }' % (self.http_code, self.redirect))
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)
        self.log_unmapped_lines()

class InterfaceVlan(ConfigBlock):
    '''
    interface vlan 1151
    description T1-UK-APPS-LB
    ip address 10.188.10.2 255.255.255.0
    alias 10.188.10.1 255.255.255.0
    peer ip address 10.188.10.3 255.255.255.0
    access-group input PERMIT_ALL_EXCEPT_PCIDSS_LB
    nat-pool 1 10.188.10.254 10.188.10.254 netmask 255.255.255.255 pat
    nat-pool 2 10.188.10.253 10.188.10.253 netmask 255.255.255.255 pat
    service-policy input PM-SVIP-V1151-SNAT
    service-policy input UK-T1-V1151-SERVERSIDE-LB-POLICY-INTERNAL
    no shutdown
    '''
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'interface',
        'ip',
        'alias',
        'peer',
        'service-policy',
        'nat-pool']

    def __init__(self, config):
        super().__init__(config)
        self.service_policy = []
        self.acl = []
        self.nat = []
        for line in self.config.splitlines():
            if line.strip().startswith('interface'):
                *_, vlan = line.split()
                self.vlan_id = vlan
                self.vlan = 'VLAN{}'.format(vlan)
            elif line.strip().startswith('ip address'):
                *_, self.self_ip, self.self_mask = line.split()
            elif line.strip().startswith('alias'):
                *_, self.float_ip, self.float_mask = line.split()
            elif line.strip().startswith('peer ip address'):
                *_, self.peer_ip, self.peer_mask = line.split()
            elif line.strip().startswith('service-policy'):
                *_, policy = line.split()
                self.service_policy.append(policy)
            elif line.strip().startswith('access-group'):
                *_, acl = line.split()
                self.acl.append(acl)
            elif line.strip().startswith('nat-pool'):
                SNATPool(line, self.vlan_id)
                self.nat.append(line)
        InterfaceVlan.all_objs[self.name] = self
        self.log_unmapped_lines()

class ipRoute(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        *_, self.net, self.mask, self.gateway = config.splitlines()[0].split()
        self.name = '%s/%s' % (self.net, get_net_mask(self.mask))
        ipRoute.all_objs[self.name] = self
    def __str__(self):
        return self.config

class Sticky(ConfigBlock):
    all_objs = {}
    mapped_lines = ConfigBlock.mapped_lines + [
        'serverfarm',
        'backup']

    def __init__(self, config):
        super().__init__(config)
        for line in config.splitlines():
            if line.strip().startswith('serverfarm'):
                if 'backup' in line:
                    _, self.serverfarm, _, self.backup_serverfarm, *_ = line.split()
                else:
                    _, self.serverfarm = line.split()

class StickyIP(Sticky):
    all_objs = {}
    mapped_lines = Sticky.mapped_lines + [
        'sticky',
        'timeout',
        'replicate']

    def __init__(self, config):
        super().__init__(config)
        self.sticky_type = 'ip'
        self.timeout = '1440'
        self.mirror = False
        for line in config.splitlines():
            if line.startswith('sticky ip-netmask'):
                *_, self.mask, _, self.type, _ = line.split()
            elif line.strip().startswith('timeout'):
                if len(line.split()) == 2:
                    _, self.timeout = line.split()
                elif len(line.split()) == 3:
                    _, self.timeout, _ = line.split()
            elif line.strip().startswith('replicate'):
                self.mirror = True
        self._f5conf_local()
        Sticky.all_objs[self.name] = self
        self.log_unmapped_lines()

    def _f5conf_local(self):
        '''sticky ip-netmask 255.255.255.255 address source ST-SF01-SR-T1-TD-NLP-i31ses04-80
                timeout 60
                replicate sticky
                serverfarm SF01-SR-T1-TD-NLP-i31ses04-80
            ltm persistence source-addr persist_source_addr_120 { 
                defaults-from /Common/source_addr
                timeout 720
                mirror enabled }'''
        self.f5conf = []
        self.f5conf.append('ltm persistence source-addr %s {' % (self.name))
        self.f5conf.append('    %s' % (self.description))
        self.f5conf.append('    defaults-from /Common/source_addr')
        self.f5conf.append('    mask %s' % (self.mask))
        self.f5conf.append('    timeout %d' % (int(self.timeout)*60))
        if self.mirror:
            self.f5conf.append('    mirror enabled')
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)

class StickyHTTP(Sticky):
    all_objs = {}
    mapped_lines = Sticky.mapped_lines + [
        'sticky',
        'timeout']

    def __init__(self, config):
        super().__init__(config)
        self.sticky_type = 'http'
        self.timeout = '1440'
        self.cookie = ''
        for line in config.splitlines():
            if line.startswith('sticky http-cookie'):
                *_, self.cookie, self.name = line.split()
            elif line.strip().startswith('timeout'):
                if len(line.split()) == 2:
                    _, self.timeout = line.split()
                elif len(line.split()) == 3:
                    _, self.timeout, _ = line.split()
        self._f5conf_local()
        Sticky.all_objs[self.name] = self
        self.log_unmapped_lines()

    def _f5conf_local(self):
        '''ltm persistence cookie ST-SF01-UK-T1-PRD-PROD-MEM.HEALTH.TSCBANK-HTTP {
    app-service none
    cookie-name UK-T1-PRD-PROD-MEM.HEALTH.TSCBANK
    defaults-from /Common/cookie'''
        self.f5conf = []
        self.f5conf.append('ltm persistence cookie %s {' % (self.name))
        self.f5conf.append('    %s' % (self.description))
        self.f5conf.append('    defaults-from /Common/cookie')
        if self.cookie:
            self.f5conf.append('    cookie-name %s' % (self.cookie))
        #self.f5conf.append('    timeout %d' % (int(self.timeout)*60))
        self.f5conf.append('}')
        self.f5conf = '\n'.join(self.f5conf)

class StickyHTTPHeader(Sticky):
    def __init__(self, config):
        super().__init__(config)
        self.sticky_type = 'header'
        self.timeout = '1440'
        Sticky.all_objs[self.name] = self


class StickyRADIUS(Sticky):
    def __init__(self, config):
        super().__init__(config)
        self.sticky_type = 'radius'
        self.timeout = '1440'
        Sticky.all_objs[self.name] = self


class RserverRedirect(ConfigBlock):
    all_objs = {}
    def __init__(self, config):
        super().__init__(config)
        RserverRedirect.all_objs[self.name] = self
        self.log_unmapped_lines()

class SNATPool(ConfigBlock):
    all_objs = {}
    def __init__(self, config, vlan):
        super().__init__(config)
        self.config = config
        self.vlan = vlan
        _, num, snat_ip1, snat_ip2, *_ = config.strip().split()
        self.name = 'snatpool_%s_%s' % (self.vlan, num)
        if snat_ip1 == snat_ip2:
            self.f5conf = 'ltm snatpool snatpool_%s_%s {\n	members {\n		%s\n	}\n}' % (self.vlan, num, snat_ip1)
        SNATPool.all_objs[self.name] = self


class F5VS:
    '''
    Takes Cisco ACE Class Map, Policy Map Class and Policy LB configuration blocks for conversion into F5 output for migration.
    e.g:
    ### ACE Input ###
        class-map match-any Class-Map-01
        2 match virtual-address 172.16.4.2 tcp eq www

        policy-map multi-match Policy-Map-01
          class Class-Map-01
            loadbalance vip inservice
            loadbalance policy Policy-LB-01
            loadbalance vip icmp-reply

        policy-map type loadbalance first-match Policy-LB-01
        class class-default
            serverfarm Serverfarm-01
    
    ### F5 OUTPUT ###
        ltm virtual Class-Map-01 {
            destination 172.16.4.2:http
            pool Serverfarm-01
            vlans {
                VLAN_1
            }
            profiles {
                tcp {}
                http {}
            }
        }
    '''
    all_objs = []
    def __init__(self, ClassMap, PolicyMapClass, PolicyLB):
        self.error = ''
        self.name = ''
        self.classmap = ClassMap
        self.policymapclass = PolicyMapClass
        self.policylb = PolicyLB
        self.serverfarm_type = ''
        self.vlans = policymapclass_vlan(PolicyMapClass)
        self.config = '%s\n%s\n%s' % (self.classmap.config, self.policymapclass.config, self.policylb.config)
        self.f5config = ''
        self.f5configbuild()
        F5VS.all_objs.append(self)
    
    def vip_checking(self):
        if len(self.classmap.vips) == 1:
            self.destination = self.classmap.vips[0]
            return
        else:
            error = '#ERROR: class-map %s contains %d VIPS, which is not one!' % (self.classmap.name, len(self.classmap.vips))
            ace2f5.error_blocks.append(error)
            print(error)
    
    def f5configbuild(self):
        '''
        Sets F5 Virtual Server (VS) configuration output from ACE configuration blocks, if multiple VIP exist in ACE Class configuration then
        each VIP is set to create a different VS configuration on the F5 output.
        
        Error/Warning messages are added to the F5 output for checking
        '''
        f5config = []
        count = 0
        if len(self.classmap.vips) > 1:
            error = '#ERROR: class-map %s contains %d VIPS, which is not one!' % (self.classmap.name, len(self.classmap.vips))
            ace2f5.error_blocks.append(error)
            print(error)
            for vip in self.classmap.vips:
                count += 1
                f5config.append('ltm virtual %s_%d {' % (self.classmap.name, count))
                f5config.append(self.f5configbuild_vs(vip))
        elif len(self.classmap.vips) == 1:
            f5config.append('ltm virtual %s {' % (self.classmap.name))
            f5config.append(self.f5configbuild_vs(self.classmap.vips[0]))
        else:
            error = '#ERROR: class-map %s contains %d VIPS, which is not one!' % (self.classmap.name, len(self.classmap.vips))
            ace2f5.error_blocks.append(error)
            print(error)
        self.f5config = '\n'.join(f5config)
        self.f5conf = self.f5config

    def f5configbuild_vs(self, vip):
        '''
        Sets F5 configuration output from ACE configuration blocks
        '''
        #Clear f5config list
        f5config = []
        #Set Virtual Server be TCP only by setting 'http_profile' var to False
        self.http_profile = False
        
        #Get and set VS description
        if self.classmap.description:
            f5config.append('    %s' % (self.classmap.description))
        f5config.append('    destination %s:%s' % (vip['ip'], vip['port']))
        
        #Check for Sticky Serverfarm in Policy LB
        if self.policylb.sticky:
            if Sticky.all_objs[self.policylb.sticky_serverfarm].sticky_type == 'http':
                #If sticky typs is HTTP VS must have HTTP profile
                self.http_profile = True
            #Set Pool from serverfarm configured under the sticky serverfarm config 
            if hasattr(Sticky.all_objs[self.policylb.sticky_serverfarm], 'serverfarm'):
                f5config.append('    pool %s' % (Sticky.all_objs[self.policylb.sticky_serverfarm].serverfarm))
            else:
                #Output error is serverfarm is not found
                f5config.append('    #TODO missing Serverfarm from sticky config %s' % (Sticky.all_objs[self.policylb.sticky_serverfarm].name))
            f5config.append('    persist { %s }' % (self.policylb.sticky_serverfarm))
        
        #Check for Backup Serverfarm in Policy LB
        if hasattr(self.policylb, 'backup_serverfarm'):
            #Output error if backup serverfarm is found (TODO)
            f5config.append('   #TODO: Backup serverfarm in use, manual merge %s and %s.' % (
                self.policylb.serverfarm, self.policylb.backup_serverfarm))
        #If no sticky and backup serverfarm, find serverfarm in Policy LB
        elif hasattr(self.policylb, 'serverfarm'):
            #If Serverfarm is Host set VS pool
            if self.policylb.serverfarm in ServerfarmHost.all_objs.keys():
                f5config.append('    pool %s' % (self.policylb.serverfarm))
            #If Serverfarm is a Redirect set iRule in place of pool
            elif self.policylb.serverfarm in ServerfarmRedirect.all_objs.keys():
                f5config.append('    rules { %s } #TODO: Check iRule and replace' % (self.policylb.serverfarm))
        #Get VLAN list (from PolicyMapMultiMatch originally and set in class __init__) and set VS to listen only on listed VLANs
        if self.vlans:
            f5config.append('    vlans {')
            for vlan in self.vlans:
                f5config.append('        %s' % (vlan))
            f5config.append('    }\n    vlans-enabled')
        #If SNAT found in PolicyMapClass object then generate source-address-translation ConfigBlock
        if self.policymapclass.snat == True:
            f5config.append('    source-address-translation {')
            f5config.append('        %s' % (self.policymapclass.snat_pool))
            f5config.append('        type snat')
            f5config.append('   }')
        #Set VS profile, minimum 'tcp' profile will be set
        f5config.append('    profiles {')
        f5config.append('        %s {}' % (vip['protocol']))
        if vip['port'] == 'http' or vip['port'] == '80' or self.policymapclass.ssl or self.http_profile:
            f5config.append('        http {}')
        if self.policymapclass.ssl:
            f5config.append('        %s {}' % (self.policymapclass.ssl_proxy))
        
        f5config.append('    }\n}')
        return '\n'.join(f5config)
    
    def csv_output(self):
        line = ''
        for vip in self.classmap.vips:
            line = '%s, %s, %s, %s, ' % (self.classmap.name, vip['ip'], vip['port'], vip['protocol'])
            if self.policymapclass.ssl:
                line += '%s, ' % (self.policymapclass.ssl_proxy)
            else:
                line += ', '
            if self.policylb.sticky:
                line += '%s, ' % (self.policylb.sticky_serverfarm)
                if hasattr(Sticky.all_objs[self.policylb.sticky_serverfarm], 'serverfarm'):
                    line += '%s, ' % (Sticky.all_objs[self.policylb.sticky_serverfarm].serverfarm)
                else:
                    line += ', '
            elif hasattr(self.policylb, 'serverfarm'):
                line += ', %s, ' % (self.policylb.serverfarm)
            else:
                line += ', , '
            if hasattr(self.policylb, 'backup_serverfarm'):
                line += '%s, ' % (self.policylb.backup_serverfarm)
            else:
                line += ', '
            if self.vlans:
                vlan_str = ''
                for vlan in self.vlans:
                    vlan_str += '%s ' % (vlan)
                line += '%s, ' % (vlan_str)
            else:
                line += ', '
            if self.policymapclass.snat == True:
                line += '%s, ' % (self.policymapclass.snat_pool)
            else:
                line += ', '
            if self.classmap.description:
                line += '%s\n' % (self.classmap.description)
            else:
                line += '\n'
        return line
            
                
    
    def __str__(self):
        return '##### ACE #####\n%s%s%s##### F5 #####\n%s' % (self.classmap.config, self.policymapclass.config, self.policylb.config, self.f5config)

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="file", type="str",
                      default="", help="ACE Configuration File")
    parser.add_option("-o", "--output", dest="output", type="str",
                      default="", help="Output file")
    parser.add_option("-n", "--nooutput", dest="nooutput", action="store_true",
                      default=False, help="Disables file output, use with python -i <script>")
    parser.add_option("-s", "--ssllab", dest="ssllab", action="store_true",
                      default=False, help="Output to console SSL lab script for SSL cert and key object creation")
    parser.add_option("-t", "--notime", dest="timestamp", action="store_false",
                      default=True, help="Disables appending timestamp to the end of 'checking' output file")
    (options, args) = parser.parse_args()
    
    if options.file:
        if options.output:
            out_file = options.output + '-' + timestamp()
        else:
            out_file = '{}.output'.format(options.file)
        if options.timestamp:
            checking_file = '%s.checking-%s'% (options.file, timestamp())
            logging_file = '%s.log-%s'% (options.file, timestamp())
        else:
            checking_file = '%s.checking'% (options.file)
            logging_file = '%s.log'% (options.file)
        logging.basicConfig(filename=logging_file, filemode='w', level=logging.DEBUG)
        logging.info('LOG STARTED for %s' % (options.file))
        csv_file = '{}.csv'.format(options.file)
        ace2f5 = aceconf(options.file)
        tmp_config = []
        sticky = ''
        probe_dict = {}
        rserver_host_dict = {}
        rserver_redirect_dict = {}
        classmap_dict = {}
        policymapclass_dict = {}
        policylb_dict = {}
        sticky_dict = {}
        serverfarm_host_dict = {}
        serverfarm_redirect_dict = {}
        ssl_dict = {}
        f5vs_dict = {}
        vs_count = 0
        for class_map in sorted(ClassMap.all_objs.keys()):
            serverfarm = ''
            classmap_dict[ClassMap.all_objs[class_map].name] = ClassMap.all_objs[class_map]
            policy_map_class = find_policy_map_class(class_map)
            if policy_map_class:
                policymapclass_dict[policy_map_class.name] = policy_map_class
            policy_lb = find_policy_lb(policy_map_class)
            if policy_lb:
                vs_count += 1
                f5vs_dict[vs_count] = F5VS(ClassMap.all_objs[class_map], policy_map_class, policy_lb)
        ace2f5.error_blocks.append('\n\n# NOTE: Probes to be reviewed, destination port likely required due to set on node or pool members with wildcard port:')
        print('# NOTE: Probes to be reviewed, destination port likely required due to set on node or pool members with wildcard port:')
        for probe in set(RserverHost.rserver_monitors):
            print('Rserver Probe %s' % (probe))
            ace2f5.error_blocks.append('Rserver Probe %s' % (probe))
        for probe in set(ServerfarmHost.serverfarm_any_monitors):
            print('Serverfarm Probe %s' % (probe))
            ace2f5.error_blocks.append('Serverfarm Probe %s' % (probe))
        ace2f5.error_blocks.append('\n\n')
        if options.nooutput == False:
            with open(checking_file, 'wt') as f:
                print('#### Configuration Blocks not found ####', file=f)
                for item in ace2f5.error_blocks:
                    print(item, file=f)
                #crypto chaingroup
                #paramerter-map
                #action list
                #ACL
                #print('\n### Routes Count: %s' % (len(ipRoute.all_objs)), file=f)
                #print_ace_conf_to_file(ipRoute.all_objs, f)
                print('\n### SSL Profile Count: %s' % (len(SSLProxy.all_objs)), file=f)
                print_ace_conf_to_file(SSLProxy.all_objs, f)
                print('\n### ACL Count: %s' % (len(ACL.all_objs)), file=f)
                print_ace_conf_to_file(ACL.all_objs, f)
                print('\n### Monitor Count: %s' % (len(Probe.all_objs)), file=f)
                print_ace_conf_to_file(Probe.all_objs, f)
                print('\n### Node Count: %s' % (len(RserverHost.all_objs)), file=f)
                print_ace_conf_to_file(RserverHost.all_objs, f)
                print('\n### Redirect iRule Count: %s' % (len(RserverRedirect.all_objs)), file=f)
                print_ace_conf_to_file(RserverRedirect.all_objs, f)
                print('\n### Pool Count: %s' % (len(ServerfarmHost.all_objs)), file=f)
                print_ace_conf_to_file(ServerfarmHost.all_objs, f)
                print_ace_conf_to_file(ServerfarmRedirect.all_objs, f)
                print('\n### SNAT Pool Count: %s' % (len(SNATPool.all_objs)), file=f)
                print_ace_conf_to_file(SNATPool.all_objs, f)
                print('\n### Persistence Count: %s' % (len(Sticky.all_objs)), file=f)
                print_ace_conf_to_file(Sticky.all_objs, f)
                print('\n### Virtual Server Count: %s' % (len(f5vs_dict)), file=f)
                print_ace_conf_to_file(f5vs_dict, f)
                print('\n\n#*******************************************************************************', file=f, end='')
                print('\n# SSL Profile Count: %s' % (len(SSLProxy.all_objs)), file=f, end='')
                print('\n# Monitor Count: %s' % (len(Probe.all_objs)), file=f, end='')
                print('\n# Node Count: %s' % (len(RserverHost.all_objs)), file=f, end='')
                print('\n# Redirect iRule Count: %s' % (len(RserverRedirect.all_objs)), file=f, end='')
                print('\n# Pool Count: %s' % (len(ServerfarmHost.all_objs)), file=f, end='')
                print('\n# Persistence Count: %s' % (len(Sticky.all_objs)), file=f, end='')
                print('\n# Virtual Server Count: %s' % (len(f5vs_dict)), file=f, end='')
                print('\n\n\n# Run the following to create F5 output from this file\n# python checking-output.py -f \"%s\"' % (checking_file), file=f)
            
            '''with open(out_file, 'wt') as f:
                print_f5_conf_to_file(SSLProxy.all_objs, f)
                print_f5_conf_to_file(Probe.all_objs, f)
                print_f5_conf_to_file(RserverHost.all_objs, f)
                print_f5_conf_to_file(ServerfarmHost.all_objs, f)
                print_f5_conf_to_file(ServerfarmRedirect.all_objs, f)
                print_f5_conf_to_file(Sticky.all_objs, f)
                print_f5_conf_to_file(f5vs_dict, f)'''
            with open(csv_file, 'wt') as c:
                print('Name, IP, Port, Protocol, SSL, Sticky, Serverfarm, Backup Serverfarm, VLANs, SNAT, Description\n', file=c, end='')
                for object in F5VS.all_objs:
                    print(object.csv_output(), file=c, end='')
        if options.ssllab:
            print('\n\n### SSL LAB output script, to be run from bash shell ###\n')
            print(output_ssl_lab())
            print()
    else:
        parser.print_help()
