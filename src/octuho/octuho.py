from . import __version__
import requests, configparser, sys, json, warnings
import logging
import logging.handlers

from os.path import expanduser

warnings.filterwarnings("ignore")

def run():
    userhome = expanduser("~")
    maindir = userhome + "/.octuho/"
    motd = "OCTUHO " + str(__version__) + " OpnSense CSV To Unbound HostOverrides"
    
    # Init Logger
    logger = logging.getLogger("oct")
    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(maindir + "octuho.log", mode="w")
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    logger.info(motd)
    
    cfg_file = maindir + "octuho.config"
    # read interval & weburls config
    try:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        url = cfg["GENERAL"]["url"]
        api_key = cfg["GENERAL"]["api_key"]
        api_secret = cfg["GENERAL"]["api_secret"]
    except Exception as e:
        print(str(e))
        logger.error(str(e))
        sys.exit()
    print(api_key)
    sys.exit()

    base_url = url + "/api/unbound/settings/"
    
    # loop over all host overrides, and replace them by setting desc. to hostname
    unbound_cmd = base_url + "search_host_override"
    r = requests.get(unbound_cmd , verify=False, auth=(api_key, api_secret))
    if r.status_code != 200:
        print("Url or api_key/secret wrong, exiting ...")
        sys.exit()

    rj = json.loads(r.text)["rows"]
    for dict0 in rj:
        uuid = dict0["uuid"]
        hostname = dict0["hostname"]
        unbound_cmd = base_url + "del_host_override/" + uuid
        r = requests.post(unbound_cmd, verify=False, auth=(api_key, api_secret))
        print(hostname, uuid, json.loads(r.text)["result"])
        payload = {"host":
                       {"enabled": "1",
                        "hostname": dict0["hostname"],
                        "domain": dict0["domain"],
                        "rr": "A",
                        "mxprio": "",
                        "mx": "",
                        "server": dict0["server"],
                        "description": dict0["hostname"] + "2"
                        }
                   }
        unbound_cmd = base_url + "add_host_override"
        r = requests.post(unbound_cmd, json=payload, verify=False, auth=(api_key, api_secret))
        rj = json.loads(r.text)
        print(rj["result"], rj["uuid"])
        print("*" * 100)
    
    sys.exit()
    
    
    
    print(dict0)
    # ... and get the uuid of the last one
    uuid = dict0["uuid"]
    
    # delete the last entry (with the above uuid)
    unbound_cmd = base_url + "del_host_override/" + uuid
    r = requests.post(unbound_cmd, verify=False, auth=(api_key, api_secret))
    print(r.text)
    
    # and insert it again but with changed description
    payload = {"host":
                   {"enabled":"1",
                    "hostname": dict0["hostname"],
                    "domain": dict0["domain"],
                    "rr":"A",
                    "mxprio":"",
                    "mx":"",
                    "server": dict0["server"],
                    "description": dict0["description"] + "1"
                    }
               }
    unbound_cmd = base_url + "add_host_override"
    # payload = rj
    r = requests.post(unbound_cmd, json=payload, verify=False, auth=(api_key, api_secret))
    print(r.text)
    
    
    
    """unbound_cmd = base_url + "get_host_override/"+uuid
    print(unbound_cmd)
    r = requests.get(unbound_cmd , verify=False, auth=(api_key, api_secret))
    rj = json.loads(r.text)
    print("-"*80)
    rj["description"] = "tasmotaatec"
    print(rj)"""
    
