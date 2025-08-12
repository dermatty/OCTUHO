import os.path
import csv
from . import __version__
import requests, configparser, sys, json, warnings

from os.path import expanduser

warnings.filterwarnings("ignore")

SEPSTRING =  "*" * 100 + "\n"

def run():
    print("\nOCTUHO " + str(__version__) + " OpnSense CSV To Unbound HostOverrides\n")
    
    # setup directories
    userhome = expanduser("~")
    maindir = userhome + "/octuho/"
    
    # read domain, api_key, api_secret and url from config config
    cfg_file = maindir + "octuho.config"
    try:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        url = cfg["GENERAL"]["url"]
        api_key = cfg["GENERAL"]["api_key"]
        api_secret = cfg["GENERAL"]["api_secret"]
        domain = cfg["GENERAL"]["domain"]
    except Exception as e:
        print(str(e) + ", exiting!")
        sys.exit()
        
    # check if input file exists and read into list
    try:
        input_csv_file = sys.argv[1]
        if not os.path.exists(input_csv_file):
            raise Exception("Input CSV file does not exist, exiting!")
        if not input_csv_file.casefold().endswith(".csv"):
            raise Exception("Input file does not have CSV extension, exiting!")
    except Exception as e:
        print(str(e) + ", exiting!")
        sys.exit()
    kea_data = []
    with open(input_csv_file, "r") as f:
        line = f.readline()
        i = 0
        while line != '':
            if i > 0:
                kr = line.split(",")[:-1]
                try:
                    kea_data.append({"host": kr[2], "domain": domain, "ip": kr[0], "description": kr[3]})
                except Exception:
                    pass
            line = f.readline()
            i += 1
    # print("KEA data list is:", kea_data)
    print(SEPSTRING)

    # now delete all unbound overrides and load csv hosts as overrides
    base_url = url + "/api/unbound/settings/"
    # loop over all host overrides, and replace them by setting desc. to hostname
    unbound_cmd = base_url + "search_host_override"
    r = requests.get(unbound_cmd , verify=False, auth=(api_key, api_secret))
    if r.status_code != 200:
        e = "Url or api_key/secret wrong, exiting ..."
        print(str(e) + ", exiting!")
        sys.exit()
    # delete host overrides
    print("Deletion of unbound overrides:")
    rj = json.loads(r.text)["rows"]
    for dict0 in rj:
        uuid = dict0["uuid"]
        hostname = dict0["hostname"]
        unbound_cmd = base_url + "del_host_override/" + uuid
        r = requests.post(unbound_cmd, verify=False, auth=(api_key, api_secret))
        print("   ", hostname, uuid, " ---> ", json.loads(r.text)["result"])
    print(SEPSTRING)
    
    # load kea data into unbound
    print("Loading of new Unbound host overrides from CSV:")
    for kd in kea_data:
        payload = {"host":
                       {"enabled": "1",
                        "hostname": kd["host"],
                        "domain": kd["domain"],
                        "rr": "A",
                        "mxprio": "",
                        "mx": "",
                        "server": kd["ip"],
                        "description": kd["description"] + "!"
                        }
                   }
        unbound_cmd = base_url + "add_host_override"
        r = requests.post(unbound_cmd, json=payload, verify=False, auth=(api_key, api_secret))
        rj = json.loads(r.text)
        try:
            uuid = rj["uuid"]
        except Exception:
            uuid = "N/A"
        print("    ",kd["host"], kd["domain"], " ---> ", uuid, rj["result"])
    print(SEPSTRING)
    print("DONE!\n")
    