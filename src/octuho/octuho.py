import os.path
import csv
from . import __version__
import requests, configparser, sys, json, warnings

from os.path import expanduser

warnings.filterwarnings("ignore")

SEPSTRING =  "*" * 100

def run():
    print("\nOCTUHO " + str(__version__) + " OpnSense Kea CSV Export To Technitium Zone Records and Opnsense Unbound HostOverrides\n")
    
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

    try:
        turl = cfg["TECHNITIUM"]["url"]
        tuser = cfg["TECHNITIUM"]["user"]
        tpw = cfg["TECHNITIUM"]["pw"]
        add_technitium_local_zone = True
    except:
        turl = ""
        tuser = ""
        tpw = ""
        add_technitium_local_zone = False
        
        
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
    
    # first: do the technitium stuff
    if add_technitium_local_zone:
        zone = domain
        
        # login & get token
        print("Technitium: logging in ...")
        t_login_url = turl + "/api/user/login?user=" + tuser + "&pass=" + tpw + "&includeInfo=true"
        t_r = requests.get(t_login_url, verify=False)
        t_json = json.loads(t_r.text)
        t_token = t_json["token"]
        
        # read all records from zone, only possible via export
        print("Technitium: reading all records from zone '" + zone + "' ...")
        t_export_url = turl + "/api/zones/export?token=" + t_token + "&zone=" +  zone
        t_r = requests.get(t_export_url, verify=False)
        hostlist = []
        for r1 in ''.join(t_r.text).split("\n"):
            r111 = [r10.strip() for r10 in r1.split("  ") if r10 != '']
            try:
                if r111[3] == "A":
                    hostlist.append((r111[0], r111[4]))
            except Exception:
                pass
        
        # now delete all entries
        print("Technitium: deleting all old records in zone '" + zone + "' ...")
        for hostn, ip in hostlist:
            domain0 = hostn + "." + domain
            t_delete_url = (turl + "/api/zones/records/delete?token=" + t_token + "&domain=" + domain0 +
                            "&zone=" + zone + "&type=A&value=" + ip)
            t_r = requests.get(t_delete_url, verify=False)
            print("    deleting record " + hostn + "/" + ip + ": ",t_r)
        
        # and add from download_reservations
        print("Technitium: adding all records from kea file ...")
        for kd in kea_data:
            t_add_url = (turl + "/api/zones/records/add?token=" + t_token + "&domain=" + kd["host"] + "."
                         + kd["domain"] + "&zone=" + zone + "&type=A&ipAddress=" +  kd["ip"] + "&overwrite=true&ttl=36000")
            t_r = requests.get(t_add_url, verify=False)
            print("    adding record " + kd["host"] + "." + kd["domain"] + "/" + kd["ip"] + ": ", t_r)
            
        # logout
        t_logout_url = turl + "/api/user/logout?token=" + t_token
        t_r = requests.get(t_logout_url, verify=False)
        print("Technitium: logged out: " , t_r)
    
    print(SEPSTRING)
    # now delete all unbound overrides - except those start and ending with '!!' and load csv hosts as overrides
    base_url = url + "/api/unbound/settings/"
    # loop over all host overrides, and replace them by setting desc. to hostname
    unbound_cmd = base_url + "search_host_override"
    r = requests.get(unbound_cmd , verify=False, auth=(api_key, api_secret))
    if r.status_code != 200:
        e = "Url or api_key/secret wrong, exiting ..."
        print(str(e) + ", exiting!")
        sys.exit()
    # delete host overrides
    print("OpnSense: deletion of unbound overrides")
    rj = json.loads(r.text)["rows"]
    for dict0 in rj:
        uuid = dict0["uuid"]
        hostname = dict0["hostname"]
        description = dict0["description"]
        if description.startswith("!!") and description.endswith("!!"):
            print("   skipping ", hostname, uuid, description)
            continue
        unbound_cmd = base_url + "del_host_override/" + uuid
        r = requests.post(unbound_cmd, verify=False, auth=(api_key, api_secret))
        print("   ", hostname, uuid, " ---> ", json.loads(r.text)["result"])
    print(SEPSTRING)
    
    # load kea data into unbound
    print("OpnSense: loading of new Unbound host overrides from CSV")
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
    print("ALL DONE!\n")
    