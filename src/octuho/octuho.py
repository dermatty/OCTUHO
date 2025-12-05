import os.path
import csv
from . import __version__
import requests, configparser, sys, json, warnings

from os.path import expanduser

warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings()

SEPSTRING =  "*" * 100

def run():
    print("\nOCTUHO " + str(__version__) + " OpnSense DHCP Hosts CSV Export To Technitium Zone Records and Opnsense Unbound HostOverrides\n")
    
    # setup directories
    userhome = expanduser("~")
    maindir = userhome + "/octuho/"
    
    # read domain, api_key, api_secret and url from config
    cfg_file = maindir + "octuho.config"
    try:
        cfg = configparser.ConfigParser()
        cfg.read(cfg_file)
        url = cfg["GENERAL"]["url"]
        api_key = cfg["GENERAL"]["api_key"]
        api_secret = cfg["GENERAL"]["api_secret"]
        domain = cfg["GENERAL"]["domain"]
        use_dnsmasq = True if cfg["GENERAL"]["use_dnsmasq"].lower() in ["true", "yes"] else False
    except Exception as e:
        print(str(e) + ", exiting!")
        sys.exit()
    if use_dnsmasq:
        print(" ... using DnsMasq host reservations!")
    else:
        print(" ... using Kea host reservations!")
        
    # read additional domain entries which are not in kea
    i = 0
    domainentry_list = []
    add_domain_entries = True
    while True:
        try:
            entry =  cfg.get("DOMAIN","entry"+str(i+1))
            entry_list = entry.split(",")
            domainentry_list.append(entry_list)
            i += 1
        except (Exception, ):
            break
    if i == 0:
        add_domain_entries = False
    
    # read technitium dns server config
    i = 0
    technitium_list = []
    add_technitium_local_zone = True
    while True:
        try:
            tname = cfg["TECHNITIUM" + str(i+1)]["name"]
            turl = cfg["TECHNITIUM" + str(i+1)]["url"]
            ttoken = cfg["TECHNITIUM"+ str(i+1)]["token"]
            
            technitium_list.append((tname, turl, ttoken))
            i += 1
        except (Exception, ):
            break
    if i == 0:
        add_technitium_local_zone = False
    
    print(SEPSTRING)
    # read download reservations file
    if not use_dnsmasq:
        print("Reading OpnSense Kea download_reservations.csv file ...")
        unbound_cmd = url + "/api/kea/dhcpv4/download_reservations"
    else:
        print("Reading OpnSense Dnsmasq download_hosts.csv file ...")
        unbound_cmd = url + "/api/dnsmasq/settings/download_hosts"

    r = requests.get(unbound_cmd, verify=False, auth=(api_key, api_secret))
    if r.status_code != 200:
        e = "Url or api_key/secret wrong, exiting ..."
        print(str(e) + ", exiting!")
    host_data_unsorted = []
    rsplit1 = r.text.split("\n")
    i = 0
    for r1 in rsplit1:
        if i > 0:
            kr = r1.split(",")
            if len(kr) < 4:
                continue
            if not use_dnsmasq:
                x_host = kr[2]
                x_ip = kr[0]
                x_descr = kr[3]
            else:
                x_host = kr[0]
                x_ip = kr[3]
                x_descr = kr[10]
            kd0 = {"host": x_host, "domain": domain, "ip": x_ip, "description": x_descr}
            # print(kd0)
            host_data_unsorted.append(kd0)
        i += 1
    host_data = sorted(host_data_unsorted, key=lambda d: d['ip'])
    
    # first: do the technitium stuff
    if add_technitium_local_zone:
        print(SEPSTRING)
        for tname, t_url, t_token in technitium_list:
            zone = domain
            
            # read all records from zone, only possible via export
            print(tname + ": Technitium: reading all records from zone '" + zone + "' ...")
            t_export_url = t_url + "/api/zones/export?token=" + t_token + "&zone=" +  zone
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
            print(tname + ": Technitium: deleting all old records in zone '" + zone + "' ...")
            for hostn, ip in hostlist:
                domain0 = hostn + "." + domain
                t_delete_url = (t_url + "/api/zones/records/delete?token=" + t_token + "&domain=" + domain0 +
                                "&zone=" + zone + "&type=A&value=" + ip)
                t_r = requests.get(t_delete_url, verify=False)
                print("    deleting record " + hostn + "/" + ip + ": ",t_r)
        
            # and add from download_reservations
            print(tname + ": Technitium: adding all records from kea file ...")
            for kd in host_data:
                t_add_url = (t_url + "/api/zones/records/add?token=" + t_token + "&domain=" + kd["host"] + "."
                             + kd["domain"] + "&zone=" + zone + "&type=A&ipAddress=" +  kd["ip"] + "&overwrite=true&ttl=36000")
                t_r = requests.get(t_add_url, verify=False)
                print("    adding record " + kd["host"] + "." + kd["domain"] + "/" + kd["ip"] + ": ", t_r)
            
            print(tname + ": Technitium: adding all additional records from octuho configfile ...")
            if add_domain_entries:
                for hostname, ip in domainentry_list:
                    t_add_url = (t_url + "/api/zones/records/add?token=" + t_token + "&domain=" + hostname + "."
                                 + domain + "&zone=" + zone + "&type=A&ipAddress=" + ip + "&overwrite=true&ttl=36000")
                    t_r = requests.get(t_add_url, verify=False)
                    print("    adding record " + hostname + "." + domain + "/" + ip + ": ", t_r)
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
        #description = dict0["description"]
        #if description.startswith("!!") and description.endswith("!!"):
        #    print("   skipping ", hostname, uuid, description)
        #    continue
        unbound_cmd = base_url + "del_host_override/" + uuid
        r = requests.post(unbound_cmd, verify=False, auth=(api_key, api_secret))
        print("   ", hostname, uuid, " ---> ", json.loads(r.text)["result"])
    print(SEPSTRING)
    
    # load kea data into unbound
    print("OpnSense: loading of new Unbound host overrides from CSV")
    unbound_cmd = base_url + "add_host_override"
    for kd in host_data:
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
        r = requests.post(unbound_cmd, json=payload, verify=False, auth=(api_key, api_secret))
        rj = json.loads(r.text)
        try:
            uuid = rj["uuid"]
        except Exception:
            uuid = "N/A"
        print("    ",kd["host"], kd["domain"], " ---> ", uuid, rj["result"])
    print(SEPSTRING)
    
    # load additional domain entries into unbound
    print("OpnSense: loading of new Unbound host overrides from addtl. domain entries in config file")
    unbound_cmd = base_url + "add_host_override"
    if add_domain_entries:
        for i, (hostname, ip) in enumerate(domainentry_list):
            payload = {"host":
                           {"enabled": "1",
                            "hostname": hostname,
                            "domain": domain,
                            "rr": "A",
                            "mxprio": "",
                            "mx": "",
                            "server": ip,
                            "description": "addtl. domain entry #" + str(i+1)
                            }
                       }
            
            r = requests.post(unbound_cmd, json=payload, verify=False, auth=(api_key, api_secret))
            rj = json.loads(r.text)
            try:
                uuid = rj["uuid"]
            except Exception:
                uuid = "N/A"
            print("    ", hostname, domain, " ---> ", uuid, rj["result"])
            
    print(SEPSTRING)
    print("ALL DONE!\n")
    