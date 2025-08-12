OCTUHO - OpnSense CSV To Unbound HostOverrides

Replaces OpnSense Host Overrides by the content of a CSV file - ideally following the KEA export csv file format, 
so KEA exports can be directly used.

KEA export csv file format:

    ip_address,hw_address,hostname,description,option_data
    192.168.1.101,c0:c9:e3:da:20:e6, hostname1,description1,
    192.168.1.102,b4:6d:83:8a:1c:ef,hostname2,description2,
    192.168.1.103,34:94:54:91:e6:c8,hostname3,description3,
    .
    .
    .

Create a directory "octuho" in your linux home directory and place the file "/home/myuser/octuho/octuho.config" (example 
see data directory here) here: 

    url: OpnSense Url
    api_key: OpnSense API Key
    api_secret: OpnSense API Secret
    domain: Domain (the "Domain" entry from System > Settings > General)

Usage: 
    octuho <csv_file_path>

Install: install the wheel here in the dist directory with 
    pip install octuho-....-py-none-any.whl



