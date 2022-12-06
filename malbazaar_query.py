import argparse
import pathlib
from pathlib import Path
import hashlib
import magic
import pefile
import re
import requests

parser = argparse.ArgumentParser(description='Query sample information by Hash or File.')

parser.add_argument('--file', dest='file', type=str, help='Query File at filepath (e.g. /foo/bar/blah.exe)')
parser.add_argument('--hash', dest='hash', type=str, help='Query Hash (MD5)')
args = parser.parse_args()

def md5hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashmd5 = hashlib.md5()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashmd5.update(info)
    return hashmd5.hexdigest()

def sha1hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashsha1 = hashlib.sha1()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha1.update(info)
    return hashsha1.hexdigest()

def sha256hash(file):
    BSIZE = 65536
    hnd = open(file, 'rb')
    hashsha256 = hashlib.sha256()
    while True:
        info = hnd.read(BSIZE)
        if not info:
            break
        hashsha256.update(info)
    return hashsha256.hexdigest()

def malbazaarlookup(hash):    
    data = {'query': 'get_info', 'hash': fhash}
    url = "https://mb-api.abuse.ch/api/v1/"
    response = requests.post(url, data=data)
    
    if response.json()["query_status"] == 'hash_not_found':
        print('>>>>>>>>>>  The sample hash was not found on Malbazaar  <<<<<<<<<<')

    else:
        response_json = response.json()["data"][0]

        print('###############<<<  File Info  >>>###############')
        print('#################################################')
        file_name = response_json.get("file_name")
        print('')    
        print("Filename: " + file_name)
        print('')
        file_type_mime = response_json.get("file_type_mime")
        file_type = response_json.get("file_type")
        print("MIME File Type: " + file_type_mime)
        print("     File Type: " + file_type)
        print('')
        first_seen = response_json.get("first_seen")
        last_seen = response_json.get("last_seen")
        print("First Seen: " + str(first_seen))
        print(" Last Seen: " + str(last_seen))
        print('')
        malbazaar_signature = response_json.get('signature')
        print('Signature: ' + malbazaar_signature)
        print('')
        tags = response_json.get("tags")
        print("Tags:", tags)
        print('')
        print('')
        #yararules
        yara_rules = response_json.get('yara_rules')
        if yara_rules:
            print('###############<<<  YARA rule information  >>>###############')
            print('#############################################################')
            print('')
            for yar in range(0, len(yara_rules)):
                print("YARA Rule name: " + str(yara_rules[yar]['rule_name']))
                print("YARA Description: " + str(yara_rules[yar]['description']))
                print('')
                print('')

        print('###############<<<  File HASH information  >>>###############')
        print('#############################################################')
        print('')
        sha256_hash = response_json.get("sha256_hash")
        sha1_hash = response_json.get("sha1_hash")
        md5_hash = response_json.get("md5_hash")
        print("   MD5 hash: " + md5_hash)
        print("  SHA1 hash: " + sha1_hash)
        print("SHA256 hash: " + sha256_hash)
        print('')        
        imphash_hash = response_json.get("imphash")
        ssdeep_hash = response_json.get("ssdeep")
        print("    IMPHASH: " + imphash_hash)
        print('')
        print("     SSDEEP: " + ssdeep_hash)
        print('')
        print('')

        print('###############<<<  File Intelligence information  >>>###############')
        print('#####################################################################')
        print('')
        delivery_method = response_json.get("delivery_method")
        print("Delivery method: " + str(delivery_method))
        print('')
        intelligence = response.json()["data"][0]["intelligence"]["clamav"]
        print('Intelligence: '+ str(intelligence))
        print('')
        print('')

        #ReversingLabs = response.json()["data"][0]["vendor_intel"]["ReversingLabs"]
        ReversingLabs_verdict = response.json()["data"][0]["vendor_intel"]["ReversingLabs"]["status"]
        ReversingLabs_threatname = response.json()["data"][0]["vendor_intel"]["ReversingLabs"]["threat_name"]
        ReversingLabs_firstseen = response.json()["data"][0]["vendor_intel"]["ReversingLabs"]["first_seen"]
        print('###############<<<  REVERSINGLABS info  >>>###############')
        print('##########################################################')
        print('ReversingLabs verdict: '+ ReversingLabs_verdict)
        print('ReversingLabs threatname: '+ ReversingLabs_threatname)
        print('ReversingLabs firstseen: '+ ReversingLabs_firstseen)
        print('')
        print('')
    
        #ANYRUN = response.json()["data"][0]["vendor_intel"]["ANY.RUN"]
        ANYRUN_verdict = response.json()["data"][0]["vendor_intel"]["ANY.RUN"][0]["verdict"]
        ANYRUN_firstseen = response.json()["data"][0]["vendor_intel"]["ANY.RUN"][0]["date"]
        ANYRUN_URL = response.json()["data"][0]["vendor_intel"]["ANY.RUN"][0]["analysis_url"]
        print('###############<<<  ANY.RUN info  >>>###############')
        print('####################################################')
        print('ANY.RUN verdict: ' + ANYRUN_verdict)
        print('ANY.RUN firstseen: ' + ANYRUN_firstseen)
        print('ANY.RUN Analysis URL: ' + ANYRUN_URL)
        print('')
        print('')
    
        #HatchingTriage = response.json()["data"][0]["vendor_intel"]["Triage"]
        print('###############<<<  HatchingTriage info  >>>###############')
        print('###########################################################')
        HatchingTriage_verdict = response.json()["data"][0]["vendor_intel"]["Triage"]["score"]
        HatchingTriage_malwarefamily = response.json()["data"][0]["vendor_intel"]["Triage"]["malware_family"]
        HatchingTriage_tags = response.json()["data"][0]["vendor_intel"]["Triage"]["tags"]
        HatchingTriage_URL = response.json()["data"][0]["vendor_intel"]["Triage"]["link"]
        print('Hatching Triage verdict: ' + HatchingTriage_verdict)
        print('Hatching Triage Malware family: ' + HatchingTriage_malwarefamily)
        print('Hatching Triage tags: ' + str(HatchingTriage_tags))
        print('Hatching Triage Analysis URL: ' + HatchingTriage_URL)
        print('')
        print('')

        #UnpacME                
        unpac_me = response.json()["data"][0]["vendor_intel"]["UnpacMe"]
        if unpac_me:
            print('##################<<<  Unpac Me info  >>>##################')
            print('###########################################################')
            print('')
            for unp in range(0, len(unpac_me)):
                print("   MD5 hash: " + (unpac_me[unp]['md5_hash']))
                print("SHA256 hash: " + (unpac_me[unp]['sha256_hash']))
                print("Link: " + unpac_me[unp]['link'])
                print("Detections: " + str(unpac_me[unp]['detections']))
                print('')


        #Malware Bazaar Page info
        print('###############<<<  AbuseCH Malware Bazaar info  >>>###############')
        print('###################################################################')
        print('')
        print('AbuseCH Malware Bazaar page:')
        print('https://bazaar.abuse.ch/sample/' + sha256_hash)
        print('')


if args.file is None and args.hash is None:
   parser.error("at least one of --file or --hash required")

if args.file is None:
    print('')
    print("##########################################################################################################")
    print("AbuseCH Malware Bazaar Info for the HASH: " + args.hash)
    print("##########################################################################################################")
    print('')
    print('')

    fhash = args.hash

    malbazaarlookup(fhash)
    
else:
    fpath = args.file

    p = Path(fpath)

    if p.is_dir():
        print('')
        print("You specified a directory.... Please specify a single file.")
        exit(0)

    else:
        if p.is_file():
            print('')
            print("#################################################################")
            print("Searching information for the FILE: " + args.file)
            print("#################################################################")
            print('')
            print('')
            
            files = [p]
            
            filename = (p).name
            fmd5hash = md5hash(p)
            fsha1hash = sha1hash(p)
            f256hash = sha256hash(p)
            magictype = magic.from_file(str(p))

            print('')
            print("   Filename: " + filename)
            print('')
            print("   MD5 hash: " + fmd5hash)
            print("  SHA1 hash: " + fsha1hash)
            print("SHA256 hash: " + f256hash)
            print('')

            if re.match(r'^PE[0-9]{2}\s\S*\s\([A-Z]{3}\)|^PE[0-9]{2}\+\s\S*\s\([a-z]', magictype):
                fpe = pefile.PE(p)
                imphash = fpe.get_imphash()
                print("    IMPHASH: " + imphash)
                print('')
            else:
                    print("    IMPHASH: <NONE>...not a PE")
                    print('')

            fhash = fmd5hash
            malbazaarlookup(fhash)