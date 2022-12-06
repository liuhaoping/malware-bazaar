import sys
from malwarebazaar.api import Bazaar
#https://pypi.org/project/malwarebazaar/

if len(sys.argv) == 1:
    print("Specify sha256 as argument")
    exit
else:
    sha256 = sys.argv[1]


bazaar = Bazaar("myapikey")
try:
    r = bazaar.query_hash(sha256)
except requests.exceptions.ConnectionError:
    print("Error: ", sha256)

if 'data' in r:
    if r['data'][0]['sha1_hash'] and r['data'][0]['tlsh'] and r['data'][0]['signature'] and r['data'][0]['file_type']:
        line = (sha256 +","+  
                r['data'][0]['tlsh'] +","+ 
                r['data'][0]['signature'] +","+ 
                r['data'][0]['file_type']  
                )
        print(line)
