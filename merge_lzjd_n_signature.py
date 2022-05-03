#!/usr/bin/env python
import sys
inputf = sys.argv[1]   #input file contains lzjd 
outputf = sys.argv[2]  #ouput file contian sha, tlsh , signature, file_type, lzjd 

from malwarebazaar.api import Bazaar  #https://pypi.org/project/malwarebazaar/
bazaar = Bazaar("myapikey")
#bazaar.query_hash("16a33ff1076ad51388af14a2f735a4de0a205a6a2a658598e11225368d686c10")

records = []
with open( inputf ) as file:
    SDBFs = file.readlines()
      
header = 'sha256_hash,sha1_hash,tlsh,signature,file_type,lzjd\n'

with open( outputf , 'w') as filehandle:
    filehandle.write('%s' % header)
    for SDBF in SDBFs:
        sha256 = SDBF.split(":")[1].split(".")[-2][-64:]
        lzjd = SDBF.split(':')[2]
        try:
            res = bazaar.query_hash(sha256)
        except RemoteDisconnected:
            print("RemoteDisConnected of sha256 : ",sha256)
            pass 
        except requests.exceptions.ConnectionError:
            print("ConnectionError of sha256 : ",sha256)
            pass 
        except Exceptoin:
            print( "Exception of sha256 : ",sha256)
            pass 
            
        
        if 'data' not in res:
            print("Can't find sha256 : ",sha256)
            continue
        if res['data'][0]['sha1_hash'] and res['data'][0]['tlsh'] and res['data'][0]['signature'] and res['data'][0]['file_type']:
            line =   (sha256 + "," +
                        res['data'][0]['sha1_hash'] + "," +
                        res['data'][0]['tlsh'] + "," +\
                        res['data'][0]['signature'] + "," + 
                        res['data'][0]['file_type'] + "," + 
                        lzjd)
            filehandle.write('%s' % line)
            print(sha256)
