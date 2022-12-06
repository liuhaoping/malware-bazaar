# gen-fuzzyhash
Genearte sha256, tlsh, lzjd, signature, entropy into a csv file

## Step 1 : Download binary malware sample  
```
# Option1 : download daily binary malware samples (ZIP password: infected))
$ wget https://datalake.abuse.ch/malware-bazaar/daily/2020-03-14.zip

# Optino2 : Batch
cd {data_folder}
for i in $(seq -f "%02g" 1 31 ); do wget https://datalake.abuse.ch/malware-bazaar/daily/2022-05-$i.zip ; unzip -P infected 2022-05-$i.zip; done)

# Option 3 : download by given a csv file that contains a sha1 field
$ ./download_files_by_sha1.sh malware_baazar.csv
```

## Step 2 : Generate lzjd values and concate meta data
Concate lzjd with sha256, sha1, tlsh, signature, file_type, entropy into a csv file
```
$./run_gen_lzjd_n_signatures.sh ~/data/2204/ mb2204.csv
```
## Step 3 : Filter data
show column names for csv file
```
$csvcut -n mb2204.csv
  1: sha256_hash
  2: sha1_hash
  3: tlsh
  4: signature
  5: file_type
  6: lzjd
```
Insert csv file into db and filter data by sql2csv
```
$csvsql --db sqlite:///mb2204.db --insert mb2204.csv

$sql2csv --db sqlite:///mb2204.db --query "select a.* from mb2204 a, (select signature, count(*) as cnt from mb2204 group by signature order by cnt desc limit 40) b where a.signature = b.signature and a.file_type != 'elf'" > mb2204-top40.csv
```
List top values
```
$csvcut -c 4 mb2204-top40.csv | csvstat
  1. "signature"

        Type of data:          Text
        Contains null values:  False
        Unique values:         37
        Longest value:         14 characters
        Most common values:    Formbook (746x)
                               AgentTesla (713x)
                               Heodo (498x)
                               RedLineStealer (344x)
                               Loki (336x)

Row count: 4286

$csvcut -c 5 mb2204-top40.csv | csvstat
  1. "file_type"

        Type of data:          Text
        Contains null values:  False
        Unique values:         36
        Longest value:         7 characters
        Most common values:    exe (2861x)
                               dll (579x)
                               xlsx (298x)
                               zip (129x)
                               rar (60x)

Row count: 4286
```
## Reference 
### Python Library - malwarebazaar 
https://pypi.org/project/malwarebazaar/
- Python 
```
from malwarebazaar.api import Bazaar

bazaar = Bazaar("myapikey")
response = bazaar.query_hash("Hash to search for.")
file = bazaar.download_file("Sha256 hash for file to donwload.")
```
- CLI
```
$ bazaar init myapikey
Successfully set API-Key!
$ bazaar query hash f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
Filename:       03891ab57eb301579005f62953dfd21e.exe
MD5:            03891ab57eb301579005f62953dfd21e
SHA1:           41efd56ea49b72c6dd53b5341f295e549b1b64a5
SHA256:         f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
Imphash:        f34d5f2d4577ed6d9ceec516c1f5a744
Signature:      RedLineStealer
Tags:           exe, RedLineStealer
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.zip: Zip archive data, at least v5.1 to extract
$ bazaar download f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807 --unzip
$ file f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe 
f670080b1f42d1b70a37adda924976e6d7bd62bf77c35263aff97e7968291807.exe: PE32 executable (GUI) Intel 80386 Mono/.Net assembly, for MS Windows)
```

### Malware Bazaar API Reference
https://bazaar.abuse.ch/api/

- Query a malware sample (hash)
> You can check if a particular malware sample is known to MalwareBazaar by query the API for the corresponding hash
```
wget --post-data "query=get_info&hash=7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754" https://mb-api.abuse.ch/api/v1/
```
- Query Signature
https://bazaar.abuse.ch/api/#siginfo 
> get a list of recent malware samples (max 1'000) associated with a specific signature 
```
wget --post-data "query=get_siginfo&signature=TrickBot&limit=5" https://mb-api.abuse.ch/api/v1/
```
- Query TLSH 
https://bazaar.abuse.ch/api/#tlsh
> You can get a list of malware samples (max 1'000) associated with a specific TLSH hash)
```
wget --post-data "query=get_tlsh&tlsh=4FB44AC6A19643BBEE8766FF358AC55DBC13D91C1B4DB4FBC789AA020A31B05ED12350&limit=50" https://mb-api.abuse.ch/api/v1/
```
- Query YARA rule
https://bazaar.abuse.ch/api/#yararule
> You can get a list of malware samples (max 1'000) associated with a specific YARA rule
```
wget --post-data "query=get_yarainfo&yara_rule=win_remcos_g0&limit=50" https://mb-api.abuse.ch/api/v1/
```
###  malbazaar_query 
https://gist.github.com/n3l5/1a06fe180733a5df82ae392c2db4e52d
```
python  malbazaar_query.py --hash 063c4ae42d64081d50fecb5ee3d0f5ed835c8351964e32ae2bc222172d7e0b3c

buseCH Malware Bazaar Info for the HASH: 063c4ae42d64081d50fecb5ee3d0f5ed835c8351964e32ae2bc222172d7e0b3c
##########################################################################################################


###############<<<  File Info  >>>###############
#################################################

Filename: JR_FHM_DAB7400006479004597_147-637593641117581330.exe

MIME File Type: application/x-dosexec
     File Type: exe

     First Seen: 2022-03-15 19:23:55
      Last Seen: 2022-03-21 12:44:52

      Signature: SnakeKeylogger

      Tags: ['exe', 'snakekeylogger']


      ###############<<<  YARA rule information  >>>###############
      #############################################################

      YARA Rule name: pe_imphash
      YARA Description:


      YARA Rule name: Skystars_Malware_Imphash
      YARA Description: imphash


      ###############<<<  File HASH information  >>>###############
      #############################################################

         MD5 hash: 1198534eff0ca700ece37457ad5e2b2d
           SHA1 hash: 728daf9d3a51c5382e24fbe3bef9e2c350062193
           SHA256 hash: 063c4ae42d64081d50fecb5ee3d0f5ed835c8351964e32ae2bc222172d7e0b3c

               IMPHASH: f34d5f2d4577ed6d9ceec516c1f5a744

                    SSDEEP: 12288:xeAASEiEb4kwOEocElaAk1EVtAgpbfyfcjvdQAtHdgvDdJUCXdwRwChZal2iBW2P:itzrwOCAsib6fcdQa9GIsdl


                    ###############<<<  File Intelligence information  >>>###############
                    #####################################################################

                    Delivery method: email_attachment

                    Intelligence: ['SecuriteInfo.com.W32.MSIL_Troj.BZN.genEldorado.4728.4428.UNOFFICIAL']


                    ###############<<<  REVERSINGLABS info  >>>###############
                    ##########################################################
                    ReversingLabs verdict: MALICIOUS
                    ReversingLabs threatname: ByteCode-MSIL.Trojan.SnakeKeylogger
                    ReversingLabs firstseen: 2022-03-15 19:24:18


                    ###############<<<  ANY.RUN info  >>>###############
                    ####################################################
                    ANY.RUN verdict: Malicious activity
                    ANY.RUN firstseen: 2022-03-15 23:13:25
                    ANY.RUN Analysis URL: https://app.any.run/tasks/48b28602-5640-465e-858f-3a023f0d48ae


                    ###############<<<  HatchingTriage info  >>>###############
                    ###########################################################
                    Hatching Triage verdict: 10
                    Hatching Triage Malware family: snakekeylogger
                    Hatching Triage tags: ['family:snakekeylogger', 'collection', 'keylogger', 'spyware', 'stealer']
                    Hatching Triage Analysis URL: https://tria.ge/reports/220315-x4ehesddfl/


                    ##################<<<  Unpac Me info  >>>##################
                    ###########################################################

                       MD5 hash: 9ac16a9924c8c6ec82b1eafd45088692
                       SHA256 hash: 115fc98f6db14129e62b320c8569269d62fad7ae20c30ff38e70a9392401ad11
                       Link: https://www.unpac.me/results/5c0c0813-be82-471c-a7eb-11671c019b51/
                       Detections: []

                          MD5 hash: fc6d91ff314356715f5c76ba61240c9f
                          SHA256 hash: 4ffb59b76867dc3ee5df8b1476a82043c8bbfa9679aa90a2e4b937292b3722b8
                          Link: https://www.unpac.me/results/5c0c0813-be82-471c-a7eb-11671c019b51/
                          Detections: []

                             MD5 hash: 2b519046f04b621efa422a6a5c393d89
                             SHA256 hash: 436a7625795d32d3dfaf840af5d97487c359ffc5f7a6e7eb5b5a218dea6fb1ac
                             Link: https://www.unpac.me/results/5c0c0813-be82-471c-a7eb-11671c019b51/
                             Detections: []

                                MD5 hash: 4a2e46ca76edc18eefc42457d0483fb8
                                SHA256 hash: 6fd8a39e9c6ab8d2d667efad7a7f40a2f9ee0659286e6d2804c7f7e05913d624
                                Link: https://www.unpac.me/results/5c0c0813-be82-471c-a7eb-11671c019b51/
                                Detections: []

                                   MD5 hash: 1198534eff0ca700ece37457ad5e2b2d
                                   SHA256 hash: 063c4ae42d64081d50fecb5ee3d0f5ed835c8351964e32ae2bc222172d7e0b3c
                                   Link: https://www.unpac.me/results/5c0c0813-be82-471c-a7eb-11671c019b51/
                                   Detections: []

                                   ###############<<<  AbuseCH Malware Bazaar info  >>>###############
                                   ###################################################################

                                   AbuseCH Malware Bazaar page:
                                   https://bazaar.abuse.ch/sample/063c4ae42d64081d50fecb5ee3d0f5ed835c8351964e32ae2bc222172d7e0b3c]
 ```
