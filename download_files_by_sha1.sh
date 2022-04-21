#!/bin/bash

# Goal : Download samples and put under download folder
#
# input : malware_bazaar.csv
# example:
# sha1_hash,tlsh,signature
# 003411d0a9610cfe8a027a364b46c489fa034502,AF74AD89B6257A65DE3A727411C78FC1B994D007602253AFE040F397BC17BEA3E7A1E4,Quakbot
#
# output: ./download/*.* 
###

input=${1%}

# cut sha1 field
cd ~/malware-bazaar/
cut -d, -f 1 ${input} | tail -n +2 > ${input}.sha1.tmp

# get sha256 values
while read -r line; do python bazaar_get_info.py -s $line -f sha256_hash; done < ${input}.sha1.tmp  >> ${input}.sha256.tmp

# downlaod file by given sha256
while read -r line; do python bazaar_download.py -s $line -u; done < ${input}.sha256.tmp

rm *.tmp























