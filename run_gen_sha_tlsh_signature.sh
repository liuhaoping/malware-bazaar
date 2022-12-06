
input_folder=$1 #../mbdata/mb2205/001*
output_csv=$2   #mb2205.sig.tmp 

echo "sha256,tlsh,signature" > $output_csv

#bazaar init myapikey

for file in "$input_folder"/*; do 
    
    sha256=`echo $file | sed 's#.*/##' | cut -d. -f 1 `

    #Python:
    python lib/mb_query_hash.py $sha256
    
    #CLI:
    #bazaar query hash $sha256  > /tmp/bazzar
    
    #sha1=`./lib/keytojson.sh /tmp/bazzar | jq -r '.SHA1'`

    #Signature=`./lib/keytojson.sh /tmp/bazzar | jq -r '.Signature'`

    #echo "${sha256},${sha1},${Signature}" 
done >> "$output_csv"
