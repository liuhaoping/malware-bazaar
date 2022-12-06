cd ~/mb_data/$1   #$1 = mb2205

for i in $(seq -f "%02g" 1 31 ); do wget https://datalake.abuse.ch/malware-bazaar/daily/2022-05-$i.zip ; unzip -P infected 2022-05-$i.zip; done

mkdir -p ../nonexe/$1

find . -not -path "." -not -name "*.exe" -not -name "*.dll" -exec mv {} ../nonexe/$1 \;)

