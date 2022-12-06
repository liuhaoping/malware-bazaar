#!/bin/bash


while read -r line; do echo -n $line","; python lib/calc_entropy.py ../mb220419/$line.* ; done < <(cut -d, -f 1 mb220419-top40.csv | sed '1d' ) > mb220419-top40.ent

sed -i '1i sha256_hash,entropy' mb220419-top40.ent

csvjoin -c sha256_hash mb220419-top40.csv mb220419-top40.ent > mb220419-top40.csv.t
