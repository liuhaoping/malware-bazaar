#!/bin/bash

# Goal : Download samples, generate lzjd_hash and merge signatures, tlsh, etc. to a csv file
#
# input_folder : location of binary malware files 
# output_file: malware_bazaar.lzjd.csv
# putput-fle example:
# sha_256,sha1_hash,tlsh,signature,file_type,lzjd
#
# command example : 
# $ ./run_gen_lzjd_n_signatures.sh ~/data/mb_binarys_2022/ mb2022.lzjd.csv
###

input_folder=${1%}
output_file=${2%}

# generate SBDFs from input folder 
# git clone jLZJD on upper level folder : https://github.com/EdwardRaff/jLZJD 
java -cp ../jLZJD/target/jLZJD-1.0-SNAPSHOT-jar-with-dependencies.jar com.edwardraff.jlzjd.Main -r ${input_folder} -o  ${output_file}.lzjd.tmp

# generate sha256,tlsh,lzjd list into csv file
python lib/merge_lzjd_n_signature.py ${output_file}.lzjd.tmp ${output_file}.lzjd.signature.tmp

# calcuate entropy
while read -r line; do echo -n $line","; python lib/calc_entropy.py $input_folder/$line.* ; done < <(cut -d, -f 1 ${output_file}.lzjd.signature.tmp | sed '1d' ) > ${output_file}.ent.tmp

sed -i '1i sha256_hash,entropy' ${output_file}.ent.tmp

# join files
csvjoin -c sha256_hash ${output_file}.lzjd.signature.tmp ${output_file}.ent.tmp > ${output_file}

# Remove tmp files
#rm *.tmp



























