#!/bin/bash
# sarav (hello@grity.com)
# convert key=value to json
# Created at Gritfy ( Devops Junction )
# https://www.middlewareinventory.com/blog/convert-keyvalue-pair-into-json/

file_name=$1
last_line=$(wc -l < $file_name)
current_line=0
echo "{"
while read line
do
    current_line=$(($current_line + 1))
    if [[ $current_line -ne $last_line ]]; then
    [ -z "$line" ] && continue
        echo $line|awk -F':'  '{ print " \""$1"\" : \""$2"\","}'|grep -iv '\"#' |  sed 's/ //g'
    else
        echo $line|awk -F':'  '{ print " \""$1"\" : \""$2"\""}'|grep -iv '\"#' |  sed 's/ //g'
    fi
done < $file_name
echo "}"
