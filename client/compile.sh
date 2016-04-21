#!/bin/bash
date_format="%a %b %d %H:%M:%S %Y"

MAIN_CLASS="MultiPlayClient"
PROGRAM_NAME="$MAIN_CLASS.java"
cd src
javac $PROGRAM_NAME

if [ $? -eq 0 ]
then
    now=`date +"$date_format"`
    printf "\033[1;36m%s\033[0m :: %s compiled.\n" "$now" "$PROGRAM_NAME"
else
    exit
fi

mv *.class ..
cd ..
printf "Main-Class: $MAIN_CLASS\n" >MANIFEST
jar cvfm "mpc.jar" MANIFEST *.class > /dev/null
rm MANIFEST
rm *.class

