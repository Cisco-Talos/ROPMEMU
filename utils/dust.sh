# ROPMEMU framework
# 
# dust.sh embeds the extracted raw chain in a tiny ELF file
# Parameters: - $1: chain.bin  - the absolute path to the bin blob
#             - $2: tinyelf.c  - the name for the C program
#             - $3: outputname - the name of the final ELF file
#             - $4: dir        - the directory containing the final ELF
#

# Checks
if [ $# -ne "4" ]
then
    echo "Usage $0: <chain.bin> <tinyelf.c> <outputname> <dir>" 
    exit
fi

# Global vars
DIR=$4
FILE=$2
INPUT=$1
OUTPUT=$3
ROPMEMU="ropmemu"

if [ ! -d $DIR ]
then
    mkdir $DIR
fi

cd $DIR
touch $FILE

echo ":: Compiling $FILE"
echo -ne "#include <stdio.h>\nint main(){return 0;}" > $FILE
gcc -o $OUTPUT $FILE

oep=`readelf -S $OUTPUT 2>/dev/null | grep -i text | awk '{print $4}'`
echo ":: OEP: $oep" 

echo ":: Change .text section name"
objcopy --rename-section .text=$ROPMEMU $OUTPUT

echo ":: Feeding .text section"
objcopy --add-section .text=$1 --change-section-address .text="0x"$oep $OUTPUT 2>/dev/null

echo ":: Removing useless sections..."
for sname in `readelf -S $OUTPUT | grep -i "\." | cut -d "]" -f2 | cut -d " " -f2`
do
    if [ $sname == ".text" ]
    then 
        continue
    fi    
    objcopy --remove-section=$sname $OUTPUT 2>/dev/null
done

objcopy --remove-section=$ROPMEMU $OUTPUT 2>/dev/null

oep=`readelf -S $OUTPUT 2>/dev/null | grep -i text | awk '{print $5}'`
echo ":: OEP: $oep"

echo -ne ":: DONE\n\n"

