# Description
This is an MFT parser that allows direct extraction in filesystem timeline format (mactime).
It uses Omer BenAmram's (https://github.com/omerbenamram/mft) great MFT rust parsing libraries, which allows a great speed and efficiency in the process.

# Requirement
pip install mft argparse tqdm

# Use
usage: mftmactime.py [-h] -f FILE -o OUTPUT [-m DRIVE] [-n] [-tz TIMEZONE]
                        
# Example
mftmactime.py -f /mnt/comp001/\\$MFT -o comp001_fstl.csv

![image](https://user-images.githubusercontent.com/143736/183637088-0089c8c4-ef23-46e1-bbd5-8321422108cb.png)


