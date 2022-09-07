# Description
This is an MFT parser that allows direct extraction in filesystem timeline format (mactime).
It uses Omer BenAmram's (https://github.com/omerbenamram/mft) great MFT rust parsing libraries, which allows a great speed and efficiency in the process.

# Requirement
pip install mft argparse tqdm pytz

# Use
usage: mftmactime.py [-h] -f FILE -o OUTPUT [-m DRIVE] [-n] [-tz TIMEZONE] [-r RESIDENT] 
                        
# Example
mftmactime.py -f /mnt/comp001/\\$MFT -o comp001_fstl.csv -n

![image](https://user-images.githubusercontent.com/143736/183637088-0089c8c4-ef23-46e1-bbd5-8321422108cb.png)

#Example with dump resident files
mftmactime -f MFT -o test.csv -n -r recovery_output

![Screenshot at 2022-09-07 11-29-48](https://user-images.githubusercontent.com/143736/188844076-9eefc9b7-9801-4c23-a0df-0ef794b92dc1.png)
