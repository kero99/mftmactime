# Description
This is an MFT and USN parser that allows direct extraction in filesystem timeline format (mactime).
It uses Omer BenAmram's (https://github.com/omerbenamram/mft) great MFT rust parsing libraries, which allows a great speed and efficiency in the process.
The integration with the USN Journal parser allows to have in the same timeline the combined MFT and USN data. You can use as input files either individual files derived from a triage or a forensic image in RAW format or a mixture of both modes. In case the input is RAW the artifacts will be dumped in a selected directory.

# Requirement
pip install mft argparse tqdm pytz pytsk3

# Use
usage: mftmactime.py [-h] -f FILE -o OUTPUT [-m DRIVE] [-n] [-tz TIMEZONE] [-r RESIDENT] [-u USN] [-d DUMP]
                        
# Example
mftmactime.py -f /mnt/comp001/\\$MFT -o comp001_fstl.csv -n

![image](https://user-images.githubusercontent.com/143736/183637088-0089c8c4-ef23-46e1-bbd5-8321422108cb.png)

# Example with dump resident files
mftmactime -f MFT -o test.csv -n -r recovery_output

![Screenshot at 2022-09-07 11-29-48](https://user-images.githubusercontent.com/143736/188844076-9eefc9b7-9801-4c23-a0df-0ef794b92dc1.png)

# Example of inode entries with USN Journal and MFT mixed data

![image](https://user-images.githubusercontent.com/143736/191730418-ba1f5a8d-2ff0-4e88-aa30-236c5169e580.png)

# Example of dump and process from RAW Evidence
mftmactime -n -f ../evidence/Testing/test-img.dd -u ../evidence/Testing/test-img.dd -o ./filesystem_tln.csv -d dump -r resindents

![image](https://user-images.githubusercontent.com/143736/191998130-097e69ea-80dc-4684-80ba-d4dfbe861452.png)


