#!/usr/bin/env python3
#
# mftmactime.py
#
# (c) Authors: Miguel Quero & Javier Marin (Based in mft work of Omer BenAmram)
# (c) USN Authors: Adam Witt / Corey Forman <github.com/digitalsleuth>
# e-mail: motrilwireless@gmail.com
# company: Alpine Security
#
# ***************************************************************
#
# The license below covers all files distributed with infofile unless 
# otherwise noted in the file itself.
#
# This program is free software: you can redistribute it and/or 
# modify it under the terms of the GNU General Public License as 
# published by the Free Software Foundation, version 3.
# 
# This program is distributed in the hope that it will be useful, 
# but WITHOUT ANY WARRANTY; without even the implied warranty of 
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
# General Public License for more details.
# 
# You should have received a copy of the GNU General Public License 
# along with this program. If not, see <https://www.gnu.org/licenses/>. 
#
#

import argparse
import pytz
import os
import struct
import collections
import pytsk3
import platform
import yara

from mft import PyMftParser, PyMftAttributeX10, PyMftAttributeX30, PyMftAttributeX80
from operator import itemgetter
from tqdm import tqdm
from datetime import datetime
from os import path

UTC=pytz.UTC
BUFF_SIZE = 1024 * 1024
OS=platform.system()
VERSION="0.8.1"
YARA_VERSION=yara.__version__

########################### IMG SUPPORT ################################

def inode_seek_and_dump(imgfile, dump_path, offset, inode, filename):
    img = pytsk3.Img_Info(imgfile)
    fs = pytsk3.FS_Info(img, offset=offset)
    f = fs.open_meta(inode = inode)

    filesize = 0
    thisoffset = 0
    for i in f:
        if (i.info.type == pytsk3.TSK_FS_ATTR_TYPE_NTFS_DATA):
            thissize = i.info.size
            if thissize > filesize:
                filesize = thissize

    thisfile = "{}/{}".format(dump_path, filename)
    os.makedirs(os.path.dirname(thisfile), exist_ok=True)
    of = open(thisfile,"wb")
    pbar = tqdm(total = filesize,  desc = "  + DUMPING {}".format(filename))
    while thisoffset < filesize:
        available_to_read = min(BUFF_SIZE, filesize - thisoffset)
        data = f.read_random(thisoffset, available_to_read,1)
        if not data:
            break
        thisoffset += len(data)
        of.write(data)
        pbar.update(available_to_read)
    of.close()
    return thisfile

def check_file(file, offset):
    fl = open(file, 'rb')
    header = fl.read(5)
    if "FILE0" in str(header):
        fl.close()
        return "mft"

    fl.seek(offset + 3 , 0)
    header = fl.read(4)
    if "NTFS" in str(header):
        fl.close()
        return "ntfs"

    fl.close()
    return False

########################### USN SECTION ################################

reasons = collections.OrderedDict()
reasons[0x1] = 'DATA_OVERWRITE'
reasons[0x2] = 'DATA_EXTEND'
reasons[0x4] = 'DATA_TRUNCATION'
reasons[0x10] = 'NAMED_DATA_OVERWRITE'
reasons[0x20] = 'NAMED_DATA_EXTEND'
reasons[0x40] = 'NAMED_DATA_TRUNCATION'
reasons[0x100] = 'FILE_CREATE'
reasons[0x200] = 'FILE_DELETE'
reasons[0x400] = 'EA_CHANGE'
reasons[0x800] = 'SECURITY_CHANGE'
reasons[0x1000] = 'RENAME_OLD_NAME'
reasons[0x2000] = 'RENAME_NEW_NAME'
reasons[0x4000] = 'INDEXABLE_CHANGE'
reasons[0x8000] = 'BASIC_INFO_CHANGE'
reasons[0x10000] = 'HARD_LINK_CHANGE'
reasons[0x20000] = 'COMPRESSION_CHANGE'
reasons[0x40000] = 'ENCRYPTION_CHANGE'
reasons[0x80000] = 'OBJECT_ID_CHANGE'
reasons[0x100000] = 'REPARSE_POINT_CHANGE'
reasons[0x200000] = 'STREAM_CHANGE'
reasons[0x800000] = 'INTEGRITY_CHANGE'
reasons[0x00400000] = 'TRANSACTED_CHANGE'
reasons[0x80000000] = 'CLOSE'


attributes = collections.OrderedDict()
attributes[0x1] = 'READONLY'
attributes[0x2] = 'HIDDEN'
attributes[0x4] = 'SYSTEM'
attributes[0x10] = 'DIRECTORY'
attributes[0x20] = 'ARCHIVE'
attributes[0x40] = 'DEVICE'
attributes[0x80] = 'NORMAL'
attributes[0x100] = 'TEMPORARY'
attributes[0x200] = 'SPARSE_FILE'
attributes[0x400] = 'REPARSE_POINT'
attributes[0x800] = 'COMPRESSED'
attributes[0x1000] = 'OFFLINE'
attributes[0x2000] = 'NOT_CONTENT_INDEXED'
attributes[0x4000] = 'ENCRYPTED'
attributes[0x8000] = 'INTEGRITY_STREAM'
attributes[0x10000] = 'VIRTUAL'
attributes[0x20000] = 'NO_SCRUB_DATA'


sourceInfo = collections.OrderedDict()
sourceInfo[0x1] = 'DATA_MANAGEMENT'
sourceInfo[0x2] = 'AUXILIARY_DATA'
sourceInfo[0x4] = 'REPLICATION_MANAGEMENT'
sourceInfo[0x8] = 'CLIENT_REPLICATION_MANAGEMENT'

def parseUsn(infile, usn):
    recordProperties = [
        'majorVersion',
        'minorVersion',
        'fileReferenceNumber',
        'parentFileReferenceNumber',
        'usn',
        'timestamp',
        'reason',
        'sourceInfo',
        'securityId',
        'fileAttributes',
        'filenameLength',
        'filenameOffset'
    ]
    recordDict = dict(zip(recordProperties, usn))
    recordDict['filename'] = filenameHandler(infile, recordDict)
    recordDict['reason'] = convertAttributes(reasons, recordDict['reason'])
    recordDict['fileAttributes'] = convertAttributes(
        attributes, recordDict['fileAttributes'])
    recordDict['mftSeqNumber'], recordDict['mftEntryNumber'] = convertFileReference(
        recordDict['fileReferenceNumber'])
    recordDict['pMftSeqNumber'], recordDict['pMftEntryNumber'] = convertFileReference(
        recordDict['parentFileReferenceNumber'])
    reorder = [
        'filename',
        'timestamp',
        'usn',
        'fileReferenceNumber',
        'parentFileReferenceNumber',
        'reason',
        'fileAttributes',
        'mftSeqNumber',
        'mftEntryNumber',
        'pMftSeqNumber',
        'pMftEntryNumber',
        'filenameLength',
        'filenameOffset',
        'sourceInfo',
        'securityId',
        'majorVersion',
        'minorVersion'
    ]
    recordDict = {key: recordDict[key] for key in reorder}
    return recordDict

def findFirstRecord(infile):
    """
    Returns a pointer to the first USN record found
    Modified version of Dave Lassalle's 'parseusn.py'
    https://github.com/sans-dfir/sift-files/blob/master/scripts/parseusn.py
    """
    while True:
        data = infile.read(65536).lstrip(b'\x00')
        if data:
            return infile.tell() - len(data)


def findNextRecord(infile, journalSize):
    """
    There are runs of null bytes between USN records. I'm guessing
    this is done to ensure that journal records are cluster-aligned on disk.
    This function reads through these null bytes, returning an offset
    to the first byte of the the next USN record.
    """
    while True:
        try:
            recordLength = struct.unpack_from('<I', infile.read(4))[0]
            if recordLength:
                infile.seek(-4, 1)
                return infile.tell() + recordLength
        except struct.error:
            if infile.tell() >= journalSize:
                break


def convertFileReference(buf):
    """
    Read, store, unpack, and return FileReference
    """
    b = memoryview(bytearray(struct.pack("<Q", buf)))
    seq = struct.unpack_from("<h", b[6:8])[0]

    b = memoryview(bytearray(b[0:6]))
    byteString = ''

    for i in b[::-1]:
        byteString += format(i, 'x')
    entry = int(byteString, 16)

    return seq, entry


def filenameHandler(infile, recordDict):
    """
    Read and return filename
    """
    try:
        filename = struct.unpack_from('<{}s'.format(
            recordDict['filenameLength']), infile.read(recordDict['filenameLength']))[0]
        return filename.decode('utf16')
    except struct.error:
        return ''


def convertAttributes(attributeType, data):
    """
    Identify attributes and return list
    """
    attributeList = [attributeType[i] for i in attributeType if i & data]
    return ' '.join(attributeList)


########################### MFT SECTION ################################

def generator():
    while True:
      yield

def join_mft_datetime_attributes(old_entry, value_to_add):
    mask = "macb"
    value_pos = mask.find(value_to_add)
    new_entry = old_entry[:value_pos] + value_to_add + old_entry[value_pos+1:]
    return new_entry

def save_mft_to_file(mft, output_path, timezone):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("Date,Size,Type,Mode,UID,GID,Meta,File Name\n")
        for entry in mft:
            fflag = ""
            ftype = "r/rrwxrwxrwx" #TODO
            if "DIRECTORY" in entry["ftype"]:
                ftype = "d/drwxrwxrwx" #TODO
            else:
                ftype = "-/-rwxrwxrwx" #TODO

            if timezone:
                thistz = pytz.timezone(timezone) 
                formatted_date = entry["date"].replace(tzinfo=pytz.utc).astimezone(thistz).strftime("%a %b %d %Y %H:%M:%S (%Z)")
            else:
                formatted_date = entry["date"].strftime("%a %b %d %Y %H:%M:%S (%Z)")

            if "ALLOCATED" in entry["flags"]:
                fflag = ""
            elif "USN" in entry["flags"]:
                fflag = entry["flags"]
            else:
                fflag = "(deleted)"
            f.write("{},{},{},{},{},{},{},{} {}\n".format(formatted_date, entry["file_size"], entry["date_flags"], ftype, 0, 0, entry["inode"], entry["full_path"], fflag))

def dump_resident_file(resident_path, full_path, data):
    try:
        filename = "{}/{}".format(resident_path, full_path)
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "wb") as rf:
            rf.write(data)
    except:
        return

def mft_parser(mftfile, mftout, drive_letter, file_name, timezone, resident_path, usnfile, offset, dump_path, yara_rules, resident_yara_path):
    mft = list()
    fpath = dict()
    adsres = list()
    adsnores = dict()
    totalres = 0
    totaldel = 0
    totalyar = 0
    usninode = None

    if resident_path or resident_yara_path:
        if resident_path:
            report_file = "{}/resident_summary.txt".format(resident_path)
        else:
            report_file = "{}/resident_summary.txt".format(resident_yara_path)

        os.makedirs(os.path.dirname(report_file), exist_ok=True)
        with open(report_file, "w") as r:
            r.write("STATUS, FILE PATH\n")

    parser = PyMftParser(mftfile)
    for file_record in tqdm(parser.entries(), desc = "  + PARSING MFT"):
        if isinstance(file_record, RuntimeError):
            continue

        ftypex10 = ""
        ftypex30 = ""
        resident = False
        asndate = None
        yara_match = None
        rdeleted = "ALLOCATED"
        mft_entryx10 = dict()
        mft_entryx30 = dict()
        adsres.clear()

        # PATHs Conversions
        if OS == "Windows":
            thisfullpath = "{}:\{}".format(drive_letter, file_record.full_path)
        else:
            thisfullpath = "{}:/{}".format(drive_letter, file_record.full_path)

        for attribute_record in file_record.attributes():

            if isinstance(attribute_record, RuntimeError):
                continue

            resident = attribute_record.is_resident

            if attribute_record.name and attribute_record.type_name == "DATA" and attribute_record.data_size > 0:
                if file_record.base_entry_id > 0 and file_record.file_size > 0:
                    adsnores[file_record.base_entry_id] = [attribute_record.name, file_record.file_size]
                elif file_record.base_entry_id > 0 and file_record.base_entry_id not in adsnores:
                    adsnores[file_record.base_entry_id] = [attribute_record.name, attribute_record.data_size]
                else:
                    adsres.append([attribute_record.name, attribute_record.data_size])

            attribute_data = attribute_record.attribute_content
            if attribute_data:
                if isinstance(attribute_data, PyMftAttributeX10):
                    if attribute_data.modified not in mft_entryx10:
                        mft_entryx10[attribute_data.modified] = "m..."
                    else:
                        mft_entryx10[attribute_data.modified] = join_mft_datetime_attributes(mft_entryx10[attribute_data.modified], 'm')
                    if attribute_data.accessed not in mft_entryx10:
                        mft_entryx10[attribute_data.accessed] = ".a.."
                    else:
                        mft_entryx10[attribute_data.accessed] = join_mft_datetime_attributes(mft_entryx10[attribute_data.accessed], 'a')
                    if attribute_data.mft_modified not in mft_entryx10:
                        mft_entryx10[attribute_data.mft_modified] = "..c."
                    else:
                        mft_entryx10[attribute_data.mft_modified] = join_mft_datetime_attributes(mft_entryx10[attribute_data.mft_modified], 'c')
                    if attribute_data.created not in mft_entryx10:
                        mft_entryx10[attribute_data.created] = "...b"
                    else:
                        mft_entryx10[attribute_data.created] = join_mft_datetime_attributes(mft_entryx10[attribute_data.created], 'b')
                    ftypex10 = attribute_data.file_flags
                    asndate = attribute_data.accessed

                if file_name:
                    if isinstance(attribute_data, PyMftAttributeX30):
                        if attribute_data.modified not in mft_entryx30:
                            mft_entryx30[attribute_data.modified] = "m..."
                        else:
                            mft_entryx30[attribute_data.modified] = join_mft_datetime_attributes(mft_entryx30[attribute_data.modified], 'm')
                        if attribute_data.accessed not in mft_entryx30:
                            mft_entryx30[attribute_data.accessed] = ".a.."
                        else:
                            mft_entryx30[attribute_data.accessed] = join_mft_datetime_attributes(mft_entryx30[attribute_data.accessed], 'a')
                        if attribute_data.mft_modified not in mft_entryx30:
                            mft_entryx30[attribute_data.mft_modified] = "..c."
                        else:
                            mft_entryx30[attribute_data.mft_modified] = join_mft_datetime_attributes(mft_entryx30[attribute_data.mft_modified], 'c')
                        if attribute_data.created not in mft_entryx30:
                            mft_entryx30[attribute_data.created] = "...b"
                        else:
                            mft_entryx30[attribute_data.created] = join_mft_datetime_attributes(mft_entryx30[attribute_data.created], 'b')
                        ftypex30 = attribute_data.flags

                if resident and (resident_path or resident_yara_path or yara_rules):
                    if isinstance(attribute_data, PyMftAttributeX80) and ftypex10:
                        if file_record.file_size != 0:
                            if yara_rules:
                                yara_match = yara_rules.match(data=attribute_data.data)
                                if yara_match:
                                    print("\n    - YARA MATCHED: {} RESIDENT FILE: {}".format(yara_match, file_record.full_path))
                                    totalyar +=1
                            if resident_path or resident_yara_path:
                                if "ALLOCATED" not in file_record.flags:
                                    rdeleted = "DELETED"
                                resident_fullpath = file_record.full_path
                                if  attribute_record.name and attribute_record.type_name == "DATA": 
                                    resident_fullpath = "{}:{}".format(file_record.full_path, attribute_record.name)
                                if resident_path:
                                    dump_resident_file(resident_path, resident_fullpath, attribute_data.data)
                                    totalres += 1
                                    if rdeleted == "DELETED":
                                        totaldel += 1
                                elif yara_match and resident_yara_path:
                                    dump_resident_file(resident_yara_path, resident_fullpath, attribute_data.data)
                                    totalres += 1
                                    if rdeleted == "DELETED":
                                        totaldel += 1                              
                                

                                with open(report_file, "a") as r:
                                    if yara_match:
                                        r.write("{},{},YARA MATCHED: {}\n".format(rdeleted, resident_fullpath, yara_match))
                                    elif resident_path:
                                        r.write("{},{}\n".format(rdeleted, resident_fullpath))

        # Store inode path reference
        if asndate:
            fpath[file_record.entry_id] = [thisfullpath, file_record.file_size, asndate]

        for entry in mft_entryx10:
            if usnfile:
                if OS == "Windows" and ":\$Extend\$UsnJrnl" in thisfullpath and int(file_record.file_size) > BUFF_SIZE :
                    usninode = file_record.entry_id
                elif ":/$Extend/$UsnJrnl" in thisfullpath and int(file_record.file_size) > BUFF_SIZE :
                    usninode = file_record.entry_id

            mft.append({
                "file_size": file_record.file_size,
                "full_path": thisfullpath,
                "inode": file_record.entry_id,
                "flags": file_record.flags,
                "date": entry,
                "date_flags": mft_entryx10[entry],
                "ftype": ftypex10
                
            })

            # ADS Support
            if adsres:
                for adsr in adsres:
                    thisfulladspath = "{}:{}".format(thisfullpath, adsr[0])
                    mft.append({
                        "file_size": adsr[1],
                        "full_path": thisfulladspath,
                        "inode": file_record.entry_id,
                        "flags": file_record.flags,
                        "date": entry,
                        "date_flags": mft_entryx10[entry],
                        "ftype": ftypex10
                    })
            if file_record.entry_id in adsnores:
                thisfulladspath = "{}:{}".format(thisfullpath, adsnores[file_record.entry_id][0])
                mft.append({
                    "file_size": adsnores[file_record.entry_id][1],
                    "full_path": thisfulladspath,
                    "inode": file_record.entry_id,
                    "flags": file_record.flags,
                    "date": entry,
                    "date_flags": mft_entryx10[entry],
                    "ftype": ftypex10
                })
                del adsnores[file_record.entry_id]


        if file_name:
            for entry in mft_entryx30:
                mft.append({
                    "file_size": file_record.file_size,
                    "full_path": "{} ($FILE_NAME)".format(thisfullpath),
                    "inode": file_record.entry_id,
                    "flags": file_record.flags,
                    "date": entry,
                    "date_flags": mft_entryx30[entry],
                    "ftype": ftypex30
            })

    for adsnr in adsnores:
        if adsnr in fpath:
            thisfulladspath = "{}:{}".format(fpath[adsnr][0], adsnores[adsnr][0])
            #if usnfile:
            #    if OS == "Windows" and ":\$Extend\$UsnJrnl:$J" in thisfulladspath and int(adsnores[adsnr][1]) > BUFF_SIZE :
            #        usninode = adsnr
            #    elif ":/$Extend/$UsnJrnl:$J" in thisfulladspath and int(adsnores[adsnr][1]) > BUFF_SIZE :
            #        usninode = adsnr
            mft.append({
                "file_size": adsnores[adsnr][1],
                "full_path": thisfulladspath,
                "inode": adsnr,
                "flags": "ALLOCATED",
                "date": fpath[adsnr][2],
                "date_flags": "....",
                "ftype": ""
            })


    if usnfile:
        skip = False
        check = check_file(usnfile, offset)
        if check == "ntfs":
            if not dump_path:
                print ('  + Dump path is required for dump USN Journal. Skipping')
                skip = True
            elif not usninode:
                print ('  + USN Jornal not found. Skipping')
                skip = True
            else:
                usnfile = inode_seek_and_dump(usnfile, dump_path, offset, usninode, "UsnJrnl") 

        if not skip:
            journalSize = os.path.getsize(usnfile)
            with open(usnfile, 'rb') as i:
                i.seek(findFirstRecord(i))
                for _ in tqdm(generator(), desc = "  + PARSING USN"):
                    try:
                        nextRecord = findNextRecord(i, journalSize)
                        recordLength = struct.unpack_from('<I', i.read(4))[0]
                        recordData = struct.unpack_from('<2H4Q4I2H', i.read(56))
                        usn = parseUsn(i, recordData)
                        if usn['mftEntryNumber'] in fpath:
                            thisfullpath = fpath[usn['mftEntryNumber']][0]
                        else:
                            thisfullpath =  usn['filename']
                        thisfilename = os.path.basename(thisfullpath)
                        if usn['filename'] not in thisfilename:
                            thisfullpath = usn['filename']
                        mft.append({
                            "file_size": fpath[usn['mftEntryNumber']][1],
                            "full_path": thisfullpath,
                            "inode": usn['mftEntryNumber'],
                            "flags": "(USN: {})".format(usn['reason']),
                            "date": UTC.localize(datetime.fromtimestamp(float(usn['timestamp']) * 1e-7 - 11644473600)),
                            "date_flags": "....",
                            "ftype": usn['fileAttributes']
                        })
                        i.seek(nextRecord)
                    except:
                        break

    print("  + GENERATING TIMELINE ...")          
    mft_ordered_by_date = sorted(mft, key=itemgetter("date"))
    save_mft_to_file(mft_ordered_by_date, mftout, timezone)

    if yara_rules:
        print ("  + TOTAL YARA MACHED: {}".format(totalyar))

    if resident_path or resident_yara_path:
        print ("  + TOTAL RESIDENT RECOVERED: {}".format(totalres))
        print ("  + TOTAL DELETED RESIDENT RECOVERED: {}".format(totaldel))
        print ("  + RECOVERY REPORT FILE: {}".format(report_file))


def get_args():
    argparser = argparse.ArgumentParser(
        description='Utility to create a mactime format filesystem timeline from MFT')

    argparser.add_argument('-V', '--version',
                            action='version', 
                            version='%(prog)s {} (LIBS: yara {})'.format(VERSION, YARA_VERSION))

    argparser.add_argument('-f', '--file',
                           required=True,
                           action='store',
                           help='MFT artifact path or RAW Evidente(require --dump-path)')

    argparser.add_argument('-o', '--output',
                           required=True,
                           action='store',
                           help='Output file: Ex: mft.csv')

    argparser.add_argument('-m', '--drive',
                           required=False,
                           default='C',
                           action='store',
                           help='Drive letter: Ex: C')

    argparser.add_argument('-n', '--filenameattr',
                           required=False,
                           action='store_true',
                           help='Extract X30 Attributes file_name too.')

    argparser.add_argument('-tz', '--timezone',
                           required=False,
                           action='store',
                           help='The timezone of the collected MFT (UTC Default): Ex: Europe/Madrid')

    argparser.add_argument('-r', '--resident',
                           required=False,
                           action='store',
                           help='Output path for dump MFT resident data')

    argparser.add_argument('-u', '--usn',
                           required=False,
                           action='store',
                           help='USN Journal path or RAW Evidente(require --dump-path)')

    argparser.add_argument('-s', '--offset',
                           required=False,
                           action='store',
                           default=0,
                           help='Filesystem offset in RAW evidence. Default: 0')
    
    argparser.add_argument('-d', '--dump_path',
                        required=False,
                        action='store',
                        help='Dump path to allocate MFT and USN files')

    argparser.add_argument('-y', '--yara_rules',
                        required=False,
                        action='store',
                        help='Process yara rules in resident data')

    argparser.add_argument('-yc', '--yara_compiled',
                        required=False,
                        action='store',
                        help='Process compiled yara rules in resident data')

    argparser.add_argument('-ry', '--resident_yara',
                        required=False,
                        action='store',
                        help='Output path for dump only MFT resident files with yara matched '
                             'rules (not needed if -r is used )')

    args = argparser.parse_args()

    return args


def main():

    args = get_args()
    inputfile = args.file
    offset = int(args.offset)
    dump_path = args.dump_path
    inputusn = args.usn

    if not path.exists(inputfile):
        print('+ No input file')
        return 1

    # CHECK MFT INPUT
    check = check_file(inputfile, offset)
    if not check:
        print('+ Input file not supported')
        return 1
    elif check == "ntfs":
        print("- RAW Evidence Detected")
        if not dump_path:
            print('+ Dump path is required for RAW Evidence')
            return 1
        mftfile = inode_seek_and_dump(inputfile, dump_path, offset, 0, "MFT")
    else:
        print("- MFT FILE Detected")
        mftfile = inputfile

    timezone = args.timezone
    if timezone and timezone not in pytz.all_timezones:
        print('+ Invalid timezone string!')
        return 1
    
    mftout = args.output
    drive_letter = args.drive
    file_name = args.filenameattr
    resident_path = args.resident
    yara_rules_path = args.yara_rules
    yara_compiled_path = args.yara_compiled
    resident_yara_path = args.resident_yara

    yara_rules = None
    if yara_rules_path:
        if path.exists(yara_rules_path):
            try:
                yara_rules = yara.compile(yara_rules_path)
            except Exception as e:
                print('+ Yara error: {}'.format(e))
                return 1
        else:
            print('+ Invalid yara rules path')
            return 1
    elif yara_compiled_path:
        if path.exists(yara_compiled_path):
            try:
                yara_rules = yara.load(yara_compiled_path)
            except Exception as e:
                print('+ Yara error: {}'.format(e))
                return 1   
        else:
            print('+ Invalid yara rules path')
            return 1

    mft_parser(mftfile, mftout, drive_letter, file_name, timezone, resident_path, inputusn,
               offset, dump_path, yara_rules, resident_yara_path)


# *** MAIN LOOP ***
if __name__ == '__main__':
    main()