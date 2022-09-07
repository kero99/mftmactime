#!/usr/bin/env python3
#*
# mftmactime.py
#
# (c) Authors: Miguel Quero & Javier Marin (Based in mft work of Omer BenAmram)
# e-mail: motrilwireless@gmail.com
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

from mft import PyMftParser, PyMftAttributeX10, PyMftAttributeX30, PyMftAttributeX80
from operator import itemgetter
from tqdm import tqdm



def join_mft_datetime_attributes(old_entry, value_to_add):
    mask = "macb"
    value_pos = mask.find(value_to_add)
    new_entry = old_entry[:value_pos] + value_to_add + old_entry[value_pos+1:]
    return new_entry


def save_mft_to_file(mft, output_path, timezone):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("Date,Size,Type,Mode,UID,GID,Meta,File Name,Resident\n")
        for entry in mft:
            fflag = ""
            ftype = "r/rrwxrwxrwx" #TODO
            if "FILE_ATTRIBUTE_IS_DIRECTORY" in entry["ftype"]:
                ftype = "d/drwxrwxrwx" #TODO
            elif "(empty)" in entry["ftype"]:
                ftype = "-/-rwxrwxrwx" #TODO

            if timezone:
                thistz = pytz.timezone(timezone) 
                formatted_date = entry["date"].replace(tzinfo=pytz.utc).astimezone(thistz).strftime("%a %b %d %Y %H:%M:%S")
            else:
                formatted_date = entry["date"].strftime("%a %b %d %Y %H:%M:%S")

            if "ALLOCATED" not in entry["flags"]:
                fflag = "(deleted)"
            f.write("{},{},{},{},{},{},{},{} {}\n".format(formatted_date, entry["file_size"], entry["date_flags"], ftype, 0, 0, entry["inode"], entry["full_path"], fflag))

def dump_resident_file(resident_path, full_path, data):
    filename = "{}/{}".format(resident_path, full_path)
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    with open(filename, "wb") as f:
        f.write(data)

def mft_parser(mftfile, mftout, drive_letter, file_name, timezone, resident_path):
    mft = list()
    totalres = 0
    totaldel = 0

    if resident_path:
        report_file = "{}/resident_summary.txt".format(resident_path)
        with open(report_file, "w") as r:
            r.write("STATUS, FILE PATH\n")

    parser = PyMftParser(mftfile)
    for file_record in tqdm(parser.entries(), desc = "  + PARSING MFT:"):
        if isinstance(file_record, RuntimeError):
            continue

        ftypex10 = ""
        ftypex30 = ""
        resident = False
        rdeleted = "ALLOCATED"
        mft_entryx10 = dict()
        mft_entryx30 = dict()
        for attribute_record in file_record.attributes():
            if isinstance(attribute_record, RuntimeError):
                continue

            resident = attribute_record.is_resident

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
                if resident and resident_path:
                    if isinstance(attribute_data, PyMftAttributeX80):
                        dump_resident_file(resident_path, file_record.full_path, attribute_data.data)
                        totalres += 1
                        if "ALLOCATED" not in file_record.flags:
                            rdeleted = "DELETED"
                            totaldel += 1
                        with open(report_file, "a") as r:
                            r.write("{},{}\n".format(rdeleted, file_record.full_path))

        for entry in mft_entryx10:
            mft.append({
                "file_size": file_record.file_size,
                "full_path": "{}:/{}".format(drive_letter, file_record.full_path),
                "inode": file_record.entry_id,
                "flags": file_record.flags,
                "date": entry,
                "date_flags": mft_entryx10[entry],
                "ftype": ftypex10
            })
        if file_name:
            for entry in mft_entryx30:
                mft.append({
                    "file_size": file_record.file_size,
                    "full_path": "{}:/{} ($FILE_NAME)".format(drive_letter, file_record.full_path),
                    "inode": file_record.entry_id,
                    "flags": file_record.flags,
                    "date": entry,
                    "date_flags": mft_entryx30[entry],
                    "ftype": ftypex30
            })

    mft_ordered_by_date = sorted(mft, key=itemgetter("date"))
    save_mft_to_file(mft_ordered_by_date, mftout, timezone)

    if resident_path:
        print ("  + TOTAL RESIDENT RECOVERED: {}".format(totalres))
        print ("  + TOTAL DELETED RESIDENT RECOVERED: {}".format(totaldel))
        print ("  + RECOVERY REPORT FILE: {}".format(report_file))


def get_args():
    argparser = argparse.ArgumentParser(
        description='Utility to create a mactime format filesystem timeline from MFT')

    argparser.add_argument('-f', '--file',
                           required=True,
                           action='store',
                           help='MFT artifact path')

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

    args = argparser.parse_args()

    return args


def main():

    args = get_args()

    mftfile = args.file
    mftout = args.output
    drive_letter = args.drive
    file_name = args.filenameattr
    timezone = args.timezone
    resident_path = args.resident

    if timezone and timezone not in pytz.all_timezones:
        raise ValueError('Invalid timezone string!')

    mft_parser(mftfile, mftout, drive_letter, file_name, timezone, resident_path)


# *** MAIN LOOP ***
if __name__ == '__main__':
    main()


