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
from mft import PyMftParser, PyMftAttributeX10, PyMftAttributeX30
from operator import itemgetter
from tqdm import tqdm
import pytz


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


def mft_parser(mftfile, mftout, drive_letter, file_name, timezone):
    mft = list()
    parser = PyMftParser(mftfile)
    for file_record in tqdm(parser.entries(), desc = "  + PARSING MFT:"):
        if isinstance(file_record, RuntimeError):
            continue

        ftypex10 = ""
        ftypex30 = ""
        mft_entryx10 = dict()
        mft_entryx30 = dict()
        for attribute_record in file_record.attributes():
            if isinstance(attribute_record, RuntimeError):
                continue

            resident_content = attribute_record.attribute_content
            if resident_content:
                if isinstance(resident_content, PyMftAttributeX10):
                    if resident_content.modified not in mft_entryx10:
                        mft_entryx10[resident_content.modified] = "m..."
                    else:
                        mft_entryx10[resident_content.modified] = join_mft_datetime_attributes(mft_entryx10[resident_content.modified], 'm')
                    if resident_content.accessed not in mft_entryx10:
                        mft_entryx10[resident_content.accessed] = ".a.."
                    else:
                        mft_entryx10[resident_content.accessed] = join_mft_datetime_attributes(mft_entryx10[resident_content.accessed], 'a')
                    if resident_content.mft_modified not in mft_entryx10:
                        mft_entryx10[resident_content.mft_modified] = "..c."
                    else:
                        mft_entryx10[resident_content.mft_modified] = join_mft_datetime_attributes(mft_entryx10[resident_content.mft_modified], 'c')
                    if resident_content.created not in mft_entryx10:
                        mft_entryx10[resident_content.created] = "...b"
                    else:
                        mft_entryx10[resident_content.created] = join_mft_datetime_attributes(mft_entryx10[resident_content.created], 'b')
                    ftypex10 = resident_content.file_flags
                if file_name:
                    if isinstance(resident_content, PyMftAttributeX30):
                        if resident_content.modified not in mft_entryx30:
                            mft_entryx30[resident_content.modified] = "m..."
                        else:
                            mft_entryx30[resident_content.modified] = join_mft_datetime_attributes(mft_entryx30[resident_content.modified], 'm')
                        if resident_content.accessed not in mft_entryx30:
                            mft_entryx30[resident_content.accessed] = ".a.."
                        else:
                            mft_entryx30[resident_content.accessed] = join_mft_datetime_attributes(mft_entryx30[resident_content.accessed], 'a')
                        if resident_content.mft_modified not in mft_entryx30:
                            mft_entryx30[resident_content.mft_modified] = "..c."
                        else:
                            mft_entryx30[resident_content.mft_modified] = join_mft_datetime_attributes(mft_entryx30[resident_content.mft_modified], 'c')
                        if resident_content.created not in mft_entryx30:
                            mft_entryx30[resident_content.created] = "...b"
                        else:
                            mft_entryx30[resident_content.created] = join_mft_datetime_attributes(mft_entryx30[resident_content.created], 'b')
                        ftypex30 = resident_content.flags



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

    args = argparser.parse_args()

    return args


def main():

    args = get_args()

    mftfile = args.file
    mftout = args.output
    drive_letter = args.drive
    file_name = args.filenameattr
    timezone = args.timezone

    if timezone and timezone not in pytz.all_timezones:
        raise ValueError('Invalid timezone string!')

    mft_parser(mftfile, mftout, drive_letter, file_name, timezone)


# *** MAIN LOOP ***
if __name__ == '__main__':
    main()


