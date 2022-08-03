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
from mft import PyMftParser, PyMftAttributeX10
from operator import itemgetter


def join_mft_datetime_attributes(old_entry, value_to_add):
    mask = "macb"
    value_pos = mask.find(value_to_add)
    new_entry = old_entry[:value_pos] + value_to_add + old_entry[value_pos+1:]
    return new_entry


def save_mft_to_file(mft, output_path):
    with open(output_path, "w") as f: 
        for entry in mft:
            ftype = "r/rrwxrwxrwx" 
            if "FILE_ATTRIBUTE_IS_DIRECTORY" in entry["ftype"]:
                ftype = "d/drwxrwxrwx"
            elif "(empty)" in entry["ftype"]:
                ftype = "-/-rwxrwxrwx"
            formatted_date = entry["date"].strftime("%a %b %d %Y %H:%M:%S")
            f.write("{},{},{},{},{},{},{},{}\n".format(formatted_date, entry["file_size"], entry["date_flags"], ftype, 0, 0, entry["inode"], entry["full_path"]))


def mft_parser(mftfile, mftout, drive_letter):
    mft = list()
    parser = PyMftParser(mftfile)
    for entry_or_error in parser.entries():
        if isinstance(entry_or_error, RuntimeError):
            continue

        ftype = ""
        mft_entry = dict()
        for attribute_or_error in entry_or_error.attributes():
            if isinstance(attribute_or_error, RuntimeError):
                continue

            resident_content = attribute_or_error.attribute_content
            if resident_content:
                if isinstance(resident_content, PyMftAttributeX10):
                    if resident_content.modified not in mft_entry:
                        mft_entry[resident_content.modified] = "m..."
                    else:
                        mft_entry[resident_content.modified] = join_mft_datetime_attributes(mft_entry[resident_content.modified], 'm')
                    if resident_content.accessed not in mft_entry:
                        mft_entry[resident_content.accessed] = ".a.."
                    else:
                        mft_entry[resident_content.accessed] = join_mft_datetime_attributes(mft_entry[resident_content.accessed], 'a')
                    if resident_content.mft_modified not in mft_entry:
                        mft_entry[resident_content.mft_modified] = "..c."
                    else:
                        mft_entry[resident_content.mft_modified] = join_mft_datetime_attributes(mft_entry[resident_content.mft_modified], 'c')
                    if resident_content.created not in mft_entry:
                        mft_entry[resident_content.created] = "...b"
                    else:
                        mft_entry[resident_content.created] = join_mft_datetime_attributes(mft_entry[resident_content.created], 'b')
                    ftype = resident_content.file_flags

        for entry in mft_entry:
            mft.append({
                "file_size": entry_or_error.file_size,
                "full_path": "{}:/{}".format(drive_letter, entry_or_error.full_path),
                "inode": entry_or_error.entry_id,
                "flags": entry_or_error.flags,
                "date": entry,
                "date_flags": mft_entry[entry],
                "ftype": ftype
            })

    mft_ordered_by_date = sorted(mft, key=itemgetter("date"))
    save_mft_to_file(mft_ordered_by_date, mftout)


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

    args = argparser.parse_args()

    return args


def main():

    args = get_args()

    mftfile = args.file
    mftout = args.output
    drive_letter = args.drive

    mft_parser(mftfile, mftout, drive_letter)


# *** MAIN LOOP ***
if __name__ == '__main__':
    main()


