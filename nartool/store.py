# SPDX-License-Identifier: GPL-3.0-Only

import os
import sys
import re
import json
import pathlib
import typing

import subprocess

from typing import List
from dataclasses import dataclass
from dataclasses import asdict

import requests

def nix_hash_is_valid(hash: str) -> bool:
    if not re.match(r"[0-9abcdfghijklmnpqrsvwxyz]{32}", hash):
        return False

    return True

def check_nix_hash(hash: str) -> str:
    if not nix_hash_is_valid(hash):
        raise Exception("Hash is not valid Nix store path hash: " +  hash)

    return hash

def hash_from_name(name: str) -> str:
    '''Convert a file name into NIX store hash
    '''

    # Length of hash in Nix store path names
    hash_len = 32

    # strip path
    bname = os.path.basename(name)

    assert(len(name) >= hash_len)
    hash = bname[0:hash_len]

    return hash

@dataclass
class NarInfo:
    StorePath: str
    URL: str
    Compression: str
    NarHash: str
    NarSize: int
    Sig: List[str]
    References: List[str]
    FileHash: typing.Optional[str] = None
    FileSize: typing.Optional[int] = None
    Deriver: typing.Optional[str] = None
    System: typing.Optional[str] = None
    CA: typing.Optional[str] = None

    def __init__(self):
        self.Sig = []
        self.References = []
        self.Deriver = None

    def __repr__(self):
        return json.dumps(asdict(self))

class Closure(dict):
    '''Represent a closure of narinfo files
    '''

    @staticmethod
    def key_is_valid(key):
        if not nix_hash_is_valid(key):
            raise Exception("Key error") #"0123456789abcdfghijklmnpqrsvwxyz"
        return key

    @staticmethod
    def value_is_valid(value):
        if type(value) != NarInfo:
            raise Exception("Value is not of type NarInfo")

        return value

    def __init__(self, mapping=None, /, **kwargs):
        if mapping is not None:
            mapping = {
                self.key_is_valid(key): self.value_is_valid(value) for key, value in mapping.items()
            }
        else:
            mapping = {}
        if kwargs:
            mapping.update(
                {self.key_is_valid(key): self.value_is_valid(value) for key, value in kwargs.items()}
            )
        super().__init__(mapping)

    def __setitem__(self, key, value):
        self.key_is_valid(key)
        self.value_is_valid(value)

        super().__setitem__(key, value)


class NarStore:
    def __init__(self, store_dir: str):
        self.store_dir = store_dir
        self.by_hash = None
        self.by_url = None

    def read_narinfo(self, hash: str) -> NarInfo:
        '''Read a narinfo file
        '''
        with open(os.path.join(self.store_dir, hash + ".narinfo"), 'r') as file:
            lines = file.read()

        return self.parse_narinfo(lines)

    def write_narinfo(self, hash: str, info: NarInfo):
        '''Write a .narinfo file
        '''

        with open(os.path.join(self.store_dir, hash + ".narinfo"), 'w') as file:
            file.write(self.narinfo_to_text(info))

    def narinfo_to_text(self, info: NarInfo) -> str:

        text = ""
        for field in [a for a in dir(info) if not a.startswith('__')]:
            value = getattr(info, field)
            if type(value) == list:
                if not value:
                    value = None
                else:
                    value = " ".join(value)
            if value != None:
                text = text + field + ": " + str(value) + "\n"


        return text


    def parse_narinfo(self, text: str) -> NarInfo:
        nar_info = NarInfo()

        for line in text.split("\n"):
            kv = line.split(': ')
            if len(kv) == 2:
                key = kv[0]
                value = kv[1].strip()

                if key == "Sig":
                    nar_info.Sig.append(value)
                elif key == "References":
                    nar_info.References = value.split(" ")
                    if len(nar_info.References) > 0 and len(nar_info.References[-1]) == 0:
                        nar_info.References.pop()
                else:
                    setattr(nar_info, key, value)

        return nar_info


    def get_closure(self, hash: str, narinfo_dict: typing.Optional[Closure] = None) -> Closure:
        '''Get a narinfo file and all dependcies
        '''

        if narinfo_dict == None:
            narinfo_dict = Closure()

        if hash not in narinfo_dict:
            try:
                narinfo_dict[hash] = self.read_narinfo(hash)

                for ref in narinfo_dict[hash].References:
                   ref_hash = hash_from_name(ref)
                   if ref_hash != hash:
                        narinfo_dict = self.get_closure(ref_hash, narinfo_dict)
            except:
                None

        return narinfo_dict

    @staticmethod
    def get_missing_refs(closure: Closure) -> List[str]:
        '''Get the hashes of all references not explicitly in the closure
        '''

        missing = []
        for _, narinfo in closure.items():
            for ref in narinfo.References:
                if ref not in closure:
                    missing.append(hash_from_name(ref))


        return missing

    def get_closure_from_hashes(self, hashes: List[str]) -> Closure:
        '''Read all narinfo for the given lis of hashes
        '''

        closure = Closure()

        for hash in hashes:
            try:
                closure[hash] = self.read_narinfo(hash)
            except:
                print("Warning: " + hash + " not found in nar store")

        return closure


    def get_store(self):
        '''Get all narinfo files in store
        '''
        by_hash = Closure()
        by_url = {}
        for f in os.listdir(self.store_dir):
            f = os.path.join(self.store_dir, f)
            if os.path.isfile(f):
                _, ext = os.path.splitext(f)
                if ext == ".narinfo":
                    hash = hash_from_name(f)
                    ni = self.read_narinfo(hash)
                    by_hash[hash] = ni

                    if ni.URL in by_url:
                        by_url[ni.URL].append(hash)
                    else:
                        by_url[ni.URL] = [ hash ]

        self.by_hash = by_hash
        self.by_url = by_url
        return by_hash, by_url


    def verify_closure(self, closure: Closure) -> bool:
        '''
            Check if NAR files are present and match in size
        '''
        closure_complete = True

        for _, narinfo in closure.items():

            if not pathlib.Path(os.path.join(self.store_dir, narinfo.URL)).is_file():
                print("{} is missing".format(narinfo.URL))
                closure_complete = False

        return closure_complete


    def get_closure_files(self, closure: Closure) -> List[str]:
        '''Get a list of all files that belong to closure
        '''
        files = []
        for hash, info in closure.items():
            files.append(os.path.join(self.store_dir, hash) + ".narinfo")
            files.append(os.path.join(self.store_dir, info.URL))

        return files

    def closure_to_json(self, closure: Closure) -> str:
        '''Convert closure data strucuture to JSON
        '''
        cl = {}
        for hash, narinfo in closure.items():
            cl[hash] = asdict(narinfo)

        return json.dumps(cl)

    # def get_removable_nar_files(self, file_hash: List[str]):
    #     '''Get a list of nar and narinfo files that can be removed.
    #        Respects the references.
    #     '''


    def find_orphaned_nar_files(self, nar_dir: str = "nar") -> List[str]:
        '''Find nar files that are not referenced by any .narinfo
        '''

        if self.by_hash == None or self.by_url == None:
            self.get_store()

        nar_path = os.path.join(self.store_dir, nar_dir)

        orphans = []
        # Get all files in nar subdir and match against narinfos
        for fname in os.listdir(nar_path):
            fpath = os.path.join(nar_path, fname)
            if os.path.isfile(fpath):
                url = os.path.join(nar_dir, fname)

                if not url in self.by_url:
                    orphans.append(fpath)

        return orphans


    def find_orphaned_narinfo_files(self, closure: typing.Optional[Closure] = None) -> List[str]:
        '''Find narinfo files that point to non-existent NAR files
        '''

        if closure == None:
            closure, _ = self.get_store()

        missing_narinfo_path = []

        for hash, narinfo in closure.items():
            narinfo.URL
            nar_path = os.path.join(self.store_dir, narinfo.URL)
            if not os.path.isfile(nar_path):
                missing_narinfo_path.append(os.path.join(self.store_dir, hash + ".narinfo"))

        return missing_narinfo_path


    def find_cached_hashes(self, closure: typing.Optional[Closure] = None, cache_urls: List[str] = ["https://cache.nixos.org"], check_refs: bool = False) -> List[str]:
        '''Find all files, that are avaible in external caches
        '''

        def check_caches(hash):
            for cache in cache_urls:
                url = cache + "/" + hash + ".narinfo"
                try:
                    res = requests.get(url, timeout=10)
                    if res.status_code == 200:
                        return True
                except:
                    print("Warning download failed " + url, file=sys.stderr)

            return False

        if closure == None:
            closure, _ = self.get_store()

        available = []
        for hash, info in closure.items():

            if not check_refs:
                if check_caches(hash):
                    available.append(hash)

            if check_refs:
                for ref in info.References:
                    ref = hash_from_name(ref)
                    if ref not in closure:
                        if check_caches(ref):
                            available.append(ref)

        return available

    def fetch_from_cache(self, hashes: List[str], cache_urls: List[str] = ["https://cache.nixos.org"]):
        '''Fetch NAR + narinfo files from cache
        '''

        for hash in hashes:
            for cache in cache_urls:
                url = cache + "/" + hash + ".narinfo"
                try:
                    res = requests.get(url, timeout=3)
                    if res.status_code == 200:
                        info = self.parse_narinfo(res.text)
                        with open(os.path.join(self.store_dir, hash + ".narinfo"), 'w') as file:
                            file.write(res.text)
                        res = requests.get(cache + "/" + info.URL, timeout=3)
                        if res.status_code == 200:
                            with open(os.path.join(self.store_dir, info.URL), 'wb') as file:
                                file.write(res.content)

                except:
                    print("Warning download failed " + url, file=sys.stderr)

    def recompress_nar(self, hashes, compression: typing.Optional[str] = "xz"):
        '''Recompress given NAR file and update narinfo
        '''

        nar_path = os.path.join(self.store_dir, 'nar')
        for hash in hashes:
            info = self.read_narinfo(hash)

            # Current compression
            if info.Compression == 'none':
                cmd = 'cat '
            elif info.Compression == 'xz':
                cmd = 'xz -dc '
            elif info.Compression == 'zstd':
                cmd = 'zstd -dc '
            else:
                raise Exception('Unsupported compression type: ' + info.Compression)

            cmd = cmd + os.path.join(self.store_dir, info.URL) + ' | '

            # Target compression
            if compression == None or compression == "none":
                cmd = cmd + 'cat > '
                ext = ""
                info.Compression = "none"
            elif compression == "xz":
                cmd = cmd + 'xz -z > '
                ext = ".xz"
                info.Compression = "xz"
            elif compression == "zstd":
                cmd = cmd + 'zstd > '
                ext = ".zstd"
                info.Compression = "zstd"
            else:
                raise Exception('Unsupported compression type: ' + compression)

            tmp_name = os.path.join(nar_path, hash + '.tmp')
            cmd = cmd + tmp_name
            print(cmd)

            # Compress file
            os.system(cmd);

            # Get hash
            if compression == None or compression == 'none':
                info.FileHash = None
                info.FileSize = None
                file_hash = info.NarHash.split(':')[1]
            else:
                type = 'sha256'
                file_hash = subprocess.run(['nix', 'hash', 'file', '--base32', '--type', type, tmp_name], stdout=subprocess.PIPE).stdout.decode().strip()
                print(file_hash)
                info.FileHash = type + ':' + file_hash
                info.FileSize = os.path.getsize(tmp_name)

            new_url = os.path.join('nar', file_hash + '.nar' + ext)
            print(new_url)
            os.system('mv ' + tmp_name + ' ' + os.path.join(self.store_dir, new_url))

            info.URL = new_url
            self.write_narinfo(hash, info)
