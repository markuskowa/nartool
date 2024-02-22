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
    NarHash: str
    NarSize: int
    Sig: List[str]
    References: List[str]
    Compression: str = "none"
    FileHash: typing.Optional[str] = None
    FileSize: typing.Optional[int] = None
    Deriver: typing.Optional[str] = None
    System: typing.Optional[str] = None
    CA: typing.Optional[str] = None

    def __init__(self, text: typing.Optional[str] = None):
        self.Sig = []
        self.References = []
        self.Deriver = None

        if text != None:
            for line in text.split("\n"):
                kv = line.split(': ')
                if len(kv) == 2:
                    key = kv[0]
                    value = kv[1].strip()

                    if key == "FileSize" or key == "NarSize":
                        value = int(value)

                    if key == "Sig":
                        self.Sig.append(value)
                    elif key == "References":
                        self.References = value.split(" ")
                        if len(self.References) > 0 and len(self.References[-1]) == 0:
                            self.References.pop()
                    else:
                        setattr(self, key, value)

    def to_str(self) -> str:

        text = ""
        for field in [a for a in dir(self) if not (a.startswith('__') or a.startswith('to_'))]:
            value = getattr(self, field)
            if type(value) == list:
                if not value:
                    value = None
                else:
                    value = " ".join(value)
            if value != None:
                text = text + field + ": " + str(value) + "\n"


        return text

    def to_json(self) -> str:
        return json.dumps(asdict(self))


    def __repr__(self):
        return self.to_json()

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

class NixStore:
    def __init__(self):
        self.store_dir = "/nix/store"

    def narinfo(self, path) -> NarInfo:
        ''' Returns an incomplete NarInfo
        '''

        if path[0] != "/":
            path = os.path.join(self.store_dir, path)

        path_info = subprocess.run(['nix', 'path-info', '--json', path], stdout=subprocess.PIPE).stdout.decode().strip()
        path_info = json.loads(path_info)[0]

        # construct
        info = NarInfo()
        info.URL = ""
        info.StorePath = path_info['path']
        info.NarHash = subprocess.run(['nix', 'hash', 'to-base32', path_info['narHash']], stdout=subprocess.PIPE).stdout.decode().strip()
        info.NarHash = "sha256:" + info.NarHash  #FIXME
        info.NarSize = path_info['narSize']
        for ref in path_info['references']:
            info.References.append(os.path.basename(ref))

        if "deriver" in path_info:
            info.Deriver = path_info['deriver']

        return info

    def dump_nar(self, info: NarInfo) -> bytes:
        return subprocess.run(['nix', 'nar', 'dump-path', info.StorePath], stdout=subprocess.PIPE).stdout

    def get_closure(self, path: str, closure: typing.Optional[Closure] = None) -> Closure:
        '''Get a closure from a nix store path
        '''
        if closure == None:
            closure = Closure()

        hash = hash_from_name(path)
        if hash not in closure:
            try:
                closure[hash] = self.narinfo(path)

                for ref in closure[hash].References:
                   if hash_from_name(ref) != hash:
                        closure = self.get_closure(ref, closure)
            except:
                None

        return closure



class NarStore:
    def __init__(self, store_dir: str):
        self.store_dir = store_dir
        self.by_hash = None
        self.by_url = None

    def get_narinfo_name(self, hash):
        return os.path.join(self.store_dir, hash + ".narinfo")

    def read_narinfo(self, hash: str) -> NarInfo:
        '''Read a narinfo file
        '''
        with open(self.get_narinfo_name(hash), 'r') as file:
            lines = file.read()

        return NarInfo(lines)

    def write_narinfo(self, hash: str, info: NarInfo):
        '''Write a .narinfo file
        '''
        with open(self.get_narinfo_name(hash), 'w') as file:
            file.write(info.to_str())

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
                print("Warning: " + hash + " not found in nar store", file=sys.stderr)

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

    def get_derivers(self, closure: Closure) -> List[str]:
        '''Get all derivers named by closure
        '''

        drvs = []
        for hash, info in closure.items():
            if info.Deriver != None:
                drv_path = info.Deriver

                if drv_path not in closure:
                    drvs.append(drv_path)

        return drvs

    def get_FODs(self, closure: Closure) -> List[str]:
        '''Get all fixed output derivations (FODs) from closure
        '''

        fods = []
        for hash, info in closure.items():
            if not info.References and info.Deriver == None:  # FODs have no references
                fods.append(hash)
                print(info)

        return fods


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


    def get_closure_files(self, closure: Closure, relative: bool = False) -> List[str]:
        '''Get a list of all files that belong to closure
        '''
        files = []
        for hash, info in closure.items():
            if relative:
                files.append(hash + ".narinfo")
                files.append(info.URL)
            else:
                files.append(os.path.join(self.store_dir, hash + ".narinfo"))
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

                if url[0] == "/":
                    if os.path.isfile(url):
                        return True
                else:
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
            found = False
            for cache in cache_urls:
                url = cache + "/" + hash + ".narinfo"
                print("fetching {}".format(hash))
                if url[0] == "/":
                    if os.path.isfile(url):
                        with open(url, 'r') as file:
                            info = NarInfo(file.read())

                        os.system("cp " + url + " " + self.get_narinfo_name(hash))
                        os.system("cp " + os.path.join(cache, info.URL) + " " + os.path.join(self.store_dir, info.URL))
                        found = True
                else:
                    try:
                        res = requests.get(url, timeout=3)
                        if res.status_code == 200:
                            found = True
                            info = NarInfo(res.text)
                            with open(os.path.join(self.store_dir, hash + ".narinfo"), 'w') as file:
                                file.write(res.text)
                            res = requests.get(cache + "/" + info.URL, timeout=3)
                            if res.status_code == 200:
                                with open(os.path.join(self.store_dir, info.URL), 'wb') as file:
                                    file.write(res.content)

                    except:
                        print("Warning download failed " + url, file=sys.stderr)

            if not found:
                print("Warning: file {} not found in any cache.".format(hash), file=sys.stderr)


    def recompress_nar(self, hashes, compression: str = "xz") -> tuple[int, int]:
        '''Recompress given NAR file and update narinfo
        '''

        size_old = 0
        size_new = 0

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

            if info.FileSize == None:
                size_old = size_old + info.NarSize
            else:
                size_old = size_old + info.FileSize

            old_compression = info.Compression
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

            # Compress file
            print("re-compressing {}: {} -> {}".format(hash, old_compression, compression))
            os.system(cmd);

            # Get hash
            if compression == None or compression == 'none':
                info.FileHash = None
                info.FileSize = None
                file_hash = info.NarHash.split(':')[1]
            else:
                type = 'sha256'
                file_hash = subprocess.run(['nix', 'hash', 'file', '--base32', '--type', type, tmp_name], stdout=subprocess.PIPE).stdout.decode().strip()
                info.FileHash = type + ':' + file_hash
                info.FileSize = os.path.getsize(tmp_name)

            new_url = os.path.join('nar', file_hash + '.nar' + ext)
            os.system('mv ' + tmp_name + ' ' + os.path.join(self.store_dir, new_url))

            info.URL = new_url
            self.write_narinfo(hash, info)

            if info.FileSize == None:
                size_new = size_new + info.NarSize
            else:
                size_new = size_new + info.FileSize

        return size_old, size_new

    def nix_copy(self, closure: Closure, compression: str = "xz") -> int:
        '''Copy a closure. If caches is given only paths not in cache will be copied
        '''
        nix_store = NixStore()
        pathlib.Path(os.path.join(self.store_dir, "nar")).mkdir(parents=True, exist_ok=True)

        copy_counter = 0

        for hash, info in closure.items():
            # Skip existing paths
            if not os.path.isfile(self.get_narinfo_name(hash)):
                print("copy: {}".format(info.StorePath), file=sys.stderr)
                info.URL = os.path.join("nar", info.NarHash[7:] + ".nar") #FIXME

                nar_path = os.path.join(self.store_dir, info.URL)
                with open(nar_path, 'wb') as nar:
                    nar.write(nix_store.dump_nar(info))

                if compression == "xz":
                    os.system("xz " + nar_path)
                    info.URL = info.URL + ".xz"
                    info.Compression = "xz"
                    nar_path = os.path.join(self.store_dir, info.URL)
                elif compression == "zstd":
                    os.system("zstd --rm " + nar_path + " " + "-o " + nar_path + ".zstd")
                    info.URL = info.URL + ".zstd"
                    info.Compression = "zstd"
                    nar_path = os.path.join(self.store_dir, info.URL)
                elif compression == "none":
                    None
                else:
                    raise(Exception("Invalid compression method"))

                if compression != "none":
                    type = 'sha256'
                    file_hash = subprocess.run(['nix', 'hash', 'file', '--base32', '--type', type, nar_path], stdout=subprocess.PIPE).stdout.decode().strip()
                    info.FileHash = type + ':' + file_hash
                    info.FileSize = os.path.getsize(nar_path)

                self.write_narinfo(hash, info)
                copy_counter = copy_counter + 1
            else:
                print("skip: {} (already present)".format(info.StorePath), file=sys.stderr)

        return copy_counter


