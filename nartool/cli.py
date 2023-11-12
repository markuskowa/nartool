# SPDX-License-Identifier: GPL-3.0-Only

import sys
import os
import argparse as ap

from .store import NarStore
from .store import NixStore
from .store import check_nix_hash
from .store import hash_from_name

def main():
    argsMain = ap.ArgumentParser(
          prog = "nartool",
          description = "Tool to maintain Nix NAR caches")

    cmdArgs = argsMain.add_subparsers(dest="command", help='sub-command help')
    argsMain.add_argument("store", help = "Path to NAR store")

    argsCheck = cmdArgs.add_parser("check", help="Verify the structure of the store (Check for missing nar files)")
    argsCheck.add_argument("-a", "--hash", help="Only check closure for specific hash")

    argsGetFiles = cmdArgs.add_parser("get", help="Get a list of all files beloning to closure")
    argsGetFiles.add_argument("-a", "--hash", help="Only get files for specific hash")
    argsGetFiles.add_argument("-l", "--listhashes", action='store_true', help="List nix store hashes instead of path names")
    argsGetFiles.add_argument("-r", "--relative", action='store_true', help="Path names relative to storedir")


    argsGetDrvs = cmdArgs.add_parser("drvs", help="Get a list of .drvs references by the closure")
    argsGetDrvs.add_argument("-a", "--hash", help="Only get files for specific hash")
    argsGetDrvs.add_argument("-l", "--listhashes", action='store_true', help="List nix store hashes instead of path names")

    argsOrphans = cmdArgs.add_parser("orphans", help="Find orphaned NAR files")
    argsOrphans.add_argument("-n", "--nardir", help="NAR subdirectory relative to store dir. Defaults to 'nar'")

    argsCache = cmdArgs.add_parser("cache", help="Check other caches for availability")
    argsCache.add_argument("-a", "--hash", help="Only get files for specific hash")
    argsCache.add_argument("-c", "--caches", nargs=1, default=["https://cache.nixos.org"], help="Comma separated list of cache URLs")
    argsCache.add_argument("-r", "--checkrefs", action="store_true", help="Check if missing refrences are available in cache instead")

    argsFetch = cmdArgs.add_parser("fetch", help="Fetch NARs based on hash")
    argsFetch.add_argument("-c", "--caches", nargs=1, default=["https://cache.nixos.org"], help="Comma separated list of cache URLs")
    argsFetch.add_argument("-i", "--input", default=sys.stdin, help="Input file with hashes")

    argsCompress = cmdArgs.add_parser("compress", help="(Re)compress NAR files. Original files will not be deleted!")
    argsCompress.add_argument("-z", "--compression", nargs=1, default=['xz'], help="Target compression [xz, zstd, none]")
    argsCompress.add_argument("-i", "--input", default=sys.stdin, help="Input file with hashes")

    argsCopy = cmdArgs.add_parser("nixcopy", help="Copy closure from nix store to binary cache")
    argsCopy.add_argument("-z", "--compression", nargs=1, default=['xz'], help="Target compression [xz, zstd, none]")
    argsCopy.add_argument("-s", "--skipcached", action="store_true", help="Skip all paths available in cache")
    argsCopy.add_argument("-c", "--caches", nargs=1, default=["https://cache.nixos.org"], help="Comma separated list of cache URLs")
    argsCopy.add_argument("-o", "--output", nargs='?', help="Write list of copied hashes to file")
    argsCopy.add_argument("path", help="Store path")

    args = argsMain.parse_args()

    if args.command == None:
          argsMain.print_help()
          exit(0)


    ns = NarStore(args.store)

    if args.command == "check":
        if args.hash != None:
            closure = ns.get_closure(check_nix_hash(args.hash))
            orphans = ns.find_orphaned_narinfo_files(closure)
        else:
            orphans = ns.find_orphaned_narinfo_files()

        for i in orphans:
            print(i)


    elif args.command == "get":
        if args.hash == None:
            closure, _ = ns.get_store()
        else:
            closure = ns.get_closure(check_nix_hash(args.hash))

        if args.listhashes:
            for hash in closure:
                print(hash)
        else:
            files = ns.get_closure_files(closure, args.relative)
            for f in files:
                print(f)

    elif args.command == "drvs":
        if args.hash == None:
            closure, _ = ns.get_store()
        else:
            closure = ns.get_closure(check_nix_hash(args.hash))

        drvs = ns.get_derivers(closure)

        for drv in drvs:
            if args.listhashes:
                print(hash_from_name(drv))
            else:
                print(drv)



    elif args.command == "cache":
        if args.hash == None:
            closure, _ = ns.get_store()
        else:
            closure = ns.get_closure(args.hash)

        caches = args.caches[0].split(",")
        hashes = ns.find_cached_hashes(closure, cache_urls=caches, check_refs=args.checkrefs)

        for h in hashes:
            print(h)

    elif args.command == "orphans":
        if args.nardir == None:
            files = ns.find_orphaned_nar_files()
        else:
            files = ns.find_orphaned_nar_files(args.nardir)

        for f in files:
            print(f)

    elif args.command == "fetch":
        caches = args.caches[0].split(",")
        with open(args.input, 'r') as file:
            lines = file.read().split("\n")
            hashes = filter(lambda line: line.strip() != '', lines)
            ns.fetch_from_cache(list(hashes), caches)

    elif args.command == "compress":
        with open(args.input, 'r') as file:
            lines = file.read().split("\n")
            hashes = filter(lambda line: line.strip() != '', lines)
            size_old, size_new = ns.recompress_nar(list(hashes), args.compression[0])

            diff = size_old - size_new
            perc = float(diff)/float(size_old) * 100.0
            print("Old size {}, new size {}, saved {} ({:.2f} %)".format(size_old, size_new, diff, perc))

    elif args.command == "nixcopy":
        closure = NixStore().get_closure(os.path.realpath(args.path))

        cached = 0
        if args.skipcached:
            caches = args.caches[0].split(",")
            cached_hashes = ns.find_cached_hashes(closure, cache_urls=caches)
            for hash in cached_hashes:
                cached = cached + 1
                info = closure.pop(hash)
                print("skip: {} (cached)".format(info.StorePath), file=sys.stderr)

        copied = ns.nix_copy(closure, args.compression[0])
        print("Copied {} paths, skipped {} cached paths".format(copied, cached))

        if args.output is not None:
            with open(args.output, 'w') as file:
                file.write("\n".join(list(closure.keys())))

if __name__ == '__main__':
    main()
