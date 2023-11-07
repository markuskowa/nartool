

#  Complete clousure
cat > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1.narinfo <<EOF
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1-1
URL: nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1.nar.xz
Compression: xz
FileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1
FileSize: 1
NarHash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb1
NarSize: 1
References: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1-1 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2-2
EOF

echo "1" > nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1.nar.xz

cat > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.narinfo <<EOF
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2-2
URL: nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.nar.xz
Compression: xz
FileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2
FileSize: 1
NarHash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb2
NarSize: 1
References: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2-2
EOF

echo "2" > nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2.nar.xz


# Missing references (not present)
cat > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3.narinfo <<EOF
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3-3
URL: nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3.nar.xz
Compression: xz
FileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3
FileSize: 1
NarHash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb3
NarSize: 1
References: 9la894yvmmksqlapd4v16wvxpaw3rg70-glibc-2.37-8
EOF

echo "3" > nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa3.nar.xz

# Orphaned narinfo
cat > aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4.narinfo <<EOF
StorePath: /nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4-4
URL: nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4.nar.xz
Compression: xz
FileHash: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa4
FileSize: 1
NarHash: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb4
NarSize: 1
EOF


# Orphaned nar file
echo "5" > nar/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa5.nar.xz

