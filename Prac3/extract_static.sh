#!/bin/bash
OUTDIR=~/Documents/UniDocs/ThirdYear/COS330/Prac3/benign/features
SAMPLES_DIR=~/Documents/UniDocs/ThirdYear/COS330/Prac3/benign/binaries
mkdir -p "$OUTDIR"

for f in $(find "$SAMPLES_DIR" -type f -name "*.exe"); do
  base=$(basename "$f")
  dir=$(dirname "$f")
  bname=$(basename "$f")
  outbase="$OUTDIR/${bname}"
  mkdir -p "$(dirname "$outbase")"

  echo "Processing $f" > "${outbase}.meta.txt"
  file "$f" >> "${outbase}.meta.txt"
  stat --format='Size: %s\nAccess: %x\nModify: %y\nChange: %z' "$f" >> "${outbase}.meta.txt"
  sha1sum "$f" >> "${outbase}.meta.txt"
  sha256sum "$f" >> "${outbase}.meta.txt"

  # PE header & sections with rizin (or radare2/rabin2)
  rizin -v -qi "iI; iH; iS; i" -c "q" "$f" > "${outbase}.peinfo.txt" 2>/dev/null || echo "rizin failed" >> "${outbase}.peinfo.txt"

  # imports
  # (inside your loop, with $f and $outbase set)
python3 - "$f" > "${outbase}.imports.txt" <<'PY'
import pefile, sys
f = sys.argv[1]
try:
    pe = pefile.PE(f, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT']])
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            print(entry.dll.decode(errors='ignore'))
            for imp in entry.imports:
                print("  ", imp.name)
    else:
        print("No import table")
except Exception as e:
    print("PE parse error:", e)
PY


  # strings (printable, length>=4), also search for URLs
  strings -n 4 "$f" > "${outbase}.strings.txt"
  grep -Eo 'https?://[^"]+' "${outbase}.strings.txt" > "${outbase}.urls.txt" || true

  # check for UPX/packing with upx -t or detect with binwalk
  upx -t "$f" > "${outbase}.pack.txt" 2>&1 || echo "not-upx" >> "${outbase}.pack.txt"
  binwalk "$f" > "${outbase}.binwalk.txt" 2>/dev/null || true

  # optional: run pefile script to extract compilation timestamp
  python3 - "$f" >> "${outbase}.meta.txt" <<'PY'
import pefile, sys
f = sys.argv[1]
pe = pefile.PE(f, fast_load=True)
print("Compile timestamp:", pe.FILE_HEADER.TimeDateStamp)
try:
    print("Compiler:", pe.get_string_at_rva(
        pe.OPTIONAL_HEADER.DataDirectory[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']
        ].VirtualAddress
    ))
except Exception:
    pass
PY


done

