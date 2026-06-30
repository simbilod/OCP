import sys
import subprocess
from logzero import logger

try:
    import lief
    has_lief = True
except ImportError:
    has_lief = False
    logger.info("lief not found, falling back to system nm tool")

libs = sys.argv[-1].split(';')

exported_symbols = []
name = "linux"

for lib in libs:
    logger.info(f'Analyzing {lib}')

    if has_lief:
        p = lief.parse(lib)
        if p is None:
            continue
        format = p.format
        if format==p.FORMATS.ELF:
            name = "linux"
            for s in p.exported_symbols:
                exported_symbols.append(f'{s.name}\n')
        elif format==p.FORMATS.MACHO:
            name = "mac"
            for s in p.symbols:
                if s.raw_type>1:
                    exported_symbols.append(f'{s.name}\n')
        else:
            name = "win"
            for s in p.exported_functions:
                exported_symbols.append(f'{s.name}\n')
    else:
        # Fallback using nm on Linux
        try:
            output = subprocess.check_output(["nm", "-D", "--defined-only", lib], text=True)
            for line in output.splitlines():
                parts = line.strip().split()
                if len(parts) >= 3:
                    sym = parts[-1].split('@')[0] # Remove @GLIBC versioning if present
                    exported_symbols.append(f'{sym}\n')
        except Exception as e:
            logger.error(f"Failed to analyze {lib} with nm: {e}")
            sys.exit(1)

with open(f'symbols_mangled_{name}.dat','w') as f:
    f.writelines(exported_symbols)
