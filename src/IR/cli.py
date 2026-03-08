from src.IR import (
    parse_textual_ir,
    serialize_ir_to_text,
    save_ir_json_file,

    validate_ir_json,
    IRValidationError,

    assembly_lines_to_ir,
    TranslationTableManager,
)

from pathlib import Path
import json
import sys
import argparse


def __recursiveValues(d):
    for v in d.values():
        if isinstance(v, dict):
            yield from __recursiveValues(v)
        else:
            yield v


def _cmd_validate(args):
    pth = Path(args.json_file)
    try:
        data = json.loads(pth.read_text(encoding='utf-8'))
        validate_ir_json(data)
        print('OK: JSON schema validation passed')
    except IRValidationError as e:
        print('Validation failed:', e)
        sys.exit(2)
    except Exception as e:
        print('Error reading file:', e)
        sys.exit(3)


def _cmd_text2json(args):
    inp = Path(args.infile)
    outp = Path(args.outfile)
    txt = inp.read_text(encoding='utf-8')
    ir = parse_textual_ir(txt)
    try:
        validate_ir_json(ir)
    except IRValidationError as e:
        print('Warning: validation failed after parsing (attempting to save anyway):', e)
    outp.write_text(json.dumps(ir, indent=2), encoding='utf-8')
    print(f'Wrote JSON to {outp}')


def _cmd_json2text(args):
    inp = Path(args.infile)
    outp = Path(args.outfile)
    data = json.loads(inp.read_text(encoding='utf-8'))
    try:
        validate_ir_json(data)
    except IRValidationError as e:
        print('Warning: JSON did not validate against schema:', e)
    txt = serialize_ir_to_text(data)
    outp.write_text(txt, encoding='utf-8')
    print(f'Wrote textual IR to {outp}')


def _cmd_asm2ir(args):
    asmfile = Path(args.infile)
    outjson = Path(args.outfile)
    arch = args.arch or 'x86_64'
    # prepare table manager
    dbp = Path(args.db) if args.db else None
    jsondir = Path(args.tables) if args.tables else None
    table_mgr = TranslationTableManager(db_path=dbp, json_dir=jsondir)
    asm_lines = asmfile.read_text(encoding='utf-8').splitlines()
    ir = assembly_lines_to_ir(asm_lines, arch, table_mgr)

    try:
        save_ir_json_file(ir, outjson, validate_schema=args.validate)
        print(f'Wrote IR JSON to {outjson}')
    except Exception as e:
        print('Failed to write IR JSON:', e)
        print('Attempting to write without schema validation...')
        outjson.write_text(json.dumps(ir, indent=2), encoding='utf-8')
        print(f'Wrote IR JSON to {outjson} (without validation)')


def main(argv=None):
    p = argparse.ArgumentParser(prog='IR')
    sub = p.add_subparsers(dest='cmd')

    p_val = sub.add_parser('validate')
    p_val.add_argument('--json-file', required=True, help='IR JSON file to validate')
    p_val.set_defaults(func=_cmd_validate)

    p_t2j = sub.add_parser('text2json')
    p_t2j.add_argument('--in', dest='infile', required=True)
    p_t2j.add_argument('--out', dest='outfile', required=True)
    p_t2j.set_defaults(func=_cmd_text2json)

    p_j2t = sub.add_parser('json2text')
    p_j2t.add_argument('--in', dest='infile', required=True)
    p_j2t.add_argument('--out', dest='outfile', required=True)
    p_j2t.set_defaults(func=_cmd_json2text)

    p_a2i = sub.add_parser('asm2ir')
    p_a2i.add_argument('--in', dest='infile', required=True, help='Assembly text file (one instruction per line)')
    p_a2i.add_argument('--out', dest='outfile', required=True, help='Output IR JSON file')
    p_a2i.add_argument('--arch', required=False, help='Source architecture (default x86_64)')
    p_a2i.add_argument('--db', required=False, help='Path to translation_tables.db (SQLite)')
    p_a2i.add_argument('--tables', required=False, help='Path to directory with per-arch JSON tables (fallback)')
    p_a2i.add_argument('--no-validate', dest='validate', action='store_false',
                       help='Do not validate final JSON against schema')
    p_a2i.set_defaults(func=_cmd_asm2ir, validate=True)

    args = p.parse_args(argv)
    if not hasattr(args, 'func'):
        p.print_help()
        return 1
    return exec(f'_cmd_{args.cmd}(args)', globals(), locals())


if __name__ == '__main__':
    raise SystemExit(main())
