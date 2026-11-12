"""Throwaway IDA probe: FlowChart for FH4-boundary functions."""
import idaapi
import ida_gdl
import idc

idaapi.auto_wait()
for f in (0x140005698, 0x140004BD4, 0x140005A9C, 0x140005A24):
    print("FUNC %x name=%s" % (f, idc.get_func_name(f)))
    fc = ida_gdl.FlowChart(idaapi.get_func(f))
    for bb in fc:
        if bb.start_ea >= f + 0x80:
            continue
        print("  blk %x-%x succs=%s" % (
            bb.start_ea, bb.end_ea,
            [hex(x.start_ea) for x in bb.succs()]))
idc.qexit(0)
