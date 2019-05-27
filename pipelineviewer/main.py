#!/usr/bin/env python3

import sys
import re
from attrdict import AttrDict
import colorama
import argparse

# IF log is "<cycle> IF <id> <mode> <addr>"
trace_if = re.compile(r"^\s*(\d+) IF \s*(\d+) (\w) ([0-9A-Fa-f]+)")
# DE log is "<cycle> DE <id> <addr> <insn>"
trace_de = re.compile(r"^\s*(\d+) DE \s*(\d+) ([0-9A-Fa-f]+) (.*)")
# IS log is "<cycle> IS <id>"
trace_is = re.compile(r"^\s*(\d+) IS \s*(\d+)")
# C log is "<cycle> C <id>"
trace_c = re.compile(r"^\s*(\d+) C \s*(\d+)")

display = {"IF": AttrDict(char="f", fore=colorama.Fore.WHITE, back=colorama.Back.BLUE),
           "DE": AttrDict(char="d", fore=colorama.Fore.WHITE, back=colorama.Back.YELLOW),
           "IS": AttrDict(char="i", fore=colorama.Fore.WHITE, back=colorama.Back.RED),
           "C": AttrDict(char="c", fore=colorama.Fore.WHITE, back=colorama.Back.CYAN)}


class Pipeline(object):
    def read(self, file):
        pass


class PipelineAriane(Pipeline):
    stages = ["IF", "DE", "IS", "C"]
    def __init__(self, file):
        log = {}

        for line in file:
            m = trace_if.match(line)
            if m:
                id = int(m.group(2))
                log[id] = AttrDict({"pc": int(m.group(4),16), "insn": None, "mode": m.group(3), "IF": int(m.group(1)), "DE": None, "IS": None, "C": None})
                continue
            m = trace_de.match(line)
            if m:
                id = int(m.group(2))
                pc = int(m.group(3),16)
                assert pc & ~3 == log[id].pc, "{} pc = {:x} logpc = {:x}".format(id, pc, log[id].pc)
                log[id].pc = pc
                log[id].DE = int(m.group(1))
                log[id].insn = m.group(4)
                continue
            m = trace_is.match(line)
            if m:
                id = int(m.group(2))
                log[id].IS = int(m.group(1))
                continue
            m = trace_c.match(line)
            if m:
                id = int(m.group(2))
                log[id].C = int(m.group(1))
                continue
        self.log = log


pipelines = {"ariane": PipelineAriane}


def render(pipeline, args):
    if args.colored:
        colorama.init(strip=False)
    else:
        colorama.init()

    in_snip = False
    for i in pipeline.log.values():
        if i.mode not in args.modes:
            if not in_snip:
                args.outfile.write("~" * args.width + " snip (mode)\n")
            in_snip = True
            continue
        in_snip = False
        line = list("." * args.width)
        for s in range(len(pipeline.stages)):
            stage = pipeline.stages[s]
            if stage in i and i[stage] is not None:
                line[i[stage] % args.width] = display[stage].fore + display[stage].back + display[stage].char + colorama.Style.RESET_ALL
                next = s + 1
                if next >= len(pipeline.stages):
                    continue
                next = pipeline.stages[next]
                if next in i and i[next] is not None:
                    for x in range(i[stage] + 1, i[next]):
                        line[x % args.width] = display[stage].fore + display[stage].back + "=" + colorama.Style.RESET_ALL
        line = "[" + "".join(line) + "]"

        if not args.no_mode:
            line += " {}".format(i.mode)

        if not args.no_time:
            if pipeline.stages[-1] in i and i[pipeline.stages[-1]]:
                line += " {:8}-{:8}".format(i[pipeline.stages[0]], i[pipeline.stages[-1]])
            else:
                line += " {:8}---------".format(i[pipeline.stages[0]])

        if not args.no_pc:
            line += " {:016x}".format(i.pc)

        if not args.no_insn and i.insn:
            line += " " + i.insn

        args.outfile.write(line+"\n")
    colorama.deinit()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("format", choices=["ariane"])
    parser.add_argument("infile", nargs='?', help="file with pipeline trace", type=argparse.FileType('r'),
                        default=sys.stdin)
    parser.add_argument("outfile", nargs='?', help="file to render to", type=argparse.FileType('w'),
                        default=sys.stdout)
    parser.add_argument("-c", "--colored", action="store_true", help="force colored output")
    parser.add_argument("-w", "--width", type=int, default=80, help="column width of graph")
    parser.add_argument("--modes", default="MSU", help="only show from given modes")
    parser.add_argument("--no-mode", action="store_true", help="suppress mode in output")
    parser.add_argument("--no-time", action="store_true", help="suppress time frame in output")
    parser.add_argument("--no-pc", action="store_true", help="suppress program counter in output")
    parser.add_argument("--no-insn", action="store_true", help="suppress instruction in output")
    parser.add_argument("--bp", action="store_true", help="include branch predictor in output")
    args = parser.parse_args()
    args.modes = list(args.modes)
    render(pipelines[args.format](args.infile), args)
