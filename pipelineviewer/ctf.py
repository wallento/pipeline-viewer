try:
    from babeltrace import TraceCollection
except ImportError:
    print("babeltrace needed and needs to be installed manually (e.g., python3-babeltrace in Debian/Ubuntu)")
    exit(1)

class CTFReader():
    def __init__(self, path):
        self.babelreader = CTFBabeltrace(path)

    def get_events(self):
        for event in self.babelreader.get_events():
            yield event


class CTFBabeltrace():
    def __init__(self, path):
        self.traces = dict()
        self.tc = TraceCollection()
        if self.tc:
            # add traces to the collection
            if self.tc.add_traces_recursive(path, "ctf") is None:
                raise RuntimeError('Cannot add trace')
        else:
            print("no TraceCollection available...")

    def get_events(self):
        if self.tc:
            for event in self.tc.events:
                yield event

