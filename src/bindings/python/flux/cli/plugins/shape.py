from flux.cli_jobspec.parser import CliJobspecParser 
from flux.cli.plugin import CLIPlugin

class CliJobspecShapePlugin(CLIPlugin):
    """Wrap the functionality provided by the command-line job shape
    parser into a command-line plugin users can optionally prepend to
    their `FLUX_CLI_PLUGINPATH`.
    """

    def __init__(self, prog, prefix=""):
        super().__init__(prog, prefix=prefix)
        self.add_option(
            "--shape",
            metavar="RESOURCES",
            help="Provide an RFC 46 jobspec shape on the command line. Any other resource arguments will be ignored.",
        )

    def preinit(self, args):
        if getattr(args, "shape"):
            args.nodes = 1  ## set a number of slots, will be subsequently ignored

    def modify_jobspec(self, args, jobspec):
        s = getattr(args, "shape")
        if s:
            jobspec.jobspec["resources"] = CliJobspecParser().parse(s)
