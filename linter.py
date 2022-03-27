from os import path
from shlex import quote
import logging
import re

from SublimeLinter import lint

logger = logging.getLogger("SublimeLinter.plugins.phpstan")

AUTOLOAD_OPT_RE = re.compile(r"(-a|--autoload-file)\b")


class PhpStan(lint.Linter):
    regex = r"^(?!Note: ).*:(?P<line>[0-9]+):(?P<message>.+)"
    error_stream = lint.STREAM_STDOUT
    default_type = "error"
    multiline = False
    tempfile_suffix = "-"
    defaults = {
        "selector": "source.php",
        "use_composer_autoload": True,
        "--level": "max"
    }

    def cmd(self):
        settings = self.settings

        cmd = ["phpstan", "analyse"]
        opts = ["--error-format=raw", "--no-progress"]

        if settings.get("use_composer_autoload", True):
            autoload_file = self.find_autoload_php(self.view.file_name())
            if autoload_file:
                if any(self.autoload_opts(settings)):
                    logger.error(
                        "Composer autoload-file conflicts with PHPStan user setting.\n"
                        'Disable "use_composer_autoload" or remove "{}" from "args".'.format(
                            '", and "'.join(self.autoload_opts(settings))
                        )
                    )
                    self.notify_failure()
                    return []

                opts.append("--autoload-file={}".format(quote(autoload_file)))
        return cmd + opts + ["${args}", "--", "'${file}'"]

    def get_cmd(self):
        # We need to patch `get_cmd` to handle empty return values from `cmd`.
        cmd = self.cmd()
        return self.build_cmd(cmd) if cmd else []

    def autoload_opts(self, settings):
        return (
            setting
            for setting in self.get_user_args(settings)
            if AUTOLOAD_OPT_RE.match(setting)
        )

    def find_autoload_php(self, file_path):
        basedir = None
        while file_path:
            basedir = path.dirname(file_path)
            composer_json = "{basedir}/composer.json".format(basedir=basedir)
            composer_lock = "{basedir}/composer.lock".format(basedir=basedir)
            autoload = "{basedir}/vendor/autoload.php".format(basedir=basedir)
            if path.isfile(autoload) and (
                path.isfile(composer_json) or path.isfile(composer_lock)
            ):
                return autoload
            if basedir == file_path:
                break
            file_path = basedir
