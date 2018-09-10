from SublimeLinter.lint import Linter


class PhpStan(Linter):
    cmd = 'phpstan', 'analyse', '--error-format=raw', '--no-progress', '${args}', '${file}'
    regex = r'^.*:(?P<line>[0-9]+):(?P<message>.+)'
    default_type = 'error'
    multiline = False
    tempfile_suffix = '-'
    defaults = {
        'selector': 'source.php',
        '--autoload-file': '${file}',
        '--level': 'max',
    }
