from functools import partial
from os import path
from shlex import quote
import logging
import json
import re
import sublime_plugin

from SublimeLinter import lint
from SublimeLinter.lint.quick_fix import (QuickAction, extend_existing_comment, insert_preceding_line, line_error_is_on, merge_actions_by_code_and_line, quick_actions_for, read_previous_line)

logger = logging.getLogger("SublimeLinter.plugins.phpstan")

class AutoLintOnTabSwitchListener(sublime_plugin.ViewEventListener):
    @classmethod
    def is_applicable(cls, settings):
        return True

    def on_activated_async(self):
        if self.view.file_name() and self.view.file_name().endswith(".php"):
            self.view.run_command("sublime_linter_lint")

class PhpStan(lint.PhpLinter):
    tempfile_suffix = "-"

    defaults = {
        "selector": "embedding.php, source.php"
    }

    # These lines will be stripped from stderr, allowing the remainder through (if any)
    stderr_strip_regexes = [
        # This is necessary because phpstan may be passed the `-v` argument, which also causes it to output some stats on stderr
        # Rather than always requiring phpstan to run non-verbosely (which isn't very friendly), we'll simply try to strip the relevant lines
        re.compile(r'^Elapsed time: .*?(\r?\nUsed memory: .*)?$', re.MULTILINE),
    ]

    # If the remainder of stderr matches one of these strings entirely, we'll change it to a warning instead of an error
    stderr_warning_strings = [
        # This is needed because you may e.g. be editing a file which is excluded by phpstan, which also means it won't output any JSON at all
        '[ERROR] No files found to analyse.',
    ]

    def cmd(self):
        cmd = ["phpstan", "analyse"]
        opts = ["--error-format=json", "--no-progress"]

        # if we have arguments for configuration and autoload file, we don't need to find them
        if self.have_argument("--configuration") and self.have_argument("--autoload-file"):
            return cmd + ["${args}"] + opts + ["--", "${file}"]

        configPath = self.find_phpstan_configuration(self.view.file_name())

        if configPath:
            opts.append("--configuration={}".format(quote(configPath)))

            autoload_file = self.find_autoload_php(configPath)

            if autoload_file:
                opts.append("--autoload-file={}".format(quote(autoload_file)))

                cmd[0] = autoload_file.replace("/autoload.php", "/bin/phpstan")
            else:
                print("⚠️ Fallback on PHPStan installed globally")
        else:
            print("⚠️ phpstan.neon has not been found - Fallback on PHPStan installed globally")

        return cmd + ["${args}"] + opts + ["--", "${file}"]

    def have_argument(self, name):
        if self.settings.get('args'):
            for arg in self.settings.get('args'):
                if arg.startswith(name):
                    return True

        return False

    def find_autoload_php(self, configPath):
        pathAutoLoad = configPath.replace("/phpstan.neon", "/vendor/autoload.php")

        if (path.isfile(pathAutoLoad)):
            return pathAutoLoad

        return None

    def find_phpstan_configuration(self, file_path):
        basedir = None
        while file_path:
            basedir = path.dirname(file_path)
            configFiles = (
                "{basedir}/phpstan.neon".format(basedir=basedir),
                "{basedir}/phpstan.neon.dist".format(basedir=basedir),
            )

            for configFile in configFiles:
                if (path.isfile(configFile)):
                    return configFile

            if (basedir == file_path):
                break

            file_path = basedir

    def on_stderr(self, stderr):
        for strip_regex in self.stderr_strip_regexes:
            stderr = re.sub(strip_regex, '', stderr).strip()

        if not stderr:
            return

        # Since we check for exact matches here, stripping stuff via regex should be done before this (since phpstan can still emit the elapsed time and we don't need that)
        for warning_str in self.stderr_warning_strings:
            if warning_str == stderr:
                logger.warning(stderr)
                self.notify_failure()
                return

        logger.error(stderr)
        self.notify_failure()

    def parse_output(self, proc, virtual_view):
        assert proc.stdout is not None
        assert proc.stderr is not None

        stderr = proc.stderr.strip()
        if stderr:
            self.on_stderr(stderr)

        stdout = proc.stdout.strip()
        if not stdout:
            logger.info('PHPStan returned no output')
            return

        try:
            content = json.loads(stdout)
        except ValueError:
            logger.error(
                "JSON Decode error: We expected JSON from PHPStan, "
                "but instead got this:\n{}\n\n"
                .format(stdout)
            )
            self.notify_failure()
            return

        if 'files' not in content:
            return

        for file in content['files']:
            for error in content['files'][file]['messages']:
                # If there is a tip we should display it instead of error
                # as it is more useful to solve the problem
                error_message = error['message']

                error_identifier = error['identifier'] if 'identifier' in error else ''

                if 'tip' in error:
                    # the character • is used for list of tips
                    tip = error['tip'].replace("•", "💡")

                    if not tip.startswith("💡"):
                        tip = "💡 " + tip

                    error_message = error_message + "\n" + tip

                line_region = self.view.line(self.view.text_point(error['line'] - 1, 0))
                line_content = self.view.substr(line_region)

                stripped_line = line_content.lstrip()
                leading_whitespace_length = len(line_content) - len(stripped_line)

                # Highlight the whole line in which the error is reported by default
                key = self.extract_offset_key(error)
                col = leading_whitespace_length
                end_col = len(line_content)

                # Try to check if we can find the position of the key in the line
                if key:
                    pos = self.find_position_key(key, line_content)

                    if pos is not None:
                        col = pos[0]
                        end_col = pos[1]

                match = lint.LintMatch(
                    match=error,
                    filename=file,
                    line=error['line'] - 1,
                    col=col,
                    end_col=end_col,
                    message=error_message,
                    error_type='error',
                    code=error_identifier,
                )

                processed_error = self.process_match(match, virtual_view)
                if processed_error:
                    # We'll display some quick actions for ignorable errors later
                    if 'ignorable' not in error or error['ignorable']:
                        processed_error['ignore_error'] = error['message']
                    yield processed_error

    def extract_offset_key(self, error):
        # If there is no identifier, we can't extract
        if 'identifier' not in error:
            return None

        identifier = error['identifier']

        if identifier == 'return.type':
            return 'return'

        elif identifier == 'method.visibility':
            return 'private'

        elif identifier == 'constructor.missingParentCall':
            return '__construct'

        # List of regex patterns per error identifier
        patterns = {
            'argument.type': [
                r'::(\w+)\(\)',
                r'function (\w+)',
                r'Method [\w\\]+::(\w+)\(\) is unused\.',
            ],
            'arguments.count': [
                r'Method [\w\\]+::(\w+)\(\) invoked with \d+ parameters, \d+ required\.',
                r'::(\w+)\(\)',
            ],
            'array.duplicateKey': r"value '([^']+)'",
            'assign.propertyReadOnly': r'Property object\{[^}]*\b[^}]*\}::\$(\w+) is not writable\.',
            'assign.propertyType': [
                r'does not accept [\w\\]+\\(\w+)\.',
                r'::\$(\w+)',
                r'::(\$\w+)',
            ],
            'class.notFound': [
                r'on an unknown class [\w\\]+\\(\w+)\.',
                r'has unknown class [\w\\]+\\(\w+) as its type\.',
                r'Instantiated class [\w\\]+\\(\w+) not found\.',
                r'Parameter \$\w+ of method [\w\\]+::\w+\(\) has invalid type (\w+)\.',
                r'Call to method (\w+)\(\) on an unknown class (\w+)\.',
                r'Method [\w\\]+::\w+\(\) has invalid return type (\w+)\.',
                r'extends unknown class [\w\\]+\\(\w+)\.'
            ],
            'classConstant.notFound': r'(::\w+)\.',
            'constant.notFound': r'Constant (\w+) not found\.',
            'constructor.unusedParameter': r'Constructor of class [\w\\]+ has an unused parameter (\$\w+)\.',
            'function.nameCase': r'incorrect case: (\w+)',
            'function.notFound': r'Function (\w+) not found\.',
            'function.strict': r'Call to function (\w+)\(\)',
            'interface.notFound': r'implements unknown interface [\w\\]+\\(\w+)\.',
            'isset.offset': r'static property [\w\\]+::(\$\w+)',
            'method.childParameterType': r'Parameter #\d+ \$(\w+)',
            'method.nameCase': r'incorrect case: (\w+)',
            'method.nonObject': r'\b([a-zA-Z_]\w*)\(\)',
            'method.notFound': r'Call to an undefined method [\w\\]+::(\w+)\(\)\.',
            'method.unused': r'::(\w+)\(\)',
            'method.void': r'Result of method [\w\\]+::(\w+)\(\)',
            'missingType.iterableValue': r'Method [\w\\]+::\w+\(\) has parameter (\$\w+) with no value type specified in iterable type array\.',
            'missingType.parameter': r'Method [\w\\]+::\w+\(\) has parameter (\$\w+) with no type specified\.',
            'missingType.property': r'Property [\w\\]+::(\$\w+) has no type specified\.',
            'missingType.return': r'::(\w+)\(\)',
            'offsetAccess.notFound': r"Offset '([^']+)'",
            'property.notFound': r'::\$(\w+)',
            'property.nonObject': r'property \$([\w_]+) on',
            'property.onlyRead': r'::\$(\w+)',
            'property.onlyWritten': [
                r'Property [\w\\]+::(\$\w+) is never read, only written\.',
                r'Static property [\w\\]+::(\$\w+) is never read, only written\.',
            ],
            'property.readOnlyAssignNotInConstructor': r'Cannot assign to a read-only property [\w\\]+::\$(\w+)',
            'property.uninitializedReadonly': [
                r'(\$\w+)',
                r'::\$(\w+)',
            ],
            'property.unused': [
                r'Property [\w\\]+::(\$\w+) is unused\.',
                r'Static property [\w\\]+::(\$\w+) is unused\.',
            ],
            'return.phpDocType': r'native type (\w+)',
            'return.unusedType': r'never returns (\w+)',
            'staticMethod.notFound': r'undefined static method (\w+::\w+)\(\)\.',
            'staticMethod.void': r'static method [\w\\]+::(\w+)\(\)',
            'staticProperty.notFound': r'static property [\w\\]+::(\$\w+)',
            'variable.undefined': [
                r'Undefined variable: (\$\w+)',
                r'Variable (\$\w+) might not be defined\.'
            ],
        }

        key = self.parse_pattern(patterns, error)

        if key is not None:
            if identifier == 'property.uninitializedReadonly':
                # remove the first character $
                return key[1:]

            is_static = False
            if 'static' in error['message']:
                is_static = True

            if not is_static and identifier in {'method.nonObject', 'property.notFound', 'property.nonObject', 'assign.propertyType'}:
                return "->" + key

        else:
            if identifier == 'missingType.iterableValue':
                return ": array"

            if identifier == 'property.onlyRead':
                return "readonly"

        return key

    def parse_pattern(self, patterns, error):
        error_message = error['message']
        identifier = error['identifier']

        if identifier in patterns:
            pattern = patterns[identifier]
            if isinstance(pattern, list):
                for pat in pattern:
                    match = re.search(pat, error_message)
                    if match:
                        return match.group(1)
            else:
                match = re.search(pattern, error_message)

                if match:
                    return match.group(1)

        return None

    def find_position_key(self, key, line_content):
        pattern = rf"{key}"
        # Check if key begins with $
        if key.startswith('$'):
            pattern = rf"\{key}"

        # Below we will do 3 searches, the first 2 because of associative arrays
        # can use ' or ". Example $data["index"] and $data['index']
        #
        # Search with single quote '
        key_match = re.search("\\['" + pattern + "'\\]", line_content)

        if key_match:
            col = key_match.start() + 1
            end_col = key_match.end() - 1

            return col, end_col

        # Search with double quote "
        key_match = re.search('\\["' + pattern + '"\\]', line_content)

        if key_match:
            col = key_match.start() + 1
            end_col = key_match.end() - 1

            return col, end_col

        # Original search, without any quote
        key_match = re.search(pattern, line_content)

        if key_match:
            # Compute the start and end columns
            col = key_match.start()
            end_col = key_match.end()

            # Adjust to the actual position of the key of the object
            if key.startswith('->'):
                col = key_match.start() + 2
            elif key.startswith(': '):
                col = key_match.start() + 2

            # Include $ if there is $ just before the key
            if line_content[col-1:col] == '$':
                col = col - 1

            return col, end_col

@quick_actions_for('phpstan')
def phpstan_actions_provider(errors, view):
    def make_action(error):
        # Newer phpstan versions actually require a specific identifier to ignore, the fallback is just for some backwards compatibility
        # Note though that without a valid identifier, the on-hover quick actions won't list it (still works via the Command Palette though)
        return QuickAction(
            'phpstan: Ignore {}'.format(error['code'] if error['code'] != '' else 'all errors'),
            partial(phpstan_ignore_error, error),
            '{ignore_error}'.format(**error),
            solves=[error]
        )

    except_errors = lambda error: 'ignore_error' not in error
    yield from merge_actions_by_code_and_line(make_action, except_errors, errors, view)

def phpstan_ignore_error(error, view):
    line = line_error_is_on(view, error)
    error_identifier = error['code']
    if error_identifier == '':
        # We're just always gonna insert a new line; either it's a new comment anyway, or it's another `@phpstan-ignore` **with** identifiers and we probably shouldn't touch those
        yield insert_preceding_line(
            '// @phpstan-ignore-next-line',
            line,
        )
    else:
        yield (
            extend_existing_comment(
                r'// @phpstan-ignore (?P<codes>[\w\-./]+(?:,\s?[\w\-./]+)*)(?P<comment>\s+\()?',
                ', ',
                {error_identifier},
                read_previous_line(view, line),
            )
            or insert_preceding_line(
                '// @phpstan-ignore {}'.format(error_identifier),
                line,
            )
        )
