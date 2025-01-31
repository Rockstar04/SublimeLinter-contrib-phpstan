from os import path
from shlex import quote
import logging
import json
import re

from SublimeLinter import lint

logger = logging.getLogger("SublimeLinter.plugins.phpstan")

class PhpStan(lint.Linter):
    regex = None
    error_stream = lint.STREAM_STDOUT
    default_type = "error"
    multiline = False
    tempfile_suffix = "-"

    defaults = {
        "selector": "embedding.php, source.php"
    }

    def cmd(self):
        cmd = ["phpstan", "analyse"]
        opts = ["--error-format=json", "--no-progress"]

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

    def find_errors(self, output):
        try:
            content = json.loads(output)
        except ValueError:
            logger.error(
                "JSON Decode error: We expected JSON from PHPStan, "
                "but instead got this:\n{}\n\n"
                .format(output)
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

                # If ignorable is false, then display show_quick_panle
                if 'ignorable' in error and not error['ignorable']:
                    error_list.append(error_message)

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

                yield lint.LintMatch(
                    match=error,
                    filename=file,
                    line=error['line'] - 1,
                    col=col,
                    end_col=end_col,
                    message=error_message,
                    error_type='error',
                    code='',
                )

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
                r'Static method (\w+::\w+)\(\) invoked with \d+ parameter',
            ],
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
            'property.notFound': r'Access to an undefined property [\w\\]+::\$(\w+)\.',
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
            'return.type': r'return', # to do
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

            if not is_static and identifier in {'method.nonObject', 'property.nonObject', 'assign.propertyType'}:
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
        key_match = re.search("'" + pattern + "'", line_content)

        if key_match:
            col = key_match.start() + 1
            end_col = key_match.end() - 1

            return col, end_col

        # Search with double quote "
        key_match = re.search('"' + pattern + '"', line_content)

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
