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

                # Highlight the whole line by default
                key = self.extract_offset_key(error)
                col = leading_whitespace_length
                end_col = len(line_content)

                # Try to check if we can find the locate the key in the line
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
        error_message = error['message']

        # If there is no identifier, we can't extract
        if 'identifier' not in error:
            return None

        if error['identifier'] == 'offsetAccess.notFound':
            match = re.search(r"Offset '([^']+)'", error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'argument.type':
            match = re.search(r'Parameter #\d+ \$(\w+) of method [\w\\]+::(\w+)\(\) expects .*, .+ given\.', error_message)
            if match:
                return match.group(2)

            match = re.search(r'function (\w+)', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Method ([\w\\]+)::(\w+)\(\) is unused\.', error_message)
            if match:
                return match.group(2)

        elif error['identifier'] == 'arguments.count':
            match = re.search(r'Method [\w\\]+::(\w+)\(\) invoked with \d+ parameters, \d+ required\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Static method (\w+::\w+)\(\) invoked with \d+ parameter', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'property.onlyWritten':
            match = re.search(r'Property [\w\\]+::(\$\w+) is never read, only written\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'property.unused':
            match = re.search(r'Property [\w\\]+::(\$\w+) is unused\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Static property ([\w\\]+)::(\$\w+) is unused\.', error_message)
            if match:
                return match.group(2)

        elif error['identifier'] == 'property.notFound':
            match = re.search(r'Access to an undefined property [\w\\]+::\$(\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'property.readOnlyAssignNotInConstructor':
            match = re.search(r'::\$(\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'property.nonObject':
            match = re.search(r'property \$([\w_]+) on', error_message)
            if match:
                return "->" + match.group(1)

        elif error['identifier'] == 'property.uninitializedReadonly':
            match = re.search(r'(\$\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'property.onlyRead':
            return "readonly"

        elif error['identifier'] == 'missingType.return':
            match = re.search(r'Method ([\w\\]+)::(\w+)\(\) has no return type specified\.', error_message)
            if match:
                return match.group(2)

        elif error['identifier'] == 'missingType.iterableValue':
            match = re.search(r'Method [\w\\]+::\w+\(\) has parameter (\$\w+) with no value type specified in iterable type array\.', error_message)
            if match:
                return match.group(1)
            else:
                return ": array"

        elif error['identifier'] == 'missingType.property':
            match = re.search(r'Property [\w\\]+::(\$\w+) has no type specified\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'missingType.parameter':
            match = re.search(r'Method [\w\\]+::\w+\(\) has parameter (\$\w+) with no type specified\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'method.unused':
            match = re.search(r'Method ([\w\\]+)::(\w+)\(\) is unused\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'method.notFound':
            match = re.search(r'Call to an undefined method [\w\\]+::(\w+)\(\)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'method.nameCase':
            match = re.search(r'incorrect case: (\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'method.void':
            match = re.search(r'Result of method [\w\\]+::(\w+)\(\)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'method.childParameterType':
            match = re.search(r'Parameter #(\d+) (\$\w+)', error_message)
            if match:
                return match.group(2)

        elif error['identifier'] == 'method.nonObject':
            match = re.search(r'\b([a-zA-Z_]\w*)\(\)', error_message)
            if match:
                return "->" + match.group(1)

        elif error['identifier'] == 'constructor.unusedParameter':
            match = re.search(r'Constructor of class [\w\\]+ has an unused parameter (\$\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'class.notFound':
            match = re.search(r'on an unknown class [\w\\]+\\(\w+)\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'has unknown class [\w\\]+\\(\w+) as its type\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Instantiated class [\w\\]+\\(\w+) not found\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Parameter \$\w+ of method [\w\\]+::\w+\(\) has invalid type (\w+)\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Call to method (\w+)\(\) on an unknown class (\w+)\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Method [\w\\]+::\w+\(\) has invalid return type (\w+)\.', error_message)
            if match:
                return match.group(1)

            match = re.search(r'extends unknown class [\w\\]+\\(\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'classConstant.notFound':
            match = re.search(r'(::\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'assign.propertyReadOnly':
            match = re.search(r'Property object\{[^}]*\b[^}]*\}::\$(\w+) is not writable\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'assign.propertyType':
            match = re.search(r'does not accept [\w\\]+\\(\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'constant.notFound':
            match = re.search(r'Constant (\w+) not found\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'function.nameCase':
            match = re.search(r'incorrect case: (\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'function.notFound':
            match = re.search(r'Function (\w+) not found\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'function.strict':
            match = re.search(r'Call to function (\w+)\(\)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'staticMethod.notFound':
            match = re.search(r'undefined static method (\w+::\w+)\(\)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'staticMethod.void':
            match = re.search(r'static method [\w\\]+::(\w+)\(\)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'variable.undefined':
            match = re.search(r'Undefined variable: (\$\w+)', error_message)
            if match:
                return match.group(1)

            match = re.search(r'Variable (\$\w+) might not be defined\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'interface.notFound':
            match = re.search(r'implements unknown interface [\w\\]+\\(\w+)\.', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'isset.offset':
            match = re.search(r'Offset \'(\w+)\' on array', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'staticProperty.notFound':
            match = re.search(r'static property [\w\\]+::(\$\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'return.phpDocType':
            match = re.search(r'native type (\w+)', error_message)
            if match:
                return match.group(1)

        elif error['identifier'] == 'return.type':
            return 'return'

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

            return col, end_col
