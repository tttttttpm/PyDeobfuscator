import argparse
import ast
import base64
import builtins
import operator
import sys
import pprint
import os
import shutil
import tarfile

operations = {
    ast.LShift: operator.lshift,
    ast.RShift: operator.rshift,
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Pow: operator.pow,
    ast.FloorDiv: operator.floordiv,
    ast.Div: operator.truediv,
    ast.BitAnd: operator.and_,
    ast.BitOr: operator.or_,
    ast.BitXor: operator.xor,
}

libraries = {
    "base64" : {
        "b64decode" : base64.b64decode,
        "b64encode" : base64.b64encode,
    },
    "__builtins__" : {
        "chr" : chr,
        "ord" : ord,
        "oct" : oct,
        "ыек" : oct,
        "str" : str,
        "int" : int,
        "getattr": getattr
    },
    "builtins" : {
        "chr" : chr,
        "ord" : ord,
        "oct" : oct,
        "str" : str,
        "int" : int,
        "getattr": getattr
    },
    "bytes" : {
        "fromhex" : bytes.fromhex,
    }, 
}
functions = {
    "b64decode" : base64.b64decode,
    "b64encode" : base64.b64encode,
    "chr" : chr,
    "ord" : ord,
    "oct" : oct,
    "str" : str,
    "int" : int,
    "fromhex" : bytes.fromhex,
    "getattr" : getattr
}
evilLibraries = {
    "os" : (
        "system"
    ),
    "builtins": (
        "exec",
        "eval"
    )
}
evilFunctions = {
    "system",
    "eval",
    "exec"
}

CLEAR_COLOR = '\033[0m'
RED_COLOR = '\033[38;2;255;0;0m'
GREEN_COLOR = '\033[38;2;0;255;0m'

aliases = {}

class Deobfuscator(ast.NodeTransformer):
    def __init__(self):
        self.warnings = 0
        super().__init__()

    def generic_visit(self, node):
        ast.NodeTransformer.generic_visit(self, node)
        return node
    
    def visit(self, node):
        if node is None:
            return None
        elif isinstance(node, ast.BinOp):
            node = self.visit_BinOp(node)
        elif isinstance(node, ast.Call):
            node = self.visit_Call(node)
        elif isinstance(node, ast.alias):
            node = self.visit_alias(node)
        elif isinstance(node, ast.UnaryOp):
            node = self.visit_UnaryOp(node)
        elif isinstance(node, ast.Subscript):
            node = self.visit_Subscript(node)
        else:
            node = self.generic_visit(node)
        return node

    def visit_BinOp(self, node: ast.BinOp):
        node.left = self.visit(node.left)
        node.right = self.visit(node.right)
        if isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant):
            modified = False
            for operation, action in operations.items():
                if isinstance(node.op, operation):
                    result = ast.Constant(value=action(node.left.value, node.right.value), kind=None)
                    modified = True
                    break
            if modified:
                result.lineno = node.lineno
                result.col_offset = node.col_offset
                return result
        return node

    def visit_Subscript(self, node: ast.Subscript):
        node.value = self.visit(node.value)
        node.slice = self.visit(node.slice)
        if isinstance(node.value, ast.Constant):
            value = node.value.value
            if isinstance(node.slice, ast.Constant):
                result = ast.Constant(value=node.value.value[node.slice.value], kind = None)
                result.lineno = node.lineno
                result.col_offset = node.col_offset
                return result
            elif isinstance(node.slice, ast.Slice):
                node.slice.lower = self.visit(node.slice.lower)
                node.slice.upper = self.visit(node.slice.upper)
                node.slice.step = self.visit(node.slice.step)
                if (isinstance(node.slice.lower, ast.Constant) or node.slice.lower is None) and \
                (isinstance(node.slice.upper, ast.Constant) or node.slice.upper is None) and \
                (isinstance(node.slice.step, ast.Constant) or node.slice.step is None):
                    start, end, step = 0, len(value), 1
                    if node.slice.step is not None:
                        step = node.slice.step.value
                    if step < 0:
                        start = len(value)
                        end = -len(value) - 1
                    if node.slice.lower is not None:
                        start = node.slice.lower.value
                    if node.slice.upper is not None:
                        end = node.slice.upper.value
                    new_value = value[start:end:step]
                    result = ast.Constant(value=new_value, kind = None)
                    result.lineno = node.lineno
                    result.col_offset = node.col_offset
                    return result
        return node
          

    def visit_Call(self, node: ast.Name):
        node.func = self.visit(node.func) 
        for i in range(len(node.args)):
            node.args[i] = self.visit(node.args[i]) 
        if isinstance(node.func, ast.Name):
            if node.func.id == "getattr":
                obj = node.args[0]
                method = node.args[1]
                if isinstance(node.args[0], ast.Name) and isinstance(node.args[1], ast.Constant):
                    if node.args[0].id == "builtins":
                        res = ast.Name(id=method.value, ctx=ast.Load())
                        res.lineno = node.lineno
                        res.col_offset = node.col_offset
                        return res
            for function in functions:
                if node.func.id == function and isinstance(node.args[0], ast.Constant):
                    val = functions[function](node.args[0].value)
                    result = ast.Constant(val)
                    result.lineno = node.lineno
                    result.col_offset = node.col_offset
                    return result
            for function in evilFunctions:              
                if node.func.id == function:
                    print(RED_COLOR + "Program calls " + ast.unparse(node) + " at " + str(node.lineno) + " line" + CLEAR_COLOR)
                    self.warnings += 1
                    return node              
        elif isinstance(node.func, ast.Attribute):
            node.func.value = self.visit(node.func.value)
            if (isinstance(node.func.value, ast.Name)):
                for library in libraries:
                    if node.func.value.id == library:
                        for function in libraries[library]:
                            if node.func.attr == function:
                                if isinstance(node.args[0], ast.Constant):
                                    val = libraries[library][function](node.args[0].value)
                                    result = ast.Constant(value=(val), kind=None)
                                    return result
                for library in evilLibraries:
                    if node.func.value.id == library:
                        for function in evilLibraries[library]:
                            if node.func.attr == function:
                                print(RED_COLOR + "Program calls " + ast.unparse(node) + " at " + str(node.lineno) + " line" + CLEAR_COLOR)
                                self.warnings += 1
        return node

    def visit_UnaryOp(self, node : ast.UnaryOp): 
        node.operand = self.visit(node.operand)
        if not isinstance(node.operand, ast.Constant):
            return node

        allowed = (int, float)
        if not any(isinstance(node.operand.value, allow) for allow in allowed):
            return node

        operations = {
            ast.Invert: operator.invert,
            ast.USub: operator.neg,
        }
        for operation, action in operations.items():
            if isinstance(node.op, operation):
                node.operand.value = action(node.operand.value)
                return node.operand
    def visit_alias(self, node):
        return self.generic_visit(node)

def deobfuscate(obf: str) -> tuple[str, str, str, str, int]:
    ''' deobfuscate code. returns (obf, obf_ast, deobf, deobf_ast, warnings). '''
    tree = ast.parse(obf)
    obf_ast = pprint.pformat(ast.dump(tree))
    deobfuscator = Deobfuscator()
    tree = deobfuscator.visit(tree)
    deobf_ast = pprint.pformat(ast.dump(tree))
    deobf = ast.unparse(tree)
    return (obf, obf_ast, deobf, deobf_ast, deobfuscator.warnings)

def deobfuscate_file(file_path: str, save: bool = True, save_to: str | None = None) -> int:
    file_path = os.path.abspath(file_path)
    if not os.path.isfile(file_path):
        print(f"{file_path}: no such file.")
        return 0
    dir = os.path.dirname(file_path)
    fnm = os.path.basename(file_path)
    if not fnm.endswith(".py"):
        print(f"{fnm} is not a Python file, skipping...")
        return 0
    print(f"\nStarting deobfuscation of {file_path}")
    with open(file_path, "r") as file:
        source = file.read()
    source, src_ast, result, res_ast, warnings = deobfuscate(source)
    if save:
        if save_to is None:
            save_to = dir + "/deobfuscated_" + fnm
        with open(save_to, "w") as file:
            file.write(result)
        print(f"Deobfuscated code saved to {save_to}.")
    print(RED_COLOR if warnings else GREEN_COLOR, end = '')
    print(f"Found {warnings} suspicious lines.", end='')
    print(CLEAR_COLOR)
    return warnings


def deobfuscate_dir(dir_path: str, save: bool = True, save_to: str | None = None) -> int:
    dir_path = os.path.abspath(dir_path)
    if not os.path.isdir(dir_path):
        print(f"{dir_path}: no such directory.")
        return 0
    print(f"\nStarting deobfuscation of {dir_path}")
    dir = os.path.dirname(dir_path)
    dnm = os.path.basename(dir_path)
    total = 0
    if save_to is None:
        save_to = dir + "/deobfuscated_" + dnm
    for dirpath, dirnames, filenames in os.walk(dir_path):
        rel = dirpath.removeprefix(dir_path)
        if save:
            os.makedirs(save_to + rel, exist_ok=True)
        for fnm in filenames:
            save_to_single = save_to + rel + "/" + fnm
            total += deobfuscate_file(dirpath + "/" + fnm, save, save_to_single)
    print()
    print(RED_COLOR if total else GREEN_COLOR, end = '')
    print(f"Found {total} suspicious lines total.", end='')
    print(CLEAR_COLOR)
    return total
        
def extract_all(dir_path):
    for name in os.listdir(dir_path):
        if name == ".." or name == ".":
            continue
        fpth = dir_path + '/' + name
        if os.path.isfile(fpth):
            try:
                tf = tarfile.open(fpth)
                os.remove(fpth)
                tf.extractall(fpth)
                tf.close()
            except:
                pass
        if os.path.isdir(fpth):
            extract_all(fpth)

def deobfuscate_module(module_name: str, 
        save_downloaded: bool = False, save_downloaded_to: str | None = None, 
        save_installed: bool = False, save_installed_to: str | None = None,
        save: bool = True, save_to: str | None = None, force_installing: bool = True):
    
    if save_downloaded_to is None:
        save_downloaded_to = "."
    save_downloaded_to = os.path.abspath(save_downloaded_to)
    downloaded_path = save_downloaded_to + "/downloaded_" + module_name 
    os.system(f"python3 -m pip download {module_name} -d {downloaded_path}")
    extract_all(downloaded_path)
    warnings = deobfuscate_dir(downloaded_path, save, save_to=save_to)
    if not save_downloaded:
        shutil.rmtree(downloaded_path, ignore_errors=False)

    if warnings == 0:
        print(GREEN_COLOR + "Nothing bad was found!" + CLEAR_COLOR)
    else:
        if not force_installing:
            print(RED_COLOR + "Suspicious lines were found, stopping." + CLEAR_COLOR)
            print("If you still want to install this, use --force-installing option.")
            return
        print(RED_COLOR + "Suspicious lines were found." + CLEAR_COLOR)

    print("Installing...")

    if save_installed_to is None:
        save_installed_to = "."
    save_installed_to = os.path.abspath(save_installed_to)
    installed_path = save_installed_to + "/installed_" + module_name 
    os.system(f"python3 -m pip install {module_name} -t {installed_path}")
    warnings = deobfuscate_dir(installed_path, save, save_to=save_to)
    if not save_installed:
        shutil.rmtree(installed_path, ignore_errors=True)

    if warnings == 0:
        print(GREEN_COLOR + "Nothing bad was found!" + CLEAR_COLOR)
    else:
        print(RED_COLOR + f"{warnings} suspicious lines were found." + CLEAR_COLOR)
      


def main(): 
    parser = argparse.ArgumentParser(description="A Python deobfuscator.")

    parser.add_argument("-f", "--file", metavar="FILE", type=str, help="Scan file.")
    parser.add_argument("-d", "--dir", metavar="DIRECTORY", type=str, help="Scan all Python files in directory.")
    parser.add_argument("-m", "--module", metavar="MODULE", type=str, help="Scan module from PyPI.")
    parser.add_argument("-s", "--dont-save-deobfuscated", action="store_true", help="Don't save deobfuscated output.")
    parser.add_argument("-F", "--force-installing", action="store_true", help="Install package even with warnings on downloading.")

    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        return 0
    
    sd: bool = not args.dont_save_deobfuscated

    if args.file:
        deobfuscate_file(args.file, sd)
    
    if args.dir:
        deobfuscate_dir(args.dir, sd)

    if args.module:
        deobfuscate_module(args.module, save=sd, force_installing=args.force_installing)

    return 0

if __name__ == "__main__":
    main()
