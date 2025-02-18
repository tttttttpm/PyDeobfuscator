import argparse
import ast
import astunparse
import base64
from base64 import b64decode, b64encode
import builtins
import operator
import sys

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

aliases = {}

class Deobfuscator(ast.NodeTransformer):
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
                    print("WARNING!!!")
                    print("Program calls " + function + "(\"" + node.args[0].value + "\") at " + str(node.lineno) + " line")
                    print()                  
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
                                print("WARNING!!!")
                                print("Program calls " + function + "(\"" + node.args[0].value + "\") at " + str(node.lineno) + " line")
                                print()
            elif isinstance(node.func.value, ast.Constant):
                left = node.func.value.value
                new_val = left.__getattribute__(node.func.attr)(*node.args)
                result = ast.Constant(new_val)
                result.lineno = node.lineno
                result.col_offset = node.col_offset
                return result
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


def main():
    parser = argparse.ArgumentParser(description="A Python deobfuscator.")
    parser.add_argument("-f", "--file", metavar="FILE", type=str, help="Path to the file to deobfuscate")
    parser.add_argument("-a", "--ast", action="store_true", help="Write only current AST and quit.")
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    if args.ast:
        path = args.file.replace(' ', '')
        folder = '/'.join(path.split("/")[:-1]) + "/"
        name = path.split("/")[-1].split(".")[0]
        
        try:
            with open(path, 'r') as f:
                file_content = f.read()

            tree = ast.parse(file_content)

            ast_output_path = folder + name + "_ast.py"
            with open(ast_output_path, 'w') as ast_out:
                ast_out.write(astunparse.dump(tree))


            print(f"AST output written to: {ast_output_path}")

        except FileNotFoundError:
            print(f"Error: File '{path}' not found.")
            sys.exit(1)
        sys.exit(0)
    
    elif args.file:
        path = args.file.replace(' ', '')
        folder = '/'.join(path.split("/")[:-1]) + "/"
        name = path.split("/")[-1].split(".")[0]
        
        try:
            with open(path, 'r') as f:
                file_content = f.read()

            tree = ast.parse(file_content)
            optimizer = Deobfuscator()
            tree = optimizer.visit(tree)

            ast_output_path = folder + name + "_res_ast.py"
            deobfuscated_output_path = folder + name + "_res.py"
            with open(ast_output_path, 'w') as ast_out:
                ast_out.write(astunparse.dump(tree))

            with open(deobfuscated_output_path, 'w') as deobfuscated_out:
                deobfuscated_out.write(ast.unparse(tree))

            print(f"AST output written to: {ast_output_path}")
            print(f"Deobfuscated output written to: {deobfuscated_output_path}")

        except FileNotFoundError:
            print(f"Error: File '{path}' not found.")
            sys.exit(1)

if __name__ == "__main__":
    main()
