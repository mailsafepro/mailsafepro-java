import ast
import os
from pathlib import Path
from typing import Set, List, Dict

class UndefinedNameChecker(ast.NodeVisitor):
    """Detecta nombres usados pero no definidos - Análisis en 2 fases."""
    
    def __init__(self, filename: str):
        self.filename = filename
        self.module_level_names: Set[str] = set()  # Funciones/clases del módulo
        self.defined_names: Set[str] = set()
        self.used_names: Dict[str, List[int]] = {}
        self.imports: Set[str] = set()
        self.errors: List[str] = []
        self.current_scope: List[Set[str]] = [set()]
        self.in_function_or_class = False  # Flag para saber si estamos dentro
        
    def first_pass(self, tree):
        """Primera pasada: recolectar todos los nombres de nivel módulo."""
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                self.module_level_names.add(node.name)
            elif isinstance(node, ast.ClassDef):
                self.module_level_names.add(node.name)
        
    def add_defined(self, name: str):
        self.current_scope[-1].add(name)
        self.defined_names.add(name)
        
    def is_defined(self, name: str) -> bool:
        # Primero buscar en scopes locales
        for scope in reversed(self.current_scope):
            if name in scope:
                return True
        # Luego en nivel módulo (funciones/clases definidas en el archivo)
        if name in self.module_level_names:
            return True
        # Luego en imports
        if name in self.imports:
            return True
        # Finalmente en builtins
        return name in dir(__builtins__)
    
    def enter_scope(self):
        self.current_scope.append(set())
        self.in_function_or_class = True
        
    def exit_scope(self):
        if len(self.current_scope) > 1:
            self.current_scope.pop()
        self.in_function_or_class = len(self.current_scope) > 1
    
    def visit_Import(self, node):
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name.split('.')[0]
            self.imports.add(name)
            self.add_defined(name)
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        for alias in node.names:
            if alias.name == '*':
                continue
            name = alias.asname if alias.asname else alias.name
            self.imports.add(name)
            self.add_defined(name)
        self.generic_visit(node)
        
    def visit_FunctionDef(self, node):
        self.add_defined(node.name)
        self.enter_scope()
        for arg in node.args.args:
            self.add_defined(arg.arg)
        for arg in node.args.kwonlyargs:
            self.add_defined(arg.arg)
        if node.args.vararg:
            self.add_defined(node.args.vararg.arg)
        if node.args.kwarg:
            self.add_defined(node.args.kwarg.arg)
        self.generic_visit(node)
        self.exit_scope()
        
    def visit_AsyncFunctionDef(self, node):
        self.visit_FunctionDef(node)
        
    def visit_ClassDef(self, node):
        self.add_defined(node.name)
        self.enter_scope()
        self.generic_visit(node)
        self.exit_scope()
    
    def extract_names_from_target(self, target):
        """Extrae todos los nombres de un target (maneja unpacking)."""
        if isinstance(target, ast.Name):
            self.add_defined(target.id)
        elif isinstance(target, ast.Tuple) or isinstance(target, ast.List):
            for elt in target.elts:
                self.extract_names_from_target(elt)
        elif isinstance(target, ast.Starred):
            self.extract_names_from_target(target.value)
        
    def visit_Assign(self, node):
        self.visit(node.value)
        for target in node.targets:
            self.extract_names_from_target(target)
        
    def visit_AnnAssign(self, node):
        if node.value:
            self.visit(node.value)
        self.extract_names_from_target(node.target)
            
    def visit_For(self, node):
        self.visit(node.iter)
        self.extract_names_from_target(node.target)
        for child in node.body:
            self.visit(child)
        for child in node.orelse:
            self.visit(child)
            
    def visit_With(self, node):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self.extract_names_from_target(item.optional_vars)
        for child in node.body:
            self.visit(child)
    
    def visit_AsyncWith(self, node):
        self.visit_With(node)
        
    def visit_ExceptHandler(self, node):
        if node.name:
            self.add_defined(node.name)
        self.generic_visit(node)
    
    def visit_ListComp(self, node):
        self.enter_scope()
        for generator in node.generators:
            self.visit(generator.iter)
            self.extract_names_from_target(generator.target)
            for if_ in generator.ifs:
                self.visit(if_)
        self.visit(node.elt)
        self.exit_scope()
        
    def visit_DictComp(self, node):
        self.enter_scope()
        for generator in node.generators:
            self.visit(generator.iter)
            self.extract_names_from_target(generator.target)
            for if_ in generator.ifs:
                self.visit(if_)
        self.visit(node.key)
        self.visit(node.value)
        self.exit_scope()
        
    def visit_SetComp(self, node):
        self.enter_scope()
        for generator in node.generators:
            self.visit(generator.iter)
            self.extract_names_from_target(generator.target)
            for if_ in generator.ifs:
                self.visit(if_)
        self.visit(node.elt)
        self.exit_scope()
        
    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load):
            name = node.id
            if not self.is_defined(name):
                if name not in self.used_names:
                    self.used_names[name] = []
                self.used_names[name].append(node.lineno)
        self.generic_visit(node)
        
    def report(self):
        if self.used_names:
            print(f"\n{'='*80}")
            print(f"📁 {self.filename}")
            print('='*80)
            for name, lines in sorted(self.used_names.items()):
                lines_str = ', '.join(map(str, lines[:5]))
                if len(lines) > 5:
                    lines_str += f" ... (+{len(lines)-5} más)"
                print(f"  ⚠️  '{name}' usado pero no definido en línea(s): {lines_str}")
                self.errors.append(f"{self.filename}:{lines[0]}: '{name}' no definido")
        return len(self.used_names) > 0

def check_file(filepath: Path) -> UndefinedNameChecker:
    """Analiza un archivo Python con análisis en 2 fases."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            code = f.read()
        
        tree = ast.parse(code, filename=str(filepath))
        checker = UndefinedNameChecker(str(filepath))
        
        # FASE 1: Recolectar todas las funciones/clases del módulo
        checker.first_pass(tree)
        
        # FASE 2: Analizar uso de nombres
        checker.visit(tree)
        
        return checker
    except SyntaxError as e:
        print(f"❌ Error de sintaxis en {filepath}:{e.lineno}: {e.msg}")
        return None
    except Exception as e:
        print(f"❌ Error procesando {filepath}: {e}")
        return None

def is_project_file(filepath: Path, project_root: Path) -> bool:
    """Determina si un archivo es parte del proyecto (no de librerías)."""
    path_str = str(filepath)
    
    excluded_patterns = [
        'site-packages',
        'dist-packages',
        '.venv',
        'venv',
        'env',
        '__pycache__',
        '.git',
        'node_modules',
        '.pytest_cache',
        'dist',
        'build',
        '.tox',
        'htmlcov',
        '.mypy_cache',
        '.ruff_cache',
    ]
    
    for pattern in excluded_patterns:
        if pattern in path_str:
            return False
    
    try:
        filepath.relative_to(project_root)
        return True
    except ValueError:
        return False

def scan_project(root_dir: str = ".", include_patterns: List[str] = None):
    """Escanea solo los archivos de tu proyecto."""
    root_path = Path(root_dir).resolve()
    py_files = []
    
    if include_patterns:
        for pattern in include_patterns:
            pattern_path = root_path / pattern
            if pattern_path.exists():
                for path in pattern_path.rglob('*.py'):
                    if is_project_file(path, root_path):
                        py_files.append(path)
    else:
        for path in root_path.rglob('*.py'):
            if is_project_file(path, root_path):
                py_files.append(path)
    
    if not py_files:
        print("⚠️  No se encontraron archivos Python en tu proyecto.")
        print(f"   Buscando en: {root_path}")
        return
    
    print(f"🔍 Escaneando {len(py_files)} archivos de tu proyecto...\n")
    
    total_errors = 0
    files_with_errors = 0
    all_errors = []
    
    for filepath in sorted(py_files):
        checker = check_file(filepath)
        if checker and checker.report():
            files_with_errors += 1
            total_errors += len(checker.used_names)
            all_errors.extend(checker.errors)
    
    print(f"\n{'='*80}")
    print(f"📊 RESUMEN")
    print('='*80)
    print(f"  Archivos analizados: {len(py_files)}")
    print(f"  Archivos con errores: {files_with_errors}")
    print(f"  Total de nombres indefinidos: {total_errors}")
    
    if all_errors:
        print(f"\n💾 Guardando reporte en 'undefined_names_report.txt'...")
        with open('undefined_names_report.txt', 'w', encoding='utf-8') as f:
            f.write(f"Reporte de nombres indefinidos\n")
            f.write(f"{'='*80}\n\n")
            for error in all_errors:
                f.write(f"{error}\n")
        print(f"   ✅ Reporte guardado con {len(all_errors)} errores")
    else:
        print(f"\n✅ ¡No se encontraron problemas!")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        include_patterns = sys.argv[1:]
        print(f"📂 Escaneando carpetas: {', '.join(include_patterns)}")
        scan_project(".", include_patterns)
    else:
        scan_project(".", include_patterns=["app"])
