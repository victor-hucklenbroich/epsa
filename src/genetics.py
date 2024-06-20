import copy
import os
import random
import string
from enum import Enum

from preprocessor import search_dir
from src import constants


class Genetype(Enum):
    EMPTY = -1
    STATEMENT = 0
    CALL = 1
    FLOW = 2
    FUNCTION = 3


class Function:
    RETURN_TYPES: list = ['void', 'int', 'char', 'float', 'double']

    def __init__(self, name: str, ret: str, params: [(str, str)]):
        self.name = name
        self.ret = ret
        self.params = params

    def get_definition(self) -> str:
        definition: str = self.ret + " " + self.name + "("
        if self.params:
            definition += self.params[0][0] + " " + self.params[0][1]
        for i in range(len(self.params)):
            if i >= 1:
                param: (str, str) = self.params[i]
                definition += ", " + param[0] + " " + param[1]

        definition += ")"
        return definition


class Gene:
    def __init__(self, type: Genetype, contents: [str], nested: list):
        self.type = type
        self.contents = contents
        self.nested = nested

    def get_content(self) -> str:
        if not self.nested:
            return ''.join(self.contents)
        else:
            content: str = self.contents[0]
            i: int = 1
            while i < len(self.contents):
                if i <= len(self.nested):
                    content += self.contents[i].format(self.nested[i - 1].get_content())
                else:
                    content += self.contents[i]
                i += 1
            return content


class Genome:
    def __init__(self, location: int, min_type: Genetype, genes: [Gene]):
        self.location = location
        self.min_type = min_type
        self.genes = genes

    def get_code(self) -> str:
        code: str = "\n"
        for gene in self.genes:
            code += gene.get_content() + "\n"
        return code


class Source:
    def __init__(self, path: str, code: [str], genomes: [Genome]):
        self.path = path
        self.code = code
        self.genomes = genomes

    def include_noise_header(self):
        for i in range(len(self.code)):
            if self.code[i].contains("#include"):
                self.code.insert("#include " + constants.NOISE_HEADER + "\n")
                return

    def write_code(self):
        self.include_noise_header()
        current_genome: int = 1
        i: int = 0
        output: str = self.genomes[0].get_code()
        while i < len(self.code):
            output += self.code[i]
            i += 1
            if current_genome < len(self.genomes) and self.genomes[current_genome].location == i:
                output += self.genomes[current_genome].get_code()
                current_genome += 1

        with open(self.path, "w") as f:
            f.writelines(output)


class Individual:
    def __init__(self, path: str, sources: [Source], additions: [Function]):
        self.path = path
        self.sources = sources
        self.additions = additions

    def write_code(self):
        self.generate_noise_header()
        for source in self.sources:
            source.write_code()

    def generate_noise_header(self):
        path: str = os.path.join(constants.TEST_PROGRAM_PATH, constants.NOISE_HEADER + ".h")
        content: str = ("#ifndef " + constants.NOISE_HEADER + "\n" +
                        "#define " + constants.NOISE_HEADER + "\n")
        for function in self.additions:
            content += function.get_definition() + ";\n"

        content += "#endif\n"
        with open(path, "w") as h:
            h.writelines(content)


def encode_source(path: str) -> Source:
    with open(path, "r") as s:
        code = s.readlines()

    genomes: list = [Genome(0, Genetype.FUNCTION, [])]
    i: int = 0
    while i < len(code):
        line: str = code[i]
        if (") {" in line or "){" in line) and "#" not in line and ";" and "\\" not in line and "}" not in line:
            genomes.append(Genome(i, Genetype.EMPTY, []))
        i += 1

    return Source(path, code, genomes)


def initial_population(p: str, size: int) -> list:
    population: list = []
    sources: list = []
    files: [str] = search_dir(p)
    for source in files:
        sources.append(encode_source(source))
    first: Individual = Individual(p, sources, [])
    population.append(first)
    i: int = 0
    while i < size - 1:
        c: Individual = copy.deepcopy(population[0])
        population.append(c)
        i += 1

    for individual in population:
        for source in individual.sources:
            for genome in source.genomes:
                if 0 == random.randint(0, 10):
                    genome.genes.append(generate_gene(individual, genome.min_type))
    return population


def generate_gene(i: Individual, min_type: Genetype) -> Gene:
    gene: Gene
    if Genetype.STATEMENT == min_type:
        gene = generate_statement_gene()
    elif Genetype.CALL == min_type:
        gene = generate_call_gene(i)
    elif Genetype.FLOW == min_type:
        gene = generate_flow_gene(i)
    elif Genetype.FUNCTION == min_type:
        gene = generate_function_gene(i)
    else:
        gene = generate_empty_gene()
    return gene


def generate_empty_gene() -> Gene:
    return Gene(Genetype.EMPTY, [""], [])


def generate_statement_gene(variables: [str] = None) -> Gene:
    assign_existing: bool = False
    if variables is not None:
        assign_existing: bool = bool(random.getrandbits(1))
    var: str
    if assign_existing:
        var = random.choice(variables)
    else:
        var = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(1, 8)))
    content: str = var + " = "
    simple: bool = bool(random.getrandbits(1))
    if simple:
        content += str(random.randint(0, 255))
    else:
        for i in range(random.randint(2, 4)):
            if variables is not None and bool(random.getrandbits(1)):
                content += random.choice(variables)
            else:
                content += str(random.randint(0, 32767))
            content += " " + random.choice(['+', '-', '*', '/']) + " "
        content = content[:-3]
    content += ";\n"
    return Gene(Genetype.STATEMENT, [content], [])


def generate_call_gene(i: Individual, origin: Function = None, parameters: [str] = None) -> Gene:
    available_functions: list
    if origin is not None:
        index = i.additions.index(origin)
        available_functions = copy.deepcopy(i.additions)
        del available_functions[index]
    else:
        available_functions = i.additions
    if not available_functions:
        return generate_empty_gene()
    func: Function = random.choice(available_functions)
    call: str = func.name + "("
    for param in func.params:
        if param[0] == 'char':
            call += str(random.randint(0, 255))
        elif param[0] == 'int':
            call += str(random.randint(-32768, 32767))
        else:
            call += str(random.uniform(0, 10))
        call += ", "
    call = call[:-2] + ");\n"
    return Gene(Genetype.CALL, [call], [])


def generate_flow_gene(i: Individual, origin: Function = None, variables: [str] = None) -> Gene:
    #flow_type: int = random.
    return Gene(Genetype.EMPTY, [""], [])


def generate_function_gene(i: Individual) -> Gene:
    # Function head
    name: str = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(5, 15)))
    ret: str = random.choice(Function.RETURN_TYPES)
    params: list = []
    for x in range(random.randint(0, 4)):
        n: str = ''.join(random.choice(string.ascii_letters) for i in range(random.randint(4, 8)))
        r: str = random.choice(Function.RETURN_TYPES)
        if r != "void":
            params.append((r, n))
    func: Function = Function(name, ret, params)
    i.additions.append(func)
    contents: [str] = [func.get_definition() + " {\n"]

    # Function content
    nested: list = []
    for y in range(random.randint(0, 10)):
        contents.append("{0}")
        g: int = random.randint(0, 4)
        if g < 3:
            nested.append(generate_statement_gene()) # TODO add variables
        elif g == 3:
            nested.append(generate_call_gene(i, origin=func)) # TODO add parameters
        else:
            nested.append(generate_flow_gene(i, func))  # TODO add variables

    # Function return
    if ret != "void":
        contents.append("return " + str(random.randint(0, 255)) + ";\n")
    contents.append("}")
    return Gene(Genetype.FUNCTION, contents, nested)
