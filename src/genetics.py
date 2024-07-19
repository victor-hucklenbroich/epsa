import copy
import os
import random
import string
import time
from enum import Enum
from pathlib import Path

from multipledispatch import dispatch

from preprocessor import search_dir, clean, compile_program
from src import constants, pss, logger


class ModMode(Enum):
    OBFUSCATE = 0
    HARMONIZE = 1


mode: ModMode = ModMode.HARMONIZE


class Genetype(Enum):
    EMPTY = -1
    STATEMENT = 0
    CALL = 1
    FLOW = 2
    FUNCTION = 3


class Function:
    VAR_TYPES: list = ['int', 'char', 'float', 'double']
    RETURN_TYPES: list = VAR_TYPES + ['void']

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
    NESTED_PLACEHOLDER = "{0}"

    def __init__(self, type: Genetype, contents: [str], nested: list, func: Function = None):
        self.type = type
        self.contents = contents
        self.fixed = False
        self.nested = nested
        self.function = func

    def set_fixed(self, value):
        self.fixed = value

    def append_nested(self, gene):
        self.contents.insert(len(self.contents) / 2, Gene.NESTED_PLACEHOLDER)
        self.nested.append(gene)

    def get_content(self) -> str:
        if not self.nested:
            return ''.join(self.contents)
        else:
            content: str = ''
            i: int = 0
            n: int = 0
            while i < len(self.contents):
                if self.contents[i] == self.NESTED_PLACEHOLDER:
                    content += self.contents[i].format(self.nested[n].get_content())
                    n += 1
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

    def dump_genes(self):
        self.genes = []


class Source:
    def __init__(self, path: str, code: [str], genomes: [Genome]):
        self.path = path
        self.code = code
        self.genomes = genomes

    def write_code(self):
        output: str = "#include \"" + constants.NOISE_HEADER + ".h\"\n"
        output += self.genomes[0].get_code() + self.code[0]
        current_genome: int = 1
        i: int = 1
        while i < len(self.code):
            output += self.code[i]
            i += 1
            if current_genome < len(self.genomes) and self.genomes[current_genome].location == i:
                output += self.genomes[current_genome].get_code()
                current_genome += 1

        with open(self.path, "w") as f:
            f.writelines(output)


class Individual:
    def __init__(self, path: str, sources: [Source], additions: [Function], alive: int,
                 fit: float = constants.MIN_FITNESS):
        self.path = path
        self.sources = sources
        self.additions = additions
        self.alive_since = alive
        self.fitness = fit

    def __str__(self) -> str:
        return str(hash(self))

    def write_code(self):
        self.generate_noise_header()
        for source in self.sources:
            source.write_code()

    def generate_noise_header(self):
        path: str = os.path.join(constants.TEST_SOURCES_PATH, constants.NOISE_HEADER + ".h")
        content: str = ("#ifndef " + constants.NOISE_HEADER + "\n" +
                        "#define " + constants.NOISE_HEADER + "\n")
        for function in self.additions:
            content += function.get_definition() + ";\n"

        content += "#endif\n"
        with open(path, "w") as h:
            h.writelines(content)

    def get_genes(self) -> [Gene]:
        genes: [Gene] = []
        for source in self.sources:
            for genome in source.genomes:
                for gene in genome.genes:
                    genes.append(gene)
        return genes

    def set_fitness(self, f):
        if f > self.fitness or f == constants.MIN_FITNESS:
            self.fitness = f

    def add_gene(self, gene: Gene):
        source: Source = random.choice(self.sources)
        if gene.type == Genetype.FUNCTION:
            source.genomes[0].genes.append(gene)
        else:
            genome: Genome = random.choice(source.genomes)
            genome.genes.append(gene)

    def distribute_genes(self, genes: [Gene]):
        for gene in genes:
            self.add_gene(gene)


def encode_source(path: str) -> Source:
    with open(path, "r") as s:
        code = s.readlines()
    genomes: list = [Genome(0, Genetype.FUNCTION, [])]
    i: int = 0
    while i < len(code):
        line: str = code[i]
        if " " in line and (
                ") {" in line or "){" in line) and "#" not in line and ";" and "\\" not in line and "}" not in line:
            genomes.append(Genome(i + 1, Genetype.EMPTY, []))
        i += 1

    return Source(path, code, genomes)


def encode_individual(p: str, generation: int) -> Individual:
    sources: list = []
    files: [str] = search_dir(p)
    for source in files:
        sources.append(encode_source(source))
    return Individual(p, sources, [], generation)


def run() -> (list, list):
    features: (list, list) = constants.FEATURES
    population: list = initial_population(constants.TEST_PROGRAM_PATH, constants.POPULATION_SIZE)
    i: int = 0
    # evolutionary cycle
    while i < constants.GENERATIONS:
        previous: list = copy.deepcopy(population)
        population = evolutionary_cycle(i, population, previous, features)
        i += 1

    # last Generation
    fitness_sort(population, features)
    log_generation(i, population)
    clean(Path(constants.TEST_PROGRAM_PATH), replace_with_archives=True)
    best: Individual = population[0]
    best.write_code()
    compile_program(constants.TEST_PROGRAM_PATH)
    logger.log("best individual:  ", level=2)
    log_individual(best)
    return pss.compute_features(constants.BINARY_PATH)


def initial_population(p: str, size: int) -> list:
    clean(p, replace_with_archives=True)
    population: list = [copy.deepcopy(encode_individual(constants.TEST_PROGRAM_PATH, 0))]
    i: int = 0
    while i < size - 1:
        c: Individual = copy.deepcopy(population[0])
        population.append(c)
        i += 1

    for individual in population:
        create_individual(base=individual)
    return population


def create_individual(generation: int = 0, base: Individual = None) -> Individual:
    if base is None:
        clean(Path(constants.TEST_PROGRAM_PATH), replace_with_archives=True)
        base = encode_individual(constants.TEST_PROGRAM_PATH, generation + 1)
    for source in base.sources:
        for genome in source.genomes:
            if 0 == random.randint(0, 3):
                genome.genes.append(generate_gene(base, genome.min_type))
    return base


def evolutionary_cycle(generation: int, population: list, previous: list, features: (list, list)) -> list:
    fitness_sort(population, features)
    if population[0].fitness == constants.MIN_FITNESS:
        logger.log("unfit generation, rollback to #" + str(generation - 1))
        population = previous
    log_generation(generation, population)
    pop = selection(population, generation)
    pop += crossover(pop, generation)
    mutation(pop)
    return pop


def fitness(i: Individual, features: (list, list)) -> float:
    clean(Path(constants.TEST_PROGRAM_PATH), replace_with_archives=True)
    i.write_code()
    start_time: float = time.time()
    t: float
    fit: float
    try:
        compile_program(constants.TEST_PROGRAM_PATH)
        sim: float = pss.compare(constants.BINARY_PATH, features[0], features[1])
        logger.log(str(i) + ":pss = " + str(sim), level=1)
        t = time.time() - start_time
        if mode == ModMode.OBFUSCATE:
            fit = 1 - sim - ((t - 65) ** 2) * 0.0001
        else:
            fit = 0 + sim - ((t - 65) ** 2) * 0.0001
    except Exception as e:
        logger.log(e.__str__())
        t = time.time() - start_time
        fit = constants.MIN_FITNESS
    logger.log(str(i) + ": compilation, angr analysis, pss took " + str(round(t, 2)) + " seconds", level=1)
    i.set_fitness(fit)
    return fit


def fitness_sort(population: list, features: (list, list)):
    for individual in population:
        fitness(individual, features)
    population.sort(reverse=True, key=lambda i: i.fitness)


def selection(population: list, generation: int) -> list:
    logger.log("Selection: ", level=2)
    selected: list = []
    for i in range(int(constants.POPULATION_SIZE * constants.SELECTION_RATIO)):
        if population[i].fitness == constants.MIN_FITNESS:
            selected.append(create_individual(generation=generation))
        else:
            selected.append(population[i])
        logger.log(population[i].__str__(), level=2)

    return selected


def crossover(parents: list, generation: int) -> list:
    logger.log("\nCrossover: ", level=2)
    clean(Path(constants.TEST_PROGRAM_PATH), replace_with_archives=True)
    base: Individual = encode_individual(constants.TEST_PROGRAM_PATH, generation + 1)
    offspring: list = []
    for i in range(len(parents) - 1):
        j: int = i + 1
        while j < len(parents):
            p1: Individual = parents[i]
            p2: Individual = parents[j]
            child: Individual = copy.deepcopy(base)
            # Uniform sources crossover
            for s in range(len(child.sources)):
                if bool(random.getrandbits(1)):
                    child.sources[s] = p1.sources[s]
                else:
                    child.sources[s] = p2.sources[s]
                child.sources[s].genomes[0].dump_genes()
            # Generate missing functions
            for addition in p1.additions + p2.additions:
                if addition not in child.additions:
                    child.add_gene(generate_function_gene(child, addition))
                    child.additions.append(addition)
            offspring.append(child)
            j += 1
            logger.log(child.__str__() + ": " + p1.__str__() + ", " + p1.__str__(), level=2)

    return offspring


def mutation(population: list):
    logger.log("\nMutation: ", level=2)
    for individual in population:
        if 0 == random.randint(0, 1):
            genes: [Gene] = []
            for i in range(random.randint(1, 10)):
                genes.append(generate_gene(individual, random.choice(list(Genetype))))
            individual.distribute_genes(genes)
            logger.log(individual.__str__(), level=2)


def generate_gene(i: Individual, min_type: Genetype) -> Gene:
    gene: Gene
    if Genetype.FUNCTION == min_type:
        gene = generate_function_gene(i)
    else:
        gene = generate_nested_gene(i)
    logger.log("generated " + str(gene.type) + " gene: " + gene.contents[0])
    return gene


def generate_nested_gene(i: Individual, origin: Function = None) -> Gene:
    gene: Gene
    g: int = random.randint(0, 6)
    if g < 3:
        gene = generate_statement_gene()
    elif 3 < g < 5:
        gene = generate_call_gene(i, origin=origin)
    elif g <= 5:
        gene = generate_flow_gene(i, origin)
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
        var = (random.choice(Function.VAR_TYPES) + " " + random_name(5, 16))
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
        try:
            index = i.additions.index(origin)
            available_functions = copy.deepcopy(i.additions)
            del available_functions[index]
        except ValueError:
            available_functions = i.additions
    else:
        available_functions = i.additions
    if not available_functions:
        return generate_empty_gene()
    func: Function = random.choice(available_functions)
    call: str = ""
    if func.params:
        call += func.name + "("
        for param in func.params:
            if param[0] == 'char':
                call += str(random.randint(0, 255))
            elif param[0] == 'int':
                call += str(random.randint(-32768, 32767))
            else:
                call += str(random.uniform(0, 10))
            call += ", "
        call = call[:-2] + ")"
    else:
        call += func.get_definition().split(" ")[-1]
    call += ";\n"
    return Gene(Genetype.CALL, [call], [])


def generate_flow_gene(i: Individual, origin: Function = None, variables: [str] = None) -> Gene:
    ops: [(str, str, int)] = [("<", "+", 1), (">", "-", -1)]
    contents: [str] = []
    nested: list = []
    flow_type: int = random.randint(0, 2)
    if variables is not None and flow_type == 0:
        # if else ladder
        var: str = random.choice(variables)
        val: int = random.randint(0, 255)
        contents.append("if (" + var + " == " + str(val) + ") \n")
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_nested_gene(i, origin))
        contents.append("}\n")
        for j in range(random.randint(1, 10)):
            contents.append("else if (" + var + " == " + str(val - j) + ") {\n")
            contents.append(Gene.NESTED_PLACEHOLDER)
            nested.append(generate_nested_gene(i, origin))
            contents.append("}\n")
        contents.append("else {\n")
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_nested_gene(i, origin))
        contents.append("}\n")
    elif flow_type == 1:
        # while loop
        var: str = random_name(1, 5) if not variables else random.choice(variables)
        if not variables:
            contents.append("int " + var + " = " + str(random.randint(0, 255)) + ";\n")
        op: (str, str, int) = random.choice(ops)
        contents.append("while (" + var + " " + op[0] + " " + str(random.randint(-255, 256)) + ") {\n")
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_nested_gene(i, origin))
        contents.append(op[1] + op[1] + var + ";\n}\n")
    elif flow_type == 2:
        # for loop
        op: (str, str, int) = random.choice(ops)
        var: str = random_name(5, 15)
        lim: int = random.randint(1, 500) * op[2]
        contents.append(
            ("for (int " + var + " = 0; " + var + " " + op[0] + " " + str(lim) + "; " + var + op[1] + op[1] + ") {\n"))
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_nested_gene(i, origin))
        contents.append("}\n")
    else:
        return generate_empty_gene()
    return Gene(Genetype.FLOW, contents, nested)


@dispatch(Individual)
def generate_function_gene(i: Individual) -> Gene:
    # Function head
    name: str = random_name(10, 25)
    ret: str = random.choice(Function.RETURN_TYPES)
    params: list = []
    for j in range(random.randint(0, 6)):
        n: str = random_name(4, 8)
        t: str = random.choice(Function.VAR_TYPES)
        params.append((t, n))
    func: Function = Function(name, ret, params)
    i.additions.append(func)
    return generate_function_gene(i, func)


@dispatch(Individual, Function)
def generate_function_gene(i: Individual, function: Function) -> Gene:
    # Function content
    contents: [str] = [function.get_definition() + " {\n"]
    nested: list = []
    for j in range(random.randint(0, 20)):
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_nested_gene(i, function))

    # Function return
    if function.ret != "void":
        contents.append("return " + str(random.randint(0, 255)) + ";\n")
    contents.append("}")
    return Gene(Genetype.FUNCTION, contents, nested, func=function)


def random_name(a: int, b: int) -> str:
    return ''.join(random.choice(string.ascii_letters) for i in range(random.randint(a, b)))


def log_generation(generation: int, individuals: list):
    logger.log("\n### Generation " + str(generation) + " ###", level=2)
    for individual in individuals:
        log_individual(individual)


def log_individual(i: Individual):
    output: str = "- Individual: " + i.__str__() + "\n  alive since: " + str(i.alive_since) + "\n  functions: " + str(
        len(i.additions)) + "\n  genes: " + str(len(i.get_genes())) + "\n  fitness: " + str(i.fitness) + "\n"
    logger.log(output, level=2)
