import copy
import pickle
import string
import time

import angr
import networkx as nx
from multipledispatch import dispatch

from src.constants import *
from src.preprocessor import search_dir, clean, compile_program, calculate_loc, calculate_total_loc
from src import pss, logger

MAX_MUTATIONS: int = int(calculate_total_loc() * 0.001)

class Genetype(Enum):
    EMPTY = -1
    CALL = 0
    STATEMENT = 1
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
        self.nested = nested
        self.function = func

    def append_nested(self, gene):
        self.contents.insert(int(len(self.contents) / 2), Gene.NESTED_PLACEHOLDER)
        self.nested.append(gene)

    def get_content(self) -> str:
        if not self.nested:
            return ''.join(self.contents)
        else:
            content: str = ''
            i: int = 0
            n: int = 0
            while i < len(self.contents):
                if self.contents[i] == Gene.NESTED_PLACEHOLDER:
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

    def add_gene(self, gene: Gene):
        self.genes.append(gene)

    def dump_genes(self):
        self.genes = []


class Source:
    def __init__(self, path: str, code: [str], genomes: [Genome]):
        self.path = path
        self.code = code
        self.genomes = genomes

    def write_code(self):
        output: str = ""
        if self.genomes:
            output += "#include \"" + NOISE_HEADER + ".h\"\n"
            output += self.genomes[0].get_code()
        output += self.code[0]
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
                 fit: float = MIN_FITNESS):
        self.name: str = NAME_UTIL.get_next_name()
        self.path = path
        self.sources = sources
        self.additions = additions
        self.alive_since = alive
        self.last_altered = alive
        self.fitness = fit
        # Result structure data
        self.loc = 0
        self.pss = MIN_FITNESS
        self.compile_time = MIN_FITNESS
        self.cg: nx.MultiGraph
        self.cfgs: [nx.DiGraph]

    def __str__(self) -> str:
        return self.name

    def write_code(self):
        self.generate_noise_header()
        for source in self.sources:
            source.write_code()

    def generate_noise_header(self):
        path: str = os.path.join(TEST_SOURCES_PATH, NOISE_HEADER + ".h")
        content: str = ("#ifndef " + NOISE_HEADER + "\n" +
                        "#define " + NOISE_HEADER + "\n")
        for function in self.additions:
            content += function.get_definition() + ";\n"

        content += "#endif\n"
        with open(path, "w+") as h:
            h.writelines(content)

    def get_genes(self) -> [Gene]:
        genes: [Gene] = []
        for source in self.sources:
            for genome in source.genomes:
                for gene in genome.genes:
                    genes.append(gene)
        return genes

    def get_number_of_genes(self, t: Genetype) -> int:
        n: int = 0
        for gene in self.get_genes():
            if gene.type == t:
                n += 1
        return n

    def set_fitness(self, f):
        if f > self.fitness or f == MIN_FITNESS:
            self.fitness = f

    def add_gene(self, gene: Gene):
        source: Source = random.choice(self.sources)
        if gene.type == Genetype.FUNCTION:
            self.additions.append(gene.function)
            source.genomes[0].genes.append(gene)
        else:
            genome: Genome = random.choice(source.genomes)
            counter: int = 0
            while genome.min_type.value > gene.type.value:
                if counter > 10:
                    # stop infinite loop if source contains only high min type genomes
                    source = random.choice(self.sources)
                    counter = 0
                genome = random.choice(source.genomes)
                counter += 1
            genome.genes.append(gene)

    def distribute_genes(self, genes: [Gene]):
        for gene in genes:
            self.add_gene(gene)


def encode_source(path: str) -> Source:
    with open(path, "r") as s:
        code = s.readlines()
    genomes: list = []
    if path not in EXCLUSIONS:
        genomes.append(Genome(0, Genetype.FUNCTION, []))
        i: int = 0
        while i < len(code):
            line: str = code[i]
            if " " in line and (
                    ") {" in line or "){" in line) and "#" not in line and ";" and "\\" not in line and "}" not in line and "switch" not in line:
                genomes.append(Genome(i + 1, Genetype.EMPTY, []))
            i += 1

    return Source(path, code, genomes)


def encode_individual(p: str, generation: int) -> Individual:
    sources: list = []
    files: [str] = search_dir(TEST_SOURCES_PATH)
    for source in files:
        sources.append(encode_source(source))
    return Individual(p, sources, [], generation)


def run(target_features: (list, list)) -> (list, list):
    population: list = initial_population(TEST_PROGRAM_PATH, POPULATION_SIZE)
    i: int = 0
    # evolutionary cycle
    while datetime.now() <= TIMEOUT:
        previous: list = copy.deepcopy(population)
        population = evolutionary_cycle(i, population, previous, target_features)
        i += 1

    # last Generation
    fitness_sort(population, target_features)
    log_generation(i, population)
    clean(Path(TEST_PROGRAM_PATH), replace_with_archives=True)
    best: Individual = population[0]
    best.write_code()
    compile_program(TEST_PROGRAM_PATH)
    logger.log("best individual:  ", level=2)
    log_individual(best)
    return pss.compute_features(BINARY_PATH)


def initial_population(p: str, size: int) -> list:
    clean(p, replace_with_archives=True)
    population: list = [copy.deepcopy(encode_individual(TEST_PROGRAM_PATH, 0))]
    i: int = 0
    while i < size - 1:
        c: Individual = copy.deepcopy(population[0])
        c.name = NAME_UTIL.get_next_name()
        population.append(c)
        i += 1

    for individual in population:
        create_individual(base=individual)
    return population


def get_base_individual(generation: int = 0) -> Individual:
    clean(Path(TEST_PROGRAM_PATH), replace_with_archives=True)
    return encode_individual(TEST_PROGRAM_PATH, generation)


def create_individual(generation: int = 0, base: Individual = None) -> Individual:
    if base is None:
        base = get_base_individual(generation + 1)
    for source in base.sources:
        for genome in source.genomes:
            i: int = 0
            while i < random.randint(1, 10):
                genome.genes.append(generate_gene(base, genome.min_type))
                i += 1
    return base


def evolutionary_cycle(generation: int, population: list, previous: list, features: (list, list)) -> list:
    fitness_sort(population, features)
    # return to last evolutionary step if best individual is unfit
    if population[0].fitness == MIN_FITNESS:
        logger.log("unfit generation, rollback to #" + str(generation - 1))
        population = previous
    log_generation(generation, population)
    pop = selection(population, generation)
    pop += crossover(pop, generation)
    mutation(pop, generation)
    return pop


def fitness(i: Individual, features: (list, list)) -> float:
    clean(Path(TEST_PROGRAM_PATH), replace_with_archives=True)
    i.write_code()
    start_time: float = time.time()
    t: float
    fit: float
    try:
        compile_program(TEST_PROGRAM_PATH)
        compile_time: float = round(time.time() - start_time, 2)
        p: angr.Project = pss.init_angr(BINARY_PATH)
        cg: nx.MultiGraph = pss.construct_cg(p)
        cfgs: [nx.DiGraph] = pss.construct_cfgs(p)
        sim: float = pss.compare(cg, cfgs, features[0], features[1])
        logger.log(str(i) + ":pss = " + str(sim), level=1)
        t = time.time() - start_time
        time_delta: float = (t - 60 - COMPILE_TIME) * 0.0001
        if MODE == ModMode.OBFUSCATE:
            fit = 1 - sim
            if time_delta > 0:
                fit -= time_delta ** 2
        else:
            fit = 0 + sim

    except Exception as e:
        # Handle compile time exceptions
        logger.log(e.__str__())
        t = time.time() - start_time
        fit = MIN_FITNESS
        cg = None
        cfgs = []
        compile_time = 0
        sim = 0
    logger.log(str(i) + ": compilation, angr analysis, pss took " + str(round(t, 2)) + " seconds", level=1)
    i.set_fitness(fit)
    # Set results structure data
    i.compile_time = compile_time
    i.pss = sim
    i.loc = calculate_loc(TEST_PROGRAM_PATH)
    if ENABLE_GRAPH_LOGGING:
        i.cg = cg
        i.cfgs = cfgs

    return fit


def fitness_sort(population: list, features: (list, list)):
    for individual in population:
        fitness(individual, features)
    population.sort(reverse=True, key=lambda i: i.fitness)


def selection(population: list, generation: int) -> list:
    logger.log("Selection: ", level=2)
    selected: list = []
    for i in range(int(POPULATION_SIZE * SELECTION_RATIO)):
        if population[i].fitness == MIN_FITNESS:
            selected.append(create_individual(generation=generation))
        else:
            selected.append(population[i])
        logger.log(population[i].__str__(), level=2)

    return selected


def crossover(population: list, generation: int) -> list:
    logger.log("\nCrossover: ", level=2)
    clean(Path(TEST_PROGRAM_PATH), replace_with_archives=True)
    base: Individual = get_base_individual(generation + 1)
    parents = get_parents(population)
    offspring: list = []
    # iterate parent pairs
    for i in range(len(parents) - 1):
        j: int = i + 1
        while j < len(parents):
            p1: Individual = parents[i]
            p2: Individual = parents[j]
            child: Individual = copy.deepcopy(base)
            child.name = NAME_UTIL.get_next_name()

            # iterate sources and genomes
            s: int = 0
            while s < len(child.sources):
                p1_source: Source = p1.sources[s]
                p2_source: Source = p2.sources[s]
                c_source: Source = child.sources[s]
                g: int = 0
                while g < len(c_source.genomes):
                    p1_genome: Genome = p1_source.genomes[g]
                    p2_genome: Genome = p2_source.genomes[g]
                    c_genome: Genome = c_source.genomes[g]
                    larger_gene_pool: Genome = p1_genome if len(p1_genome.genes) > len(p2_genome.genes) else p2_genome

                    # uniform gene crossover
                    x: int = 0
                    while x < len(larger_gene_pool.genes):
                        try:
                            if bool(random.getrandbits(1)):
                                c_genome.add_gene(p1_genome.genes[x])
                            else:
                                c_genome.add_gene(p1_genome.genes[x])
                        except IndexError:
                            if bool(random.getrandbits(1)):
                                c_genome.add_gene(larger_gene_pool.genes[x])
                            pass
                        x += 1
                    g += 1
                s += 1

            # generate functions iff any are missing
            for addition in p1.additions + p2.additions:
                if addition not in child.additions:
                    child.add_gene(generate_function_gene(child, addition))
                    child.additions.append(addition)
            offspring.append(child)
            j += 1
            logger.log(child.__str__() + ": " + p1.__str__() + ", " + p2.__str__(), level=2)

    return offspring


def get_parents(population: list):
    # elite and non-elite parents to avoid loss of diversity
    elites: list = population[:ELITE_SIZE]
    non_elites: list = population[ELITE_SIZE:]
    rand: list = [random.choice(non_elites)]
    non_elites.remove(rand[0])
    rand.append(random.choice(non_elites))
    parents: list = elites + rand
    return parents


def mutation(population: list, generation: int):
    logger.log("\nMutation: ", level=2)
    # mutation creates random new genes
    for individual in population:
        if 0 == random.randint(0, 3):
            genes: [Gene] = []
            max: int = MAX_MUTATIONS if MAX_MUTATIONS >= 10 else 10
            min: int = int(max / 10)
            for i in range(random.randint(min, max)):
                genes.append(generate_gene(individual, random.choice(list(Genetype))))

            # mutated genes either append into random genomes or nest into random genes
            for nested in genes:
                if bool(random.getrandbits(1)):
                    gene: Gene = random.choice(individual.get_genes())
                    if gene.type.value >= 2 >= nested.type.value or gene.type.value == 1 < nested.type.value:
                        gene.append_nested(nested)
                        genes.remove(nested)
            individual.distribute_genes(genes)
            individual.last_altered = generation
            logger.log(individual.__str__(), level=2)

    # fill population to intended size, if crossover did not
    if len(population) < POPULATION_SIZE:
        base: Individual = get_base_individual(generation)
        i: int = len(population)
        while i < POPULATION_SIZE:
            population.append(create_individual(generation, base))
            i += 1


def generate_gene(i: Individual, min_type: Genetype) -> Gene:
    gene: Gene
    if Genetype.FUNCTION == min_type:
        gene = generate_function_gene(i)
    else:
        gene = generate_non_function_gene(i)
    logger.log("generated " + str(gene.type) + " gene: " + gene.contents[0])
    return gene


def generate_non_function_gene(i: Individual, origin: Function = None) -> Gene:
    gene: Gene
    g: int = random.randint(0, 6)
    if g < 3:
        gene = generate_statement_gene(i, origin)
    elif 3 < g < 5:
        gene = generate_call_gene(i, origin=origin)
    elif g <= 5:
        gene = generate_flow_gene(i, origin)
    else:
        gene = generate_empty_gene()
    return gene


def generate_empty_gene() -> Gene:
    return Gene(Genetype.EMPTY, [""], [])


def generate_call_gene(i: Individual, origin: Function = None, only_non_void: bool = False,
                       parameters: [str] = None) -> Gene:
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
    if only_non_void:
        available_functions = list(filter(lambda f: f.ret != 'void', available_functions))
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


def generate_statement_gene(i: Individual, origin: Function = None, variables: [str] = None) -> Gene:
    assign_existing: bool = False
    if variables is not None:
        assign_existing: bool = bool(random.getrandbits(1))
    var: str
    if assign_existing:
        var = random.choice(variables)
    else:
        var = (random.choice(Function.VAR_TYPES) + " " + random_name(3, 50))
    contents: [str] = [var, " = "]
    nested: list = []
    simple: bool = bool(random.getrandbits(1))
    if simple:
        contents.append(str(random.randint(0, 255)))
    else:
        for j in range(random.randint(2, 4)):
            if variables is not None and bool(random.getrandbits(1)):
                contents.append(random.choice(variables))
            elif i.additions and bool(random.getrandbits(1)):
                call: Gene = generate_call_gene(i, origin, only_non_void=True)
                if call.type == Genetype.EMPTY:
                    contents.append(str(random.randint(0, 32767)))
                else:
                    call.contents[0] = call.contents[0][:-2]
                    contents.append(Gene.NESTED_PLACEHOLDER)
                    nested.append(call)
            else:
                contents.append(str(random.randint(0, 32767)))
            contents.append((" " + random.choice(['+', '-', '*', '/']) + " "))
        del contents[-1]
    contents.append(";\n")
    return Gene(Genetype.STATEMENT, contents, nested)


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
        nested.append(generate_non_function_gene(i, origin))
        contents.append("}\n")
        for j in range(random.randint(1, 10)):
            contents.append("else if (" + var + " == " + str(val - j) + ") {\n")
            contents.append(Gene.NESTED_PLACEHOLDER)
            nested.append(generate_non_function_gene(i, origin))
            contents.append("}\n")
        contents.append("else {\n")
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_non_function_gene(i, origin))
        contents.append("}\n")
    elif flow_type == 1:
        # while loop
        var: str = random_name(3, 50) if not variables else random.choice(variables)
        if not variables:
            contents.append("int " + var + " = " + str(random.randint(0, 255)) + ";\n")
        op: (str, str, int) = random.choice(ops)
        contents.append("while (" + var + " " + op[0] + " " + str(random.randint(-255, 256)) + ") {\n")
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_non_function_gene(i, origin))
        contents.append(op[1] + op[1] + var + ";\n}\n")
    elif flow_type == 2:
        # for loop
        op: (str, str, int) = random.choice(ops)
        var: str = random_name(3, 50)
        lim: int = random.randint(1, 500) * op[2]
        contents.append(
            ("for (int " + var + " = 0; " + var + " " + op[0] + " " + str(lim) + "; " + var + op[1] + op[1] + ") {\n"))
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_non_function_gene(i, origin))
        contents.append("}\n")
    else:
        return generate_empty_gene()
    return Gene(Genetype.FLOW, contents, nested)


@dispatch(Individual)
def generate_function_gene(i: Individual) -> Gene:
    # Function head
    name: str = random_name(3, 50)
    ret: str = random.choice(Function.RETURN_TYPES)
    params: list = []
    for j in range(random.randint(0, 6)):
        n: str = random_name(3, 50)
        t: str = random.choice(Function.VAR_TYPES)
        params.append((t, n))
    func: Function = Function(name, ret, params)
    return generate_function_gene(i, func)


@dispatch(Individual, Function)
def generate_function_gene(i: Individual, function: Function) -> Gene:
    # Function content
    contents: [str] = [function.get_definition() + " {\n"]
    nested: list = []
    for j in range(random.randint(0, 20)):
        contents.append(Gene.NESTED_PLACEHOLDER)
        nested.append(generate_non_function_gene(i, function))

    # Function return
    if function.ret != "void":
        contents.append("return " + str(random.randint(0, 255)) + ";\n")
    contents.append("}")

    gene: Gene = Gene(Genetype.FUNCTION, contents, nested, func=function)
    i.additions.append(function)
    return gene


def random_name(a: int, b: int) -> str:
    return random.choice(string.ascii_letters) + ''.join(
        random.choice(string.ascii_letters + string.digits) for i in range(random.randint(a, b)))


def log_generation(generation: int, individuals: list):
    logger.log("\n### Generation " + str(generation) + " ###", level=2)
    entries: [dict] = []
    for individual in individuals:
        entry: dict = {'name': individual.name, 'loc': individual.loc,
                       'statements': individual.get_number_of_genes(Genetype.STATEMENT),
                       'calls': individual.get_number_of_genes(Genetype.CALL),
                       'flows': individual.get_number_of_genes(Genetype.FLOW),
                       'functions': individual.get_number_of_genes(Genetype.FUNCTION), 'ctime': individual.compile_time,
                       'pss': individual.pss, 'fitness': individual.fitness, 'born': individual.alive_since,
                       'altered': individual.last_altered}
        if ENABLE_GRAPH_LOGGING:
            entry['cg'] = individual.cg
            entry['cfgs'] = individual.cfgs
        entries.append(entry)
        log_individual(individual)
    with open(os.path.join(RESULT_PATH, ("gen" + str(generation))), "wb") as f:
        pickle.dump(entries, f)
        logger.log("saved genetic execution data of generation " + str(generation) + " to file: " + f.name, level=2)


def log_individual(i: Individual):
    output: str = "- Individual: " + i.__str__() + "\n  alive since: " + str(i.alive_since) + "\n  functions: " + str(
        len(i.additions)) + "\n  genes: " + str(len(i.get_genes())) + "\n  fitness: " + str(i.fitness) + "\n"
    logger.log(output, level=2)
