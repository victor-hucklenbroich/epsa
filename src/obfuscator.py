import time

from genetics import *
from src import pss, genetics


def obfuscate(p0: str, features: (list, list)):
    pass


def initial_population(p: str) -> list:
    population: list = genetics.initial_population(p, constants.POPULATION_SIZE)
    for individual in population:
        for source in individual.sources:
            for genome in source.genomes:
                if 0 == random.randint(0, 10):
                    if genome.min_type.value == 0:
                        genome.genes.append(generate_function_gene(individual))
                    elif genome.min_type.value == 1:
                        genome.genes.append(generate_call_gene(individual))
    return population


def evolutionary_cycle(population: list, features: (list, list)):
    population = selection(population, features)
    crossover(population)
    mutation(population)


def fitness(i: Individual, features: (list, list)) -> float:
    i.write_code()
    start_time = time.time()
    try:
        sim: float = pss.compare(i.path, features[0], features[1])
        t = time.time() - start_time
    except Exception:
        return -10000
    fit: float = 1
    if t > 90:
        fit -= t * 0.0005
    return fit - sim


def selection(population: list, features: (list, list)) -> list:
    population.sort(reverse=True, key=lambda individual: fitness(individual, features))
    selected: list = []
    for i in range(int(constants.POPULATION_SIZE * 0.3)):
        selected.append(population[i])

    return selected


def crossover(population: list):
    pass


def mutation(population: list):
    pass
