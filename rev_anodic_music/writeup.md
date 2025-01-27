# Anodic Music

CTF: srdnlen CTF 2024 Quals\
Category: rev\
Difficulty: Medium\
Author: Matteo Cornacchia <@zoop>\

# Description

> ENCYCLOPEDIA [Medium: Success] Your mangled brain would like you to know there is a challenge called Anodic Music.

The challenge consists of an ELF binary named `egghead` and a second file called `hardcore.bnk`.

# Solution

The binary imports the bank file, which is a large list of MD5 hashes acting as a blacklist. 
Then, it collects user input one character at a time, exiting if the substring is found in the blacklist. 

For each character position, there are multiple characters which will pass the individual check, 
and some of these incorrect branches will have depth larger than one: that is to say, a "false positive" incorrect character might also have multiple successors.
However, all continuations will eventually reach a dead node in which all substrings are in the blacklist.

A simple solution is to run a DFS on the blacklist bank, discarding any branch for which we find all leaf nodes in the blacklist. 
The exact implementation is not that important. You might want to run the binary with a subprocess, or parse the bank file yourself in a language of your choice. I will explain later why the latter is the most efficient choice, but I would expect the time to program and execute both solutions to be quite close regardless of your hardware configuration.

There are a few optimizations and assumptions which can cut down your processing time. I will not stop to describe common sense optimizations such as expected character frequency, but feel free to implement any such trivial improvements.

First of all, if you have reversed the binary file you might have noticed that the original program performs a linear search for hash lookup. This is not a great idea. If you manage the data in a hash table yourself, you'll jump to O(1) for all your lookups. This is a massive performance improvement and requires parsing the list only once.

You might also notice that correct characters always have 2 branches of depth 1, 2 branches of depth 2 and 2 branches of depth 3. Conversely, bad branches of depth > 1 have a fixed branching factor of 2 for each layer. Technically, selecting the same character for multiple depth branches will increase this number, and decrease the correct character's. But it is still roughly the same, and the branching factor is always inferior.  Using the parent node's branching factor as a heuristic instead of lexical order will significantly improve your performance. Even better, you can discard the entire branch if it is below a certain cutoff point, without having to expand all options breadth-first at depth 2 instead.

You can also try cracking N characters at a time but be wary of collisions. Looking for the most common N-1 substring after running something like hashcat should give you significantly faster progress depending on the hardware at your disposal.

You can retrieve a solve script based on a simple subprocess approach with no optimizations at `src/solve_subprocess.py`. Compare its performance with a Python script loading the bank into a set at `src/solve_hashset.py`.