# Journey towards crypto-agile Go
This document describes the story and ratinale behind making a crypto-agile fork of Go Programming Language.

## Hard-coded switch statements
Since 2022, our organization has been (among other research activities) focusing on Post-Quantum Cryptography (PQC) implementation aspects in real-world applications. More specifically, we have been looking at Estonian e-government services provided to its citizens, which are usually open-sourced.

Throughout this time, we have noticed a very annoying issue: the standard cryptography algorithms (typically RSA, ECDSA, Ed25519, sometimes DSA) were hard-coded way too much in the applications and libraries. Back then, we mostly used [liboqs]()