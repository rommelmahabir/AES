# -*- coding: utf-8 -*-
'''
Name: Rommel Mahabir (rsm0169)
Course: CSCE3550.001
Project 3 - Encryption using AES
Date: 5/3/2022

DESCRIPTION:
            This program implements an encryption system using a simplified
            version of AES. It reads in plaintext from one file and a key from
            another file, then encrypts the plain text and prints the output
            of each step to the screen and to an output file.
'''

import sys
import copy as c

def preprocessing(INPUT):
    print("Preprocessing:")
    alpha = "ABCDEFGHIJKLMONPQRSTUVWXYZ"
    copy = ''.join(INPUT)
    PREPROC = [] # output var
    # Cleans input
    for char in copy:
        if char not in alpha:
            copy = copy.replace(char, '')
    PREPROC.append(''.join(copy))
    return PREPROC

def substitution(PREPROC, KEY):
    print("Subtitution:")
    SUBST = [] # output var
    # does shuffle
    for line in PREPROC:
        copy = []
        for i, char in enumerate(line):
            copy.append( chr((((ord(char) + ord(KEY[i%len(KEY)])) - (65*2)) % 26) + 65) )
        SUBST.append(''.join(copy))
    return SUBST

def padding(SUBST):
    print("Padding:")
    copy = ''.join(SUBST)
    PAD = [] # output var
    while(len(copy) % 16 != 0):
        copy = copy + "A"
    for i in range(0,len(copy),16):
        fbf = []
        temp = copy[i:i+16]
        for j in range(0,16,4):
            fbf.append(temp[j:j+4])
        PAD.append(fbf)
    return PAD

def shiftRows(PAD):
    print("Shift Rows:")
    S_ROW = [] # output var
    for block in PAD:
        newBlock = []
        for i, line in enumerate(block):
            newStr = line[0+i:4] + line[0:i]
            newBlock.append(newStr)
        S_ROW.append(newBlock)
    return S_ROW

# Checks for even 1s
def evenParity(num):
    binNum = bin(num)
    evenParity = True
    for bit in binNum[2:]:
        if int(bit) == 1:
            evenParity = not evenParity
    return evenParity

def parityBit(S_ROW):
    print("Parity Bit:")
    P_BIT = [] # output var
    for block in S_ROW:
        newBlock = [] # to be added to output
        for line in block:
            newLine = []
            for char in line:
                if evenParity(ord(char)): # even 1
                    hexVal = hex(ord(char))[2:]
                else: # odd 1
                    hexVal = hex(ord(char)|128)[2:]
                newLine.append(hexVal)
            newBlock.append(newLine)
        P_BIT.append(newBlock)
    return P_BIT

def rgfMul(x,y):
    if y == 3:
        retVal = x << 1
        if retVal > 256: # incase overflow
            retVal = int(bin(retVal)[-8:],2)
        retVal = retVal ^ x
        if bin(retVal)[2] == "1":
            retVal = retVal ^ 27
        return retVal
    elif y == 2:
        retVal = x << 1
        if retVal > 256: # incase overflow
            retVal = int(bin(retVal)[-8:],2)
        if bin(retVal)[2] == "1":
            retVal = retVal ^ 27
        return retVal
    else:
        return x

def mixColumns(P_BIT):
    print("Mix Columns:")
    # RGF matrix
    matrix = [
            [2,3,1,1],
            [1,2,3,1],
            [1,1,2,3],
            [3,1,1,2]
        ]
    OUTPUT = []

    for block in P_BIT:
        copy = c.deepcopy(block) # copy to hold new nums
        for i in range(0,4):
            for j in range(0,4):
                val1 = rgfMul(int(block[0][i],16), matrix[j][0])
                val2 = rgfMul(int(block[1][i],16), matrix[j][1])
                val3 = rgfMul(int(block[2][i],16), matrix[j][2])
                val4 = rgfMul(int(block[3][i],16), matrix[j][3])
                final = hex((val1 ^ val2 ^ val3 ^ val4))[2:]
                copy[j][i] = final
        OUTPUT.append(copy)
    return OUTPUT

def encrypt(INPUT, KEY, outputFile):
    with open(outputFile, 'w') as f:
        # Preprocessing
        f.write("Preprocessing:\n")
        PREPROC = preprocessing(INPUT)
        print('\n'.join(PREPROC))
        print()
        f.write('\n'.join(PREPROC))
        f.write("\n")
        f.write("\n")

        # Substitution
        f.write("Substitution:\n")
        SUBST = substitution(PREPROC, KEY)
        print('\n'.join(SUBST))
        print()
        f.write('\n'.join(SUBST))
        f.write("\n")
        f.write("\n")

        # Padding
        f.write("Padding:\n")
        PAD = padding(SUBST)
        for block in PAD:
            for line in block:
                print(line)
                f.write(line)
                f.write("\n")
            print()
            f.write("\n")

        # Shift Rows
        f.write("Shift Rows:\n")
        S_ROW = shiftRows(PAD)
        for block in S_ROW:
            for line in block:
                print(line)
                f.write(line)
                f.write("\n")
            print()
            f.write("\n")

        # Parity Bit
        f.write("Parity Bit:\n")
        P_BIT = parityBit(S_ROW)
        for block in P_BIT:
            for line in block:
                print(' '.join(line))
                f.write(' '.join(line))
                f.write("\n")
        print()
        f.write("\n")
        f.write("\n")

        # Mix Columns
        f.write("Mix Columns:\n")
        OUTPUT = mixColumns(P_BIT)
        for block in OUTPUT:
            for line in block:
                print(' '.join(line))
                f.write(' '.join(line))
                f.write("\n")
        print()
        f.write("\n")
        f.write("\n")

    return

def main():
    #inputFileName = "input.txt"
    #keyFileName = "key.txt"
    #outputFileName = "output.txt"

    inputFileName = input("Enter the name of the input plaintext file:")
    keyFileName = input("Enter the name of the input key file:")
    outputFileName = input("Enter the name of the output ciphertext file:")

    try: # incase file not exist
        with open(inputFileName, "r") as file:
            INPUT = file.read().splitlines()
    except FileNotFoundError:
        print("Input file {inputFileName} does not exist... Exiting Program")
        sys.exit()

    try: # incase file not exist
        with open(keyFileName, "r") as file:
            KEY = file.read().splitlines()
    except FileNotFoundError:
        print("Encryption key file {keyFileName} does not exist... Exiting Program")
        sys.exit()

    KEY = ''.join(KEY)
    encrypt(INPUT, KEY, outputFileName)

    return 0

if __name__ == "__main__":
    main()
