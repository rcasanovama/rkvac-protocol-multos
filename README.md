# rkvac-protocol-multos
This is a C implementation (user side) of the RKVAC (_Revocable Keyed-Verification Anonymous Credentials_) protocol
for MULTOS smart cards.

## Table of Contents
- [Getting started](#getting-started)
    - [Environment](#environment)
- [Build instructions](#build-instructions)
- [Install instructions](#install-instructions)
    - [How to know the Session Data Size](#how-to-know-the-session-data-size)
- [Benchmarks](#benchmarks)
    - [MULTOS-ML4](#multos-ml4)
- [Project structure](#project-structure)
    - [Source tree](#source-tree)
    - [Source description](#source-description)
- [License](#license)

## Getting started
These instructions will get you a copy of the project up and running on your local machine for development and
testing purposes.

Please, note that the process of compiling and building the application must be done on a **Windows** system.

### Environment
The following table summarizes the tools and libraries required to build and install the application.

| Dependency            | Description                                          | Purpose          |
| --------------------- | ---------------------------------------------------- | ---------------- |
| SmartDeck3_2Setup.msi | MULTOS SmartDeck 3.2.1                               | Smart card SDK   |
| vcredist_x86.exe      | Microsoft Visual C++ 2010  x86 Redistributable Setup | For MUtil        |
| vcredist_x64.exe      | Microsoft Visual C++ 2010  x64 Redistributable Setup | For MUtil        |
| MUtil.exe             | MUtil Application 2.8.0.5                            | App installation |

#### *Note for SmartDeck installation:*
- Specify the following installation path: `C:\SmartDeck`.
- Add `C:\SmartDeck\bin` to the system PATH.

## Build instructions
To compile the code and build the application (alu) it is necessary to execute the `make` command in the project's
root directory. This process will remove the old files and build the new application.

```sh
make
```

```console
C:\rkvac-protocol-multos>make
rm -f main.hzo rkvac-multos.hzx rkvac-multos.alu
hcl -Iconfig -Iinclude -Ilib -c -g -o main.hzo main.c
hcl -g -o rkvac-multos.hzx main.hzo
halugen rkvac-multos.hzx
```

If you have any problems during compilation, please check the [Environment](#environment) section.

## Install instructions
- Insert a supported MULTOS smart card into the reader.
- Load the application to the smart card using the MUtil application with the following parameters:
    - **Filename**: `rkvac-multos.alu`
    - **AID**: `F0000001`
    - **Session Data Size**: `1175 (Dec)`

### How to know the `Session Data Size`
In order to obtain the dynamic memory required by the application, it is necessary to execute the following command:

```sh
hls -t bin\\rkvac-multos.hzx
```

```console
C:\rkvac-protocol-multos>hls -t bin\\rkvac-multos.hzx
   start     stop    size  decimal  name
00000000 00000496     497     1175  .DB
00000000 000000ff     100      256  .PB
00000000 00000ce2     ce3     3299  .SB
00000000 00000a1e     a1f     2591  .text
```

## Benchmarks

### MULTOS-ML4

#### User attributes: 1

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 1               | 0                    | 2.158093                 | 1.439074                 | 0.719019            |
| 1               | 1                    | 2.012606                 | 1.323744                 | 0.688862            |

#### User attributes: 2

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 2               | 0                    | 2.305593                 | 1.556138                 | 0.749455            |
| 2               | 1                    | 2.157790                 | 1.439089                 | 0.718701            |
| 2               | 2                    | 2.013678                 | 1.325094                 | 0.688584            |

#### User attributes: 3

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 3               | 0                    | 2.504106                 | 1.675589                 | 0.828517            |
| 3               | 1                    | 2.308294                 | 1.558881                 | 0.749413            |
| 3               | 2                    | 2.156373                 | 1.437958                 | 0.718415            |
| 3               | 3                    | 2.011450                 | 1.322596                 | 0.688854            |

#### User attributes: 4

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 4               | 0                    | 2.656481                 | 1.797451                 | 0.859030            |
| 4               | 1                    | 2.507097                 | 1.678370                 | 0.828727            |
| 4               | 2                    | 2.306536                 | 1.557109                 | 0.749427            |
| 4               | 3                    | 2.157215                 | 1.438005                 | 0.719210            |
| 4               | 4                    | 2.012333                 | 1.323262                 | 0.689071            |

#### User attributes: 5

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 5               | 0                    | 2.806147                 | 1.916848                 | 0.889299            |
| 5               | 1                    | 2.655815                 | 1.796728                 | 0.859087            |
| 5               | 2                    | 2.507356                 | 1.678501                 | 0.828855            |
| 5               | 3                    | 2.307643                 | 1.558050                 | 0.749593            |
| 5               | 4                    | 2.156522                 | 1.437275                 | 0.719247            |
| 5               | 5                    | 2.013672                 | 1.324709                 | 0.688963            |

#### User attributes: 6

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 6               | 0                    | 2.953775                 | 2.034468                 | 0.919307            |
| 6               | 1                    | 2.808051                 | 1.918696                 | 0.889355            |
| 6               | 2                    | 2.655524                 | 1.796549                 | 0.858975            |
| 6               | 3                    | 2.506228                 | 1.677373                 | 0.828855            |
| 6               | 4                    | 2.308444                 | 1.558877                 | 0.749567            |
| 6               | 5                    | 2.160366                 | 1.441059                 | 0.719307            |
| 6               | 6                    | 2.013581                 | 1.324405                 | 0.689176            |

#### User attributes: 7

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 7               | 0                    | 3.106109                 | 2.156329                 | 0.949780            |
| 7               | 1                    | 2.958533                 | 2.038911                 | 0.919622            |
| 7               | 2                    | 2.806705                 | 1.917465                 | 0.889240            |
| 7               | 3                    | 2.654768                 | 1.795759                 | 0.859009            |
| 7               | 4                    | 2.506322                 | 1.677558                 | 0.828764            |
| 7               | 5                    | 2.305963                 | 1.556397                 | 0.749566            |
| 7               | 6                    | 2.159427                 | 1.440105                 | 0.719322            |
| 7               | 7                    | 2.011913                 | 1.323057                 | 0.688856            |

#### User attributes: 8

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 8               | 0                    | 3.252989                 | 2.273243                 | 0.979746            |
| 8               | 1                    | 3.103346                 | 2.153692                 | 0.949654            |
| 8               | 2                    | 2.954483                 | 2.034903                 | 0.919580            |
| 8               | 3                    | 2.807865                 | 1.918354                 | 0.889511            |
| 8               | 4                    | 2.656233                 | 1.797254                 | 0.858979            |
| 8               | 5                    | 2.508402                 | 1.679367                 | 0.829035            |
| 8               | 6                    | 2.309418                 | 1.559779                 | 0.749639            |
| 8               | 7                    | 2.157429                 | 1.438132                 | 0.719297            |
| 8               | 8                    | 2.014064                 | 1.324958                 | 0.689106            |

#### User attributes: 9

| User attributes | Disclosed attributes | Total elapsed time (sec) | Proof of knowledge (sec) | Communication (sec) |
| --------------- | -------------------- | ------------------------ | ------------------------ | ------------------- |
| 9               | 0                    | 3.405028                 | 2.394625                 | 1.010403            |
| 9               | 1                    | 3.257013                 | 2.277112                 | 0.979901            |
| 9               | 2                    | 3.105000                 | 2.154716                 | 0.950284            |
| 9               | 3                    | 2.954031                 | 2.034260                 | 0.919771            |
| 9               | 4                    | 2.806902                 | 1.917630                 | 0.889272            |
| 9               | 5                    | 2.657442                 | 1.798309                 | 0.859133            |
| 9               | 6                    | 2.511048                 | 1.682007                 | 0.829041            |
| 9               | 7                    | 2.308818                 | 1.559125                 | 0.749693            |
| 9               | 8                    | 2.160393                 | 1.441151                 | 0.719242            |
| 9               | 9                    | 2.014994                 | 1.325937                 | 0.689057            |

## Project structure

### Source tree

```sh
rkvac-protocol-multos/
├── bin
│   ├── rkvac-multos.alu
│   └── rkvac-multos.hzx
├── config
│   └── config.h
├── include
│   ├── apdu.h
│   ├── models
│   │   ├── issuer.h
│   │   ├── revocation-authority.h
│   │   └── user.h
│   └── types.h
├── lib
│   ├── ecc
│   │   └── multosecc.h
│   └── helpers
│       ├── mem_helper.h
│       └── random_helper.h
├── LICENSE.md
├── main.c
├── Makefile
└── README.md
```

### Source description

| Directory                   | File                           | Description                                                                                                             |
| --------------------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------------------------- |
|  `config/`                  |  `config.h`                    | constants (maximum number of user attributes, k and j values of the revocation authority, length of the user id, etc)   |
|  `include/`                 |  `apdu.h`                      | header with APDU codes used for communication with the smart card                                                       |
|  `include/models/`          |  `*`                           | definition of the data structures (information) used by the issuer, the revocation authority and the user               |
|  `include/`                 |  `types.h`                     | custom defined data types used on the MULTOS platform                                                                   |
|  `lib/ecc/`                 |  `multosecc.h`                 | macros to perform mathematical operations on elliptic curves (MULTOS support)                                           |
|  `lib/helpers/`             |  `mem_helper.h`                | macros with custom implementation of memory operations (memcpy, memcmp, memzero)                                        |
|  `lib/helpers/`             |  `random_helper.h`             | macro for the generation of random numbers                                                                              |
|  `-`                        |  `main.c`                      | main routine                                                                                                            |
|  `-`                        |  `Makefile`                    | used for compiling code and building the application (alu)                                                              |

## License
This project is licensed under the GPLv3 License - see the [LICENSE.md](LICENSE.md) file for details.
