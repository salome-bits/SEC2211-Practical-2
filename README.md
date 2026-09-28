Student: Lukonde Salome Musenge  
Course: Operating System Concepts & System Programming (SEC 2211)  
Institution: Zambia University of Technology
This repository contains low-level C system programming implementation, file descriptor manipulations, and POSIX system call security experiments for Week 1 (Questions 1 & 2)
```text
SEC2211-Practical-2/
├── README.md               <- Project documentation & setup instructions
├── docs/                   <- Technical report and submission presentation
├── evidence/               <- Raw system call execution traces (strace logs)
└── week1/
    ├── q1/                 <- File Descriptor Inspection Tool
    │   ├── secinspect.c    <- Source code inspecting FDs (STDIN, STDOUT, STDERR, open file)
    │   └── sample.txt      <- Test data file
    └── q2/                 <- File Permissions & Access Control Lab
        ├── no_access.txt   <- Permission-restricted test file (chmod 000)
        ├── read_test.txt   <- Readable test file
        └── secinspect      <- Compiled inspection binary
