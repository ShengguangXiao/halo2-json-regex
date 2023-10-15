# Halo2 Simple Json Regex Verify

This repo includes a halo2 Zero Knowledge Proof circuit example to verify simple json format regex.

## Introduction
MyRegexCircuit: The refex circuit implements the Halo2 circuits.
RegexCheckConfig: The circuit configuration to save the advice columns and selectors.

To build the circuit, we first divide the json regex to difference sections, each section has some accepted value, for example `[a-z]+` accepts all the values between `a` to `z`. Then we can build a constraint `v * (a - v) * (b - v) * (c - v)...*(z-v) = 0` to proof a value satisfy `[a-z]+`.

The circuit likes this, each regex section corresponding to a value column(advice witness) and a selector column. We only enable one selector at the same time.

```
    value1  |  selector1  |  value2  |  selector2  |  value3  |  selector3
    ----------------------------------------------------------------------
      v     |      1      |          |             |          |
            |             |     v    |      1      |          |
            |             |     v    |      1      |          |
            |             |          |             |     v    |      1
            |             |          |             |     v    |      1
```

## Instruction

Clone the repository

```
git clone https://github.com/ShengguangXiao/halo2-json-regex.git
cd halo2-json-regex
```

Build the project.

```
cargo build --release
```

Run the tests

```
cargo test --release
```

## References
1. Little Things I’ve Learned in Developing Halo2 Circuits by Chih-Cheng Liang: https://www.youtube.com/watch?v=wSfkpJDq8AI&list=LL&index=3&ab_channel=EthereumFoundation
2. Building and Testing Circuits with halo2-ce: An Introductory Workshop: https://www.youtube.com/watch?v=60lkR8DZKUA&t=2640s&ab_channel=Scroll
3. https://github.com/icemelon/halo2-examples
