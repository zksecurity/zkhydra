pragma circom 2.0.0;

// Simple test circuit with an intentional underconstrained signal
template Multiplier() {
    signal input a;
    signal input b;
    signal output c;

    // Intentionally underconstrained - c is assigned but not constrained
    c <-- a * b;
}

component main = Multiplier();
