pragma circom 2.0.0;

// IsZero circuit - properly constrained, no bugs
template IsZero() {
    signal input in;
    signal output {binary} out;

    signal inv;

    inv <-- in!=0 ? 1/in : 0;

    out <== -in*inv +1;
    in*out === 0;
}

component main = IsZero();
