pragma circom 2.0.0;

template ToyDouble() {
    signal input in;
    signal output out;
    out <== in + in;
}
