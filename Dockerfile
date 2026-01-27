# ============================================================================
# Stage 1: Build Z3 4.13.0 from source
# ============================================================================
FROM ubuntu:24.04 AS z3_builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# Build Z3 4.13.0
RUN git clone --depth 1 --branch z3-4.13.0 https://github.com/Z3Prover/z3.git && \
    cd z3 && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc) && \
    ls -la z3

# ============================================================================
# Stage 2: Build CVC5 from source with CoCoA support
# ============================================================================
FROM ubuntu:24.04 AS cvc5_builder

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git \
    cmake \
    build-essential \
    python3 \
    python3-venv \
    python3-pip \
    libgmp-dev \
    flex \
    bison \
    && rm -rf /var/lib/apt/lists/*

# Build CVC5 (latest stable) with CoCoA support for finite field problems
# Note: CoCoA is GPL-licensed, so we need --gpl flag
RUN git clone --depth 1 https://github.com/cvc5/cvc5.git && \
    cd cvc5 && \
    ./configure.sh --auto-download --cocoa --gpl --prefix=/usr/local && \
    cd build && \
    make -j$(nproc) && \
    ls -la bin/cvc5

# ============================================================================
# Stage 3: Build circom from source
# ============================================================================
FROM ubuntu:24.04 AS circom_builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Clone and build circom
RUN git clone https://github.com/iden3/circom.git && \
    cd circom && \
    . "$CARGO_HOME/env" && \
    cargo build --release && \
    cargo install --path circom && \
    ls -la target/release/circom

# ============================================================================
# Stage 4: Build circom_civer from source
# ============================================================================
FROM ubuntu:24.04 AS circom_civer_builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build

# Install build dependencies for circom_civer (including libclang for bindgen)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    libz3-dev \
    z3 \
    libclang-dev \
    clang \
    llvm-dev \
    cmake \
    python3 \
    python3-setuptools \
    python-is-python3 \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Clone and build circom_civer
RUN git clone https://github.com/costa-group/circom_civer.git && \
    cd circom_civer && \
    . "$CARGO_HOME/env" && \
    cargo build --release --bin civer_circom && \
    ls -la target/release/civer_circom

# ============================================================================
# Stage 5: Build circomspect from source
# ============================================================================
FROM ubuntu:24.04 AS circomspect_builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Clone and build circomspect
RUN git clone https://github.com/trailofbits/circomspect.git && \
    cd circomspect && \
    . "$CARGO_HOME/env" && \
    cargo install --path ./cli && \
    ls -la /root/.cargo/bin/circomspect

# ============================================================================
# Stage 6: Build zkFuzz from source
# ============================================================================
FROM ubuntu:24.04 AS zkfuzz_builder

ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:$PATH

WORKDIR /build

RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Clone and build zkFuzz
RUN git clone https://github.com/Koukyosyumei/zkFuzz.git && \
    cd zkFuzz && \
    . "$CARGO_HOME/env" && \
    cargo build --release && \
    ls -la target/release/zkfuzz

# ============================================================================
# Stage 7: Main zkhydra image
# ============================================================================
FROM ubuntu:24.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive
ENV CARGO_HOME=/root/.cargo
ENV PATH=/root/.cargo/bin:/root/.juliaup/bin:/usr/local/bin:$PATH

# Set working directory
WORKDIR /zkhydra

# Install system dependencies (minimal runtime deps)
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    build-essential \
    pkg-config \
    libssl-dev \
    libgmp-dev \
    cmake \
    python3-setuptools \
    python3-dev \
    nodejs \
    npm \
    racket \
    just \
    sudo \
    vim \
    less \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ============================================================================
# Copy all compiled binaries from builder stages to /usr/local/bin
# ============================================================================

# Copy Z3 4.13.0 from builder stage
COPY --from=z3_builder /build/z3/build/z3 /usr/local/bin/z3
RUN chmod +x /usr/local/bin/z3 && z3 --version

# Copy CVC5 from builder stage (binary and all required libraries)
COPY --from=cvc5_builder /build/cvc5/build/bin/cvc5 /usr/local/bin/cvc5
COPY --from=cvc5_builder /build/cvc5/build/src/libcvc5.so.1 /usr/local/lib/libcvc5.so.1
COPY --from=cvc5_builder /build/cvc5/build/src/parser/libcvc5parser.so.1 /usr/local/lib/libcvc5parser.so.1
COPY --from=cvc5_builder /build/cvc5/build/deps/lib/libpoly.so.0 /usr/local/lib/libpoly.so.0
COPY --from=cvc5_builder /build/cvc5/build/deps/lib/libpolyxx.so.0 /usr/local/lib/libpolyxx.so.0
RUN chmod +x /usr/local/bin/cvc5 && ldconfig && cvc5 --version

# Copy circom from builder stage
COPY --from=circom_builder /root/.cargo/bin/circom /usr/local/bin/circom
RUN chmod +x /usr/local/bin/circom && circom --version && \
    echo "circom binary installed to /usr/local/bin"

# Copy circom_civer from builder stage
COPY --from=circom_civer_builder /build/circom_civer/target/release/civer_circom /usr/local/bin/civer_circom
RUN chmod +x /usr/local/bin/civer_circom && \
    echo "civer_circom binary installed to /usr/local/bin"

# Copy circomspect from builder stage
COPY --from=circomspect_builder /root/.cargo/bin/circomspect /usr/local/bin/circomspect
RUN chmod +x /usr/local/bin/circomspect && \
    echo "circomspect binary installed to /usr/local/bin"

# Copy zkFuzz from builder stage
COPY --from=zkfuzz_builder /build/zkFuzz/target/release/zkfuzz /usr/local/bin/zkfuzz
RUN chmod +x /usr/local/bin/zkfuzz && \
    echo "zkfuzz binary installed to /usr/local/bin"

# ============================================================================
# Install additional runtime dependencies
# ============================================================================

# Install Rust toolchain (needed for some runtime dependencies)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && \
    . "$CARGO_HOME/env" && \
    rustup default stable

# Install uv for Python package management
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    mv /root/.cargo/bin/uv /usr/local/bin/uv || mv /root/.local/bin/uv /usr/local/bin/uv || true

# Install snarkjs globally via npm
RUN npm install -g snarkjs

# Install Julia
RUN curl -fsSL https://install.julialang.org | sh -s -- -y

# ============================================================================
# Copy project files
# ============================================================================

# Copy only necessary files first (excluding .git)
COPY pyproject.toml uv.lock* ./
COPY helpers helpers/
COPY setup setup/
COPY tools tools/

# ============================================================================
# Clone only repositories needed at runtime
# ============================================================================

RUN echo "Cloning runtime dependencies..." && \
    # Picus - NEEDED as Racket package
    git clone https://github.com/Veridise/Picus.git tools/picus || true && \
    # EcneProject - NEEDED as Julia package
    git clone https://github.com/franklynwang/EcneProject.git tools/ecneproject || true && \
    # Helpers - NEEDED for some tools
    git clone https://github.com/cvc5/cvc5.git helpers/cvc5 || true && \
    git clone https://github.com/mit-plv/rewriter.git helpers/rewriter || true

# ============================================================================
# Install Racket-based tools (Picus)
# ============================================================================

# Install Racket packages for Picus (ignore Z3 download error - we provide Z3 4.13.0)
RUN raco pkg install --auto rosette csv-reading || true

# Create symlink for Z3 4.13.0 so Rosette can find it (Racket 8.10 path)
RUN mkdir -p /root/.local/share/racket/8.10/pkgs/rosette/bin && \
    ln -sf /usr/local/bin/z3 /root/.local/share/racket/8.10/pkgs/rosette/bin/z3 && \
    ls -la /root/.local/share/racket/8.10/pkgs/rosette/bin/z3 && \
    /root/.local/share/racket/8.10/pkgs/rosette/bin/z3 --version && \
    echo "Z3 4.13.0 symlink created for Rosette"

# Install graph dependency for Picus (ignore doc build errors)
RUN raco pkg install --auto graph || true

# Install Picus (ignore doc build errors)
RUN if [ -d "tools/picus" ] && [ -f "tools/picus/info.rkt" ]; then \
        cd tools/picus && \
        raco pkg install --auto || true; \
    fi

# ============================================================================
# Install Julia-based tools (EcneProject)
# ============================================================================

# Setup EcneProject
RUN if [ -d "tools/ecneproject" ] && [ -f "tools/ecneproject/Project.toml" ]; then \
        cd tools/ecneproject/Circom_Functions && \
        git clone https://github.com/iden3/circomlib || true && \
        cd .. && \
        julia --project=. -e 'using Pkg; Pkg.update(); Pkg.resolve(); Pkg.instantiate()' && \
        just install || true; \
    fi

# ============================================================================
# Install Python dependencies
# ============================================================================

COPY zkhydra zkhydra/
RUN uv run python -m zkhydra.main --help

# ============================================================================
# Verify all tool binaries are accessible
# ============================================================================

RUN echo "Verifying tool installations..." && \
    which z3 && z3 --version && \
    which cvc5 && cvc5 --version && \
    which circom && circom --version && \
    which circomspect && echo "circomspect: OK" && \
    which civer_circom && echo "civer_circom: OK" && \
    which zkfuzz && echo "zkfuzz: OK" && \
    echo "All tools verified successfully!"

# Set the default command
CMD ["/bin/bash"]
