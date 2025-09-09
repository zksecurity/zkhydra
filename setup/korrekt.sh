
# Install CVC5 and Rust

uv add gmp
uv add libpgm
# find /usr /opt -name "libgmp.a"
# export GMP_LIB=/usr/lib/x86_64-linux-gnu/libgmp.a
export GMP_LIB=$(find /usr /opt -name "libgmp.a" 2>/dev/null | head -n 1)

cd tools/halo2/korrekt/

