# Distributed SGX Sort

## Dependencies

This project requires Ubuntu 20.04 LTS to run. The following libraries are
required:

- [Open Enclave](https://github.com/openenclave/openenclave)
- [MPICH](https://www.mpich.org/)
- [Mbed TLS](https://tls.mbed.org/)

The `install-dependencies.sh` script in the `scripts` folder will set up the
required repositories and install the dependencies for you through APT. This
script must be run as root If you do not wish to use APT, you may follow the
installation guide for each library individually.

Additionally, you must have `openssl` available in your PATH, which is used to
generate the signed enclave object.

## Compilation

This project uses Git submodules. If you did not clone recursively, please run,
`git submodule update --init --recursive` to initialize the submodules.

This project uses Make to compile the project. Run `make` in order to compile
the project from the home directory.

## Invocation

The usage of this project is as follows:

```
./host/parallel ./enclave/parallel_enc.signed array_size [num_threads]
```

This instantiates a array of size `array_size` and sorts it obliviously. To run
a distributed sorting instance, use `mpirun`:

```
mpirun [-hosts host_list] ./host/parallel ./enclave/parallel_enc.signed array_size [num_threads]
```

Make sure that the files are available at the same path for all MPI hosts. An
easy way to do this is to use rsync or scp to copy the files to the same path or
use NFS to mount a shared volume across all machines.

## Profiling

Because profiling cannot be performed from inside enclaves, a host-only version
of the binary is available, with adjustable compilation flags. An easy way to
compile a host-only version of the binary with gprof is to use

```
make HOSTONLY_CFLAGS=-pg HOSTONLY_LDFLAGS=-pg hostonly
```

and invoke with

```
./hostonly array_size [num_threads]
```

or

```
mpirun [-hosts host_list] ./hostonly array_size [num_threads]
```

The outputted gprof profile may then be analyzed using

```
gprof ./hostonly
```

## Benchmarking

Benchmarking can be performed with scripts available in the `scripts` directory.
The `benchmark.sh` script will run all available sorting algorithms from 1 to 32
enclaves, each with 1 to 8 threads. This script assumes that each host will have
the hostname `enclaveN`, where `N` is the zero-index of the enclave. The
benchmarked outputs are placed in a `benchmarks` folder.

## Contributors

- Nicholas Ngai (nicholas.ngai@berkeley.edu)
