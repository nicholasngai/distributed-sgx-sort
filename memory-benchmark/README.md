# SGX2 Memory Benchmarking Code

This code is used to reproduce strange SGX2 observed during the development of this project. It's a simple piece of code that allocates a large array and performs a sequential set of memory writes over the entire array with multiple threads, doubling the size of the array until it hits the memory limit.

## Setup, Compilation, and Execution

1. Run the script ./scripts/install-dependencies.sh to install all the dependencies needed to compile and run the code via APT.
2. Load the new environment by running `exec bash -l` in order to add the Open Enclave variables to your PATH. The previous script will have automatically added a line to your .bash_profile.
3. Tweak the EPC memory size by setting the `NumHeapPages` in enclave/membenchmark.conf to **half** the available system memory. The page size is 4096 bytes.
   - For example, if the system has 128 GB of physical memory, half the available system memory in pages would be `128 * 2^30 / 4096 / 2 == 16777216` pages, so you would set `NumHeapPages=16777216` in enclave/membenchmark.conf.
4. Compile the code with `make -j`.
5. Run the code with `./host/membenchmark ./enclave/membenchmark_enc.signed`.
