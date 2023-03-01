include config.mk

# App config.

APP_NAME = parallel

COMMON_DIR = common
COMMON_OBJS = \
	$(COMMON_DIR)/crypto.o \
	$(COMMON_DIR)/elem_t.o \
	$(COMMON_DIR)/error.o \
	$(COMMON_DIR)/util.o
COMMON_DEPS = $(COMMON_OBJS:.o=.d)

HOST_DIR = host
HOST_TARGET = $(HOST_DIR)/parallel
HOST_OBJS = \
	$(HOST_DIR)/parallel.o \
	$(HOST_DIR)/error.o
HOST_DEPS = $(HOST_OBJS:.o=.d)

ENCLAVE_DIR = enclave
ENCLAVE_TARGET = $(ENCLAVE_DIR)/parallel_enc
ENCLAVE_OBJS = \
	$(ENCLAVE_DIR)/parallel_enc.o \
	$(ENCLAVE_DIR)/bitonic.o \
	$(ENCLAVE_DIR)/bucket.o \
	$(ENCLAVE_DIR)/mpi_tls.o \
	$(ENCLAVE_DIR)/nonoblivious.o \
	$(ENCLAVE_DIR)/opaque.o \
	$(ENCLAVE_DIR)/orshuffle.o \
	$(ENCLAVE_DIR)/qsort.o \
	$(ENCLAVE_DIR)/synch.o \
	$(ENCLAVE_DIR)/threading.o \
	$(ENCLAVE_DIR)/util.o
ENCLAVE_DEPS = $(ENCLAVE_OBJS:.o=.d)
ENCLAVE_KEY = $(ENCLAVE_DIR)/$(APP_NAME).pem
ENCLAVE_PUBKEY = $(ENCLAVE_KEY:.pem=.pub)
ENCLAVE_CONF = $(ENCLAVE_DIR)/$(APP_NAME).conf

HOSTONLY_TARGET = hostonly
HOSTONLY_DEP = $(HOSTONLY_TARGET:=.d)

BASELINE_DIR = baselines
BASELINE_TARGETS = \
	$(BASELINE_DIR)/bitonic \
	$(BASELINE_DIR)/nonoblivious-bitonic \
	$(BASELINE_DIR)/nonoblivious-quickselect
BASELINE_DEPS = $(BASELINE_TARGETS:=.d)

SGX_SDK = /opt/intel/sgxsdk
MBEDTLS_SGX = third_party/mbedtls-SGX
MBEDTLS_SGX_LIBS = $(MBEDTLS_SGX)/ocall/libmbedtls_SGX_u.a $(MBEDTLS_SGX)/trusted/libmbedtls_SGX_t.a
LIBOBLIVIOUS = third_party/liboblivious
LIBOBLIVIOUS_LIB = $(LIBOBLIVIOUS)/liboblivious.a
THIRD_PARTY_LIBS = $(LIBOBLIVIOUS_LIB) $(MBEDTLS_SGX_LIBS)

CPPFLAGS = -I. \
	-I$(SGX_SDK)/include \
	-I$(LIBOBLIVIOUS)/include \
	-I$(MBEDTLS_SGX)/include \
	-DOE_SIMULATION_CERT
CFLAGS = -O3 -Wall -Wextra
LDFLAGS = \
	-L$(LIBOBLIVIOUS)
LDLIBS = \
	-l:liboblivious.a

# all target.

.PHONY: all
all: $(HOST_TARGET) $(ENCLAVE_TARGET).signed

# SGX edge.

HOST_EDGE_HEADERS = $(HOST_DIR)/$(APP_NAME)_u.h $(HOST_DIR)/$(APP_NAME)_args.h
HOST_EDGE_SRC = $(HOST_DIR)/$(APP_NAME)_u.c
HOST_EDGE_OBJS = $(HOST_EDGE_SRC:.c=.o)
ENCLAVE_EDGE_HEADERS = $(ENCLAVE_DIR)/$(APP_NAME)_t.h $(ENCLAVE_DIR)/$(APP_NAME)_args.h
ENCLAVE_EDGE_SRC = $(ENCLAVE_DIR)/$(APP_NAME)_t.c
ENCLAVE_EDGE_OBJS = $(ENCLAVE_EDGE_SRC:.c=.o)
SGX_EDGE = $(HOST_EDGE_HEADERS) $(HOST_EDGE_SRC) $(ENCLAVE_EDGE_HEADERS) $(ENCLAVE_EDGE_SRC)

$(SGX_EDGE): $(APP_NAME).edl
	$(SGX_EDGER8R) $< \
		--untrusted-dir $(HOST_DIR) \
		--trusted-dir $(ENCLAVE_DIR)

# Dependency generation.

CPPFLAGS += -MMD

%.d: $(SGX_EDGE);

# Third-party deps.

$(LIBOBLIVIOUS_LIB):
	$(MAKE) -C $(LIBOBLIVIOUS)

# Host.

HOST_CPPFLAGS = $(CPPFLAGS)
HOST_CFLAGS = \
	$(shell pkg-config mpi --cflags) \
	$(CFLAGS)
HOST_LDFLAGS = \
	-L$(SGX_SDK)/lib64 \
	-L$(MBEDTLS_SGX)/ocall \
	$(LDFLAGS)
HOST_LDLIBS = \
	$(shell pkg-config mpi --libs) \
	-lmbedcrypto \
	-lmbedtls_SGX_u \
	-lsgx_urts \
	$(LDLIBS)

$(HOST_DIR)/%.o: $(HOST_DIR)/%.c
	$(CC) $(HOST_CFLAGS) $(HOST_CPPFLAGS) -c -o $@ $<

$(HOST_TARGET): $(HOST_OBJS) $(HOST_EDGE_OBJS) $(COMMON_OBJS) $(THIRD_PARTY_LIBS)
	$(CC) $(HOST_LDFLAGS) $(HOST_OBJS) $(HOST_EDGE_OBJS) $(COMMON_OBJS) $(HOST_LDLIBS) -o $@

# Enclave.

ENCLAVE_CPPFLAGS = \
	-nostdinc -I$(SGX_SDK)/include/tlibc \
	$(CPPFLAGS)
ENCLAVE_CFLAGS = \
	-ffreestanding \
	-ffunction-sections \
	-fdata-sections \
	$(CFLAGS)
ENCLAVE_LDFLAGS = \
	-nostdlib \
	-L$(SGX_SDK)/lib64 \
	-L$(MBEDTLS_SGX)/trusted \
	$(LDFLAGS)
ENCLAVE_LDLIBS = \
	-Wl,--whole-archive -lsgx_trts -Wl,--no-whole-archive \
	-Wl,--start-group \
		-lmbedtls_SGX_t \
		-lsgx_tstdc \
		-lsgx_tcxx \
		-lsgx_tcrypto \
		-lsgx_tservice \
		$(LDLIBS) \
	-Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c
	$(CC) $(ENCLAVE_CFLAGS) $(ENCLAVE_CPPFLAGS) -c -o $@ $<

$(ENCLAVE_TARGET): $(ENCLAVE_OBJS) $(ENCLAVE_EDGE_OBJS) $(COMMON_OBJS) $(THIRD_PARTY_LIBS)
	$(CC) $(ENCLAVE_LDFLAGS) $(ENCLAVE_OBJS) $(ENCLAVE_EDGE_OBJS) $(COMMON_OBJS) $(ENCLAVE_LDLIBS) -o $@

$(ENCLAVE_TARGET).signed: $(ENCLAVE_TARGET) $(ENCLAVE_KEY) $(ENCLAVE_PUBKEY) $(ENCLAVE_CONF)
	$(SGX_SIGN) sign -enclave $< -out $@ -key $(ENCLAVE_KEY) -config $(ENCLAVE_CONF)

$(ENCLAVE_KEY):
	openssl genrsa -out $@ -3 3072

$(ENCLAVE_PUBKEY): $(ENCLAVE_KEY) $(ENCLAVE_CONF)
	openssl rsa -in $< -pubout -out $@

# Common.

$(COMMON_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(HOST_CFLAGS) $(HOST_CPPFLAGS) -c -o $@ $<

# Host-only binary for profiling.

HOSTONLY_CPPFLAGS = $(HOST_CPPFLAGS) -DDISTRIBUTED_SGX_SORT_HOSTONLY
HOSTONLY_CFLAGS = $(HOST_CFLAGS) -Wno-implicit-function-declaration -Wno-unused
HOSTONLY_LDFLAGS = $(HOST_LDFLAGS)
HOSTONLY_LDLIBS = $(HOST_LDLIBS) \
	-lmbedx509 \
	-lmbedtls

$(HOSTONLY_TARGET): $(HOST_OBJS:.o=.c) $(ENCLAVE_OBJS:.o=.c) $(COMMON_OBJS:.o=.c) $(THIRD_PARTY_LIBS)
	$(CC) $(HOSTONLY_CFLAGS) $(HOSTONLY_CPPFLAGS) $(HOSTONLY_LDFLAGS) $(HOST_OBJS:.o=.c) $(ENCLAVE_OBJS:.o=.c) $(COMMON_OBJS:.o=.c) $(HOSTONLY_LDLIBS) -o $@

# Baselines.

BASELINE_CPPFLAGS = $(HOST_CPPFLAGS)
BASELINE_CFLAGS = $(HOST_CFLAGS)
BASELINE_LDFLAGS = $(HOST_LDFLAGS)
BASELINE_LDLIBS = $(HOST_LDLIBS)

$(BASELINE_DIR)/%: $(BASELINE_DIR)/%.c $(HOST_DIR)/error.o $(COMMON_OBJS:.o=.c) $(THIRD_PARTY_LIBS)
	$(CC) $(BASELINE_CFLAGS) $(BASELINE_CPPFLAGS) $(BASELINE_LDFLAGS) $< $(HOST_DIR)/error.o $(COMMON_OBJS:.o=.c) $(BASELINE_LDLIBS) -o $@

# Misc.

.PHONY: clean
clean:
	$(MAKE) -C $(LIBOBLIVIOUS) clean
	rm -f $(SGX_EDGE) \
		$(COMMON_DEPS) $(COMMON_OBJS) \
		$(HOST_TARGET) $(HOST_DEPS) $(HOST_OBJS) \
		$(ENCLAVE_TARGET).signed $(ENCLAVE_TARGET) $(ENCLAVE_DEPS) $(ENCLAVE_OBJS) \
		$(ENCLAVE_PUBKEY) $(ENCLAVE_KEY) \
		$(HOSTONLY_TARGET) $(HOSTONLY_DEP) \
		$(BASELINE_TARGETS) $(BASELINE_DEPS)

-include $(COMMON_DEPS)
-include $(HOST_DEPS)
-include $(ENCLAVE_DEPS)
-include $(HOSTONLY_DEP)
-include $(BASELINE_DEPS)
