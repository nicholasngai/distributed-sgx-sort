include config.mk

# App config.

APP_NAME = parallel

COMMON_DIR = common
COMMON_OBJS = \
	$(COMMON_DIR)/crypto.o \
	$(COMMON_DIR)/error.o \
	$(COMMON_DIR)/node_t.o
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
	$(ENCLAVE_DIR)/synch.o \
	$(ENCLAVE_DIR)/mpi_tls.o
ENCLAVE_DEPS = $(ENCLAVE_OBJS:.o=.d)
ENCLAVE_KEY = $(ENCLAVE_DIR)/$(APP_NAME).pem
ENCLAVE_PUBKEY = $(ENCLAVE_KEY:.pem=.pub)
ENCLAVE_CONF = $(ENCLAVE_DIR)/$(APP_NAME).conf

HOSTONLY_TARGET = hostonly

CPPFLAGS = -I. -I$(INCDIR)
CFLAGS = -g -O3 -Wall -Wextra
LDFLAGS =
LDLIBS =

# SGX edge.

HOST_EDGE_HEADERS = $(HOST_DIR)/$(APP_NAME)_u.h $(HOST_DIR)/$(APP_NAME)_args.h
HOST_EDGE_SRC = $(HOST_DIR)/$(APP_NAME)_u.c
HOST_EDGE_OBJS = $(HOST_EDGE_SRC:.c=.o)
ENCLAVE_EDGE_HEADERS = $(ENCLAVE_DIR)/$(APP_NAME)_t.h $(ENCLAVE_DIR)/$(APP_NAME)_args.h
ENCLAVE_EDGE_SRC = $(ENCLAVE_DIR)/$(APP_NAME)_t.c
ENCLAVE_EDGE_OBJS = $(ENCLAVE_EDGE_SRC:.c=.o)
SGX_EDGE = $(HOST_EDGE_HEADERS) $(HOST_EDGE_SRC) $(ENCLAVE_EDGE_HEADERS) $(ENCLAVE_EDGE_SRC)

INCDIR = $(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)

.PHONY: all
all: $(HOST_TARGET) $(ENCLAVE_TARGET).signed

$(SGX_EDGE): $(APP_NAME).edl
	$(SGX_EDGER8R) $< \
		--untrusted-dir $(HOST_DIR) \
		--trusted-dir $(ENCLAVE_DIR) \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx

# Dependency generation.

CPPFLAGS += -MMD

%.d: $(SGX_EDGE);

# Host.

HOST_CPPFLAGS =
HOST_CFLAGS = $(shell pkg-config mpi --cflags)
HOST_LDFLAGS =
HOST_LDLIBS = -lmbedcrypto \
	$(shell pkg-config mpi --libs)

HOST_OE_CFLAGS = $(shell pkg-config oehost-$(C_COMPILER) --cflags)
HOST_OE_LDLIBS = $(shell pkg-config oehost-$(C_COMPILER) --libs)

$(HOST_DIR)/%.o: CPPFLAGS += $(HOST_CPPFLAGS)
$(HOST_DIR)/%.o: CFLAGS += $(HOST_CFLAGS)

$(HOST_TARGET): CFLAGS += $(HOST_OE_CFLAGS)
$(HOST_TARGET): LDFLAGS += $(HOST_LDFLAGS)
$(HOST_TARGET): LDLIBS += $(HOST_LDLIBS) $(HOST_OE_LDLIBS)
$(HOST_TARGET): $(HOST_OBJS) $(HOST_EDGE_OBJS) $(COMMON_OBJS)

# Enclave.

ENCLAVE_CPPFLAGS = -I$(ENCLAVE_DIR)/third_party/liboblivious/include
ENCLAVE_CFLAGS =
ENCLAVE_LDFLAGS =
ENCLAVE_LDLIBS = -L$(ENCLAVE_DIR)/third_party/liboblivious -l:liboblivious.a

ENCLAVE_OE_CFLAGS = $(shell pkg-config oehost-$(C_COMPILER) --cflags)
ENCLAVE_OE_LDLIBS = \
	$(shell pkg-config oeenclave-$(C_COMPILER) --libs) \
	$(shell pkg-config oeenclave-$(C_COMPILER) --variable=mbedtlslibs)

$(ENCLAVE_DIR)/%.o: CPPFLAGS += $(ENCLAVE_CPPFLAGS)
$(ENCLAVE_DIR)/%.o: CFLAGS += $(ENCLAVE_CFLAGS)

$(ENCLAVE_DIR)/third_party/liboblivious/liboblivious.a:
	$(MAKE) -C $(ENCLAVE_DIR)/third_party/liboblivious

$(ENCLAVE_TARGET): CFLAGS += $(ENCLAVE_OE_CFLAGS)
$(ENCLAVE_TARGET): LDFLAGS += $(ENCLAVE_LDFLAGS)
$(ENCLAVE_TARGET): LDLIBS += $(ENCLAVE_LDLIBS) $(ENCLAVE_OE_LDLIBS)
$(ENCLAVE_TARGET): $(ENCLAVE_OBJS) $(ENCLAVE_EDGE_OBJS) $(COMMON_OBJS) $(ENCLAVE_DIR)/third_party/liboblivious/liboblivious.a

$(ENCLAVE_TARGET).signed: $(ENCLAVE_TARGET) $(ENCLAVE_KEY) $(ENCLAVE_PUBKEY) $(ENCLAVE_CONF)
	$(SGX_SIGN) sign -e $< -k $(ENCLAVE_KEY) -c $(ENCLAVE_CONF)

$(ENCLAVE_KEY):
	openssl genrsa -out $@ -3 3072

$(ENCLAVE_PUBKEY): $(ENCLAVE_KEY) $(ENCLAVE_CONF)
	openssl rsa -in $< -pubout -out $@

# Host-only binary for profiling.

HOSTONLY_CPPFLAGS = -DDISTRIBUTED_SGX_SORT_HOSTONLY $(HOST_CPPFLAGS) $(ENCLAVE_CPPFLAGS)
HOSTONLY_CFLAGS = $(HOST_CFLAGS)
HOSTONLY_LDFLAGS =
HOSTONLY_LDLIBS = -lmbedtls -lmbedx509 \
	$(HOST_LDLIBS) $(ENCLAVE_LDLIBS)

$(HOSTONLY_TARGET): CPPFLAGS += $(HOSTONLY_CPPFLAGS)
$(HOSTONLY_TARGET): CFLAGS += $(HOSTONLY_CFLAGS)
$(HOSTONLY_TARGET): LDFLAGS += $(HOSTONLY_LDFLAGS)
$(HOSTONLY_TARGET): LDLIBS += $(HOSTONLY_LDLIBS)
$(HOSTONLY_TARGET): $(HOST_OBJS:.o=.c) $(ENCLAVE_OBJS:.o=.c) $(COMMON_OBJS:.o=.c) $(ENCLAVE_DIR)/third_party/liboblivious/liboblivious.a
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $^ $(LDLIBS) -o $@

# Misc.

.PHONY: clean
clean:
	$(MAKE) -C $(ENCLAVE_DIR)/third_party/liboblivious clean
	rm -f $(SGX_EDGE) \
		$(COMMON_DEPS) $(COMMON_OBJS) \
		$(HOST_TARGET) $(HOST_DEPS) $(HOST_OBJS) \
		$(ENCLAVE_TARGET).signed $(ENCLAVE_TARGET) $(ENCLAVE_DEPS) $(ENCLAVE_OBJS) \
		$(ENCLAVE_PUBKEY) $(ENCLAVE_KEY) \
		$(HOSTONLY_TARGET)

-include $(COMMON_DEPS) $(HOST_DEPS) $(ENCLAVE_DEPS)
