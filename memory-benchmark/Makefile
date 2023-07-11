include config.mk

# App config.

APP_NAME = membenchmark

HOST_DIR = host
HOST_TARGET = $(HOST_DIR)/$(APP_NAME)
HOST_OBJS = \
	$(HOST_DIR)/$(APP_NAME).o
HOST_DEPS = $(HOST_OBJS:.o=.d)

ENCLAVE_DIR = enclave
ENCLAVE_TARGET = $(ENCLAVE_DIR)/$(APP_NAME)_enc
ENCLAVE_OBJS = \
	$(ENCLAVE_DIR)/$(APP_NAME)_enc.o
ENCLAVE_DEPS = $(ENCLAVE_OBJS:.o=.d)
ENCLAVE_KEY = $(ENCLAVE_DIR)/$(APP_NAME).pem
ENCLAVE_PUBKEY = $(ENCLAVE_KEY:.pem=.pub)
ENCLAVE_CONF = $(ENCLAVE_DIR)/$(APP_NAME).conf

THIRD_PARTY_LIBS =

CPPFLAGS = -I.
CFLAGS = -O3 -Wall -Wextra -Werror
LDFLAGS =
LDLIBS =

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

INCDIR = $(shell pkg-config oehost-$(C_COMPILER) --variable=includedir)
$(SGX_EDGE): $(APP_NAME).edl
	$(SGX_EDGER8R) $< \
		--untrusted-dir $(HOST_DIR) \
		--trusted-dir $(ENCLAVE_DIR) \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx

# Dependency generation.

CPPFLAGS += -MMD

# Third-party deps.

# Host.

HOST_CPPFLAGS = $(CPPFLAGS)
HOST_CFLAGS = \
	$(shell pkg-config oehost-$(C_COMPILER) --cflags) \
	$(CFLAGS)
HOST_LDFLAGS = $(LDFLAGS)
HOST_LDLIBS = \
	$(shell pkg-config oehost-$(C_COMPILER) --libs) \
	$(LDLIBS)

$(HOST_DIR)/%.o: $(HOST_DIR)/%.c $(HOST_EDGE_HEADERS)
	$(CC) $(HOST_CFLAGS) $(HOST_CPPFLAGS) -c -o $@ $<

$(HOST_TARGET): $(HOST_OBJS) $(HOST_EDGE_OBJS) $(THIRD_PARTY_LIBS)
	$(CC) $(HOST_LDFLAGS) $(HOST_OBJS) $(HOST_EDGE_OBJS) $(HOST_LDLIBS) -o $@

# Enclave.

ENCLAVE_CPPFLAGS = $(CPPFLAGS)
ENCLAVE_CFLAGS = \
	$(shell pkg-config oeenclave-$(C_COMPILER) --cflags) \
	$(CFLAGS)
ENCLAVE_LDFLAGS = $(LDFLAGS)
ENCLAVE_LDLIBS = \
	$(shell pkg-config oeenclave-$(C_COMPILER) --libs) \
	$(shell pkg-config oeenclave-$(C_COMPILER) --variable=mbedtlslibs) \
	$(LDLIBS)

$(ENCLAVE_DIR)/%.o: $(ENCLAVE_DIR)/%.c $(ENCLAVE_EDGE_HEADERS)
	$(CC) $(ENCLAVE_CFLAGS) $(ENCLAVE_CPPFLAGS) -c -o $@ $<

$(ENCLAVE_TARGET): $(ENCLAVE_OBJS) $(ENCLAVE_EDGE_OBJS) $(THIRD_PARTY_LIBS)
	$(CC) $(ENCLAVE_LDFLAGS) $(ENCLAVE_OBJS) $(ENCLAVE_EDGE_OBJS) $(ENCLAVE_LDLIBS) -o $@

$(ENCLAVE_TARGET).signed: $(ENCLAVE_TARGET) $(ENCLAVE_KEY) $(ENCLAVE_PUBKEY) $(ENCLAVE_CONF)
	$(SGX_SIGN) sign -e $< -k $(ENCLAVE_KEY) -c $(ENCLAVE_CONF)

$(ENCLAVE_KEY):
	openssl genrsa -out $@ -3 3072

$(ENCLAVE_PUBKEY): $(ENCLAVE_KEY)
	openssl rsa -in $< -pubout -out $@

# Misc.

.PHONY: clean
clean:
	rm -f $(SGX_EDGE) \
		$(HOST_TARGET) $(HOST_DEPS) $(HOST_OBJS) \
		$(ENCLAVE_TARGET).signed $(ENCLAVE_TARGET) $(ENCLAVE_DEPS) $(ENCLAVE_OBJS) \
		$(ENCLAVE_PUBKEY) $(ENCLAVE_KEY)

-include $(HOST_DEPS)
-include $(ENCLAVE_DEPS)
