APP_NAME ?= https-graphite
APP_VERSION = $(shell git describe --tags --long --dirty --always)
EXECUTABLE = $(APP_NAME)
LDFLAGS = -X main.AppVersion=$(APP_VERSION)
CERT_DIR ?= certs
SIGN_CERT_HOST ?= localhost
CA_CERT_FLAGS ?= -cacert $(CERT_DIR)/ca.crt
SERVER_CERT_FLAGS ?= -cert $(CERT_DIR)/server.crt -key $(CERT_DIR)/server.key
SERVER_PORT ?= 8081
SHELL := $(shell which bash)
GO ?= $(shell which go)

.PHONY: all
all: $(EXECUTABLE)

$(APP_NAME): https-graphite.go
	$(GO) build -o $(APP_NAME) -ldflags "$(LDFLAGS) -X main.AppName=$@" https-graphite.go

.PHONY: clean
clean:
	-$(RM) $(EXECUTABLE)

DAYS = 3650

$(CERT_DIR)/ca.crt $(CERT_DIR)/ca.key:
	@echo $@
	@mkdir -p $(CERT_DIR)
	@openssl req \
		-newkey rsa:4096 \
		-new \
		-nodes \
		-x509 \
		-days $(DAYS) \
		-out $(CERT_DIR)/ca.crt \
		-keyout $(CERT_DIR)/ca.key \
		-subj "/C=FI/O=CSC/CN=$(USER)@$(shell hostname)" &> /dev/null

.PHONY: ca
ca: $(CERT_DIR)/ca.crt $(CERT_DIR)/ca.key

$(CERT_DIR)/%.key:
	@echo $@
	@mkdir -p $(CERT_DIR)
	@openssl genpkey \
		-algorithm rsa \
		-pkeyopt rsa_keygen_bits:4096 \
		-out $(CERT_DIR)/$*.key &> /dev/null

$(CERT_DIR)/%.csr: $(CERT_DIR)/%.key
	@echo $@
	@openssl req \
		-new \
		-key $< \
		-days $(DAYS) \
		-out $(CERT_DIR)/$*.csr \
		-subj "/C=FI/O=CSC/CN=$(APP_NAME)-$*" &> /dev/null

$(CERT_DIR)/%.crt: $(CERT_DIR)/%.csr ca
	@echo $@
	@openssl x509 \
		-req \
		-in $(CERT_DIR)/$*.csr \
		-extfile <(printf "subjectAltName=DNS:$(SIGN_CERT_HOST)") \
		-CA $(CERT_DIR)/ca.crt \
		-CAkey $(CERT_DIR)/ca.key \
		-out $(CERT_DIR)/$*.crt \
		-days $(DAYS) \
		-sha256 \
		-CAcreateserial &> /dev/null

.PHONY: server-cert
server-cert: $(CERT_DIR)/server.key $(CERT_DIR)/server.crt

.PHONY: client-cert
client-cert: $(CERT_DIR)/client.key $(CERT_DIR)/client.crt

.PHONY: certs
certs: server-cert client-cert

.PHONY: clean-certs
clean-certs:
	-$(RM) -r $(CERT_DIR)

.PHONY: clean-all
clean-all: clean clean-certs
