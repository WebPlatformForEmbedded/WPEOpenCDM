#
 # Copyright (C) 2016 TATA ELXSI
 # Copyright (C) 2016 Metrological
 # All rights reserved.
 #
 # Redistribution and use in source and binary forms, with or without
 # modification, are permitted provided that the following conditions
 # are met:
 # 1. Redistributions of source code must retain the above copyright
 #    notice, this list of conditions and the following disclaimer.
 # 2. Redistributions in binary form must reproduce the above copyright
 #    notice, this list of conditions and the following disclaimer in the
 #    documentation and/or other materials provided with the distribution.
 #
 # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 # "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 # LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 # PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 # HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 # SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 # LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 # DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 # THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 # (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 # OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 #

RM := rm  -rf
OCDM_CLIENT_DIR =  $(shell pwd)
OCDM_ROOT_PATH = $(OCDM_CLIENT_DIR)/../../..
OCDM_WPE_ROOT_PATH = $(OCDM_CLIENT_DIR)/..

MODULES   := cdm mediaengine common com/cdm/rpc com/cdm  com/mediaengine/rpc com/common/shmemsem
OCDM_SOURCES_CC_DIR   := $(addprefix $(OCDM_ROOT_PATH)/,$(MODULES))
OCDM_HEADER_PATH := $(foreach sdir,$(OCDM_SOURCES_CC_DIR),$(addprefix -I,$(sdir)/))

LD_FLAGS += -L $(OCDM_WPE_ROOT_PATH)/lib -locdm $(LDFLAGS)

OCDM_INCLUDES = -I $(OCDM_ROOT_PATH) \
                -I $(OCDM_WPE_ROOT_PATH)/opencdm \
                $(OCDM_HEADER_PATH)

CXFLAGS := -std=c++11 -g $(OCDM_INCLUDES) -pthread $(CXXFLAGS)

all: ocdm_client ocdm_decryptor
	@echo "Building ocdm client"

ocdm_client: ocdm_client.cpp
	$(MAKE) -C $(OCDM_CLIENT_DIR)/../opencdm all
	@mkdir -p $(OCDM_WPE_ROOT_PATH)/bin
	$(CXX) $< $(CXFLAGS) $(LD_FLAGS) -Wall -o  $(OCDM_WPE_ROOT_PATH)/bin/ocdm_client

	@echo "Building ocdm decryptor"

ocdm_decryptor: ocdm_decryptor.cpp
	$(MAKE) -C $(OCDM_CLIENT_DIR)/../opencdm all
	@cd $(OCDM_WPE_ROOT_PATH)/bin
	$(CXX) $< $(CXFLAGS) $(LD_FLAGS) -Wall -o  $(OCDM_WPE_ROOT_PATH)/bin/ocdm_decryptor

.PHONY: clean ocdm_client ocdm_decryptor
clean:
	@echo "Cleaning ocdm client"
	@rm -f $(OCDM_WPE_ROOT_PATH)/bin/ocdm_client

	@echo "Cleaning ocdm decryptor"
	@rm -rf $(OCDM_WPE_ROOT_PATH)/bin/ocdm_decryptor

