.PHONY: list

BINNAME = charon

OS := $(shell uname)
ifeq ($(OS),Darwin)
	# Mac specific
	LINKER_TOOL = otool -L
else
	# Linux specific
	LINKER_TOOL = ldd
endif

## UTILS ##
# Recursive wildcard function
# http://blog.jgc.org/2011/07/gnu-make-recursive-wildcard-function.html
rwildcard=$(foreach d,$(wildcard $1*),$(call rwildcard,$d/,$2) \
  $(filter $(subst *,%,$2),$d))

all: build test strip upx stats size deps outdated doc dot

install_deps:
		cargo install cargo-count
		cargo install cargo-graph
		cargo install cargo-multi
		cargo install cargo-outdated

build: build-debug build-release

build-debug:
		cargo build

build-release:
		cargo build --release

clean: clean-debug clean-release

clean-debug:
		cargo clean

clean-release:
		cargo clean --release

deps: deps-debug deps-release

deps-debug: build-debug
		${LINKER_TOOL} ./target/debug/${BINNAME}

deps-release: build-release
		${LINKER_TOOL} ./target/release/${BINNAME}

doc:
		cargo doc

dot:
		cargo graph \
			--optional-line-style dashed \
			--optional-line-color red \
			--optional-shape box \
			--build-shape diamond \
			--build-color green \
			--build-line-color orange \
			> doc/deps/cargo-count.dot

		dot -Tpng > doc/deps/rainbow-graph.png doc/deps/cargo-count.dot

list:
		@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null | awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' | sort | egrep -v -e '^[^[:alnum:]]' -e '^$@$$' | xargs

outdated:
		cargo outdated

rebuild: rebuild-debug rebuild-release

rebuild-debug: clean-debug build-debug

rebuild-release: clean-release build-release

size-debug:
		ls -lah ./target/debug/${BINNAME}

size-release:
		ls -lah ./target/release/${BINNAME}

size: size-debug size-release

stats:
		cargo count --separator , --unsafe-statistics

strip:
		strip ./target/release/${BINNAME}

test:
		cargo test

update:
		cargo multi update

upx: ./target/release/${BINNAME}
		upx -fq --ultra-brute --best -o ./bin/${BINNAME} ./target/release/${BINNAME}

watch:
		cargo watch
