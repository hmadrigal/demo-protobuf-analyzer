all: build test

build:
	@echo "Building..."
	@./configure
	@cd build && make

rebuild: clean build

test:
	@echo "Testing..."
	@cd testing && make test

clean:
	@echo "Cleaning..."
	@rm -rf build
	@cd testing && make clean