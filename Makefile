CXX = dpcpp
CXXFLAGS = -std=c++20 -Wall -Wextra -Weverything -Wno-c++98-compat -Wno-c++98-c++11-compat-binary-literal -Wno-c++98-compat-pedantic
OPTFLAGS = -O3
IFLAGS = -I ./include

all: lib

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla

lib:
	$(CXX) $(CXXFLAGS) -Wno-unused-function $(OPTFLAGS) $(IFLAGS) -fPIC --shared wrapper/xoodyak.cpp -o wrapper/libxoodyak.so

bench/a.out: bench/main.cpp include/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) -Wno-global-constructors $(OPTFLAGS) $(IFLAGS) $< -lbenchmark -lpthread -o $@

benchmark: bench/a.out
	./$<
