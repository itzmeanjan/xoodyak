CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DUSE_SSE2 = -DUSE_SSE2=$(or $(SSE2),0)

all: test_aead test_kat

test/a.out: test/main.cpp include/*.hpp include/test/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DUSE_SSE2) $< -o $@

test_aead: test/a.out
	./$<

test_kat:
	bash test.sh

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla

lib:
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DUSE_SSE2) -fPIC --shared wrapper/xoodyak.cpp -o wrapper/libxoodyak.so

bench/a.out: bench/main.cpp include/*.hpp include/bench/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DUSE_SSE2) $< -lbenchmark -o $@

benchmark: bench/a.out
	./$<
