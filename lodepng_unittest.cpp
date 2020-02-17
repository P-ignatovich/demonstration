/*
LodePNG Unit Test

Copyright (c) 2005-2020 Lode Vandevenne

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/

//g++ lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Wall -Wextra -Wsign-conversion -pedantic -ansi -O3

/*
Testing instructions:

*) Ensure no tests commented out below or early return in doMain

*) Compile with g++ with all warnings and run the unit test
g++ lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Werror -Wall -Wextra -Wsign-conversion -Wshadow -pedantic -ansi -O3 && ./a.out

*) Compile with clang, which may sometimes give different warnings
clang++ lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Werror -Wall -Wextra -Wsign-conversion -Wshadow -pedantic -ansi -O3

*) Compile with pure ISO C90 and all warnings:
mv lodepng.cpp lodepng.c ; gcc -I ./ lodepng.c examples/example_decode.c -ansi -pedantic -Werror -Wall -Wextra -O3 ; mv lodepng.c lodepng.cpp

mv lodepng.cpp lodepng.c ; clang -I ./ lodepng.c examples/example_decode.c -ansi -pedantic -Werror -Wall -Wextra -O3 ; mv lodepng.c lodepng.cpp

*) Compile with C with -pedantic but not -ansi flag so it warns about // style comments in C++-only ifdefs
mv lodepng.cpp lodepng.c ; gcc -I ./ lodepng.c examples/example_decode.c -pedantic -Werror -Wall -Wextra -O3 ; mv lodepng.c lodepng.cpp

*) try lodepng_benchmark.cpp
g++ lodepng.cpp lodepng_benchmark.cpp -Werror -Wall -Wextra -pedantic -ansi -lSDL -O3 && ./a.out testdata/corpus/''*

*) try the fuzzer
clang++ -fsanitize=fuzzer -DLODEPNG_MAX_ALLOC=100000000 lodepng.cpp lodepng_fuzzer.cpp -O3 -o fuzzer && ./fuzzer

clang++ -fsanitize=fuzzer,address,undefined -DLODEPNG_MAX_ALLOC=100000000 lodepng.cpp lodepng_fuzzer.cpp -O3 -o fuzzer && ./fuzzer

*) Check if all C++ examples compile without warnings:
g++ -I ./ lodepng.cpp examples/''*.cpp -Werror -W -Wall -ansi -pedantic -O3 -c

*) Check if all C examples compile without warnings:
mv lodepng.cpp lodepng.c ; gcc -I ./ lodepng.c examples/''*.c -Werror -W -Wall -ansi -pedantic -O3 -c ; mv lodepng.c lodepng.cpp

*) Check pngdetail.cpp:
g++ lodepng.cpp lodepng_util.cpp pngdetail.cpp -Werror -W -Wall -ansi -pedantic -O3 -o pngdetail
./pngdetail testdata/PngSuite/basi0g01.png

*) Test compiling with some code sections with #defines disabled, for unused static function warnings etc...
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ZLIB
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_PNG
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_DECODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ENCODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_DISK
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ANCILLARY_CHUNKS
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ERROR_TEXT
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_CPP
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ZLIB -DLODEPNG_NO_COMPILE_DECODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ZLIB -DLODEPNG_NO_COMPILE_ENCODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_PNG -DLODEPNG_NO_COMPILE_DECODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_PNG -DLODEPNG_NO_COMPILE_ENCODER
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_DECODER -DLODEPNG_NO_COMPILE_ANCILLARY_CHUNKS -DLODEPNG_NO_COMPILE_ERROR_TEXT -DLODEPNG_NO_COMPILE_DISK
g++ lodepng.cpp -W -Wall -ansi -pedantic -O3 -c -DLODEPNG_NO_COMPILE_ENCODER -DLODEPNG_NO_COMPILE_ANCILLARY_CHUNKS -DLODEPNG_NO_COMPILE_ERROR_TEXT -DLODEPNG_NO_COMPILE_DISK
rm *.o

*) analyze with clang:
clang++ lodepng.cpp --analyze

More verbose:
clang++ --analyze -Xanalyzer -analyzer-output=text lodepng.cpp

Or html, look under lodepng.plist dir afterwards and find the numbered locations in the pages:
clang++ --analyze -Xanalyzer -analyzer-output=html lodepng.cpp

*) check for memory leaks and vulnerabilities with valgrind
(DISABLE_SLOW disables a few tests that are very slow with valgrind)
g++ -DDISABLE_SLOW lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Wall -Wextra -pedantic -ansi -O3 -DLODEPNG_MAX_ALLOC=100000000 && valgrind --leak-check=full --track-origins=yes ./a.out

*) Try with clang++ and address sanitizer (to get line numbers, make sure 'llvm' is also installed to get 'llvm-symbolizer'
clang++ -O3 -fsanitize=address,undefined lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Werror -Wall -Wextra -Wshadow -pedantic -ansi && ASAN_OPTIONS=allocator_may_return_null=1 ./a.out

clang++ -g3 -fsanitize=address,undefined lodepng.cpp lodepng_util.cpp lodepng_unittest.cpp -Werror -Wall -Wextra -Wshadow -pedantic -ansi && ASAN_OPTIONS=allocator_may_return_null=1 ./a.out

*) remove "#include <iostream>" from lodepng.cpp if it's still in there (some are legit)
cat lodepng.cpp lodepng_util.cpp | grep iostream
cat lodepng.cpp lodepng_util.cpp | grep stdio
cat lodepng.cpp lodepng_util.cpp | grep "#include"

*) try the Makefile
make clean && make -j

*) check that no plain "free", "malloc", "realloc", "strlen", "memcpy", ... used, but the lodepng_* versions instead

*) check version dates in copyright message and LODEPNG_VERSION_STRING

*) check year in copyright message at top of all files as well as at bottom of lodepng.h

*) check examples/sdl.cpp with the png test suite images (the "x" ones are expected to show error)
g++ -I ./ lodepng.cpp examples/example_sdl.cpp -Werror -Wall -Wextra -pedantic -ansi -O3 -lSDL -o showpng && ./showpng testdata/PngSuite/''*.png

*) strip trailing spaces and ensure consistent newlines

*) check diff of lodepng.cpp and lodepng.h before submitting
git difftool -y

*/

#include "lodepng.h"
#include "lodepng_util.h"

#include <cmath>
#include <map>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include <stdio.h>
#include <stdlib.h>

////////////////////////////////////////////////////////////////////////////////

void fail() {
  throw 1; //that's how to let a unittest fail
}

//Utility for debug messages
template<typename T>
std::string valtostr(const T& val) {
  std::ostringstream sstream;
  sstream << val;
  return sstream.str();
}

//Print char as a numeric value rather than a character
template<>
std::string valtostr(const unsigned char& val) {
  std::ostringstream sstream;
  sstream << (int)val;
  return sstream.str();
}

//Print char pointer as pointer, not as string
template<typename T>
std::string valtostr(const T* val) {
  std::ostringstream sstream;
  sstream << (const void*)val;
  return sstream.str();
}

template<typename T>
std::string valtostr(const std::vector<T>& val) {
  std::ostringstream sstream;
  sstream << "[vector with size " << val.size() << "]";
  return sstream.str();
}

// TODO: remove, use only ASSERT_EQUALS (it prints line number). Requires adding extra message ability to ASSERT_EQUALS
template<typename T, typename U>
void assertEquals(const T& expected, const U& actual, const std::string& message = "") {
  if(expected != (T)actual) {
    std::cout << "Error: Not equal! Expected " << valtostr(expected)
              << " got " << valtostr((T)actual) << ". "
              << "Message: " << message << std::endl;
    fail();
  }
}

// TODO: turn into ASSERT_TRUE with line number printed
void assertTrue(bool value, const std::string& message = "") {
  if(!value) {
    std::cout << "Error: expected true. " << "Message: " << message << std::endl;
    fail();
  }
}

//assert that no error
void assertNoPNGError(unsigned error, const std::string& message = "") {
  if(error) {
    std::string msg = (message == "") ? lodepng_error_text(error)
                                      : message + std::string(": ") + lodepng_error_text(error);
    assertEquals(0, error, msg);
  }
}

void assertNoError(unsigned error) {
  if(error) {
    assertEquals(0, error, "Expected no error");
  }
}

#define STR_EXPAND(s) #s
#define STR(s) STR_EXPAND(s)
#define ASSERT_EQUALS(e, v) {\
  if((e) != (v)) {\
    std::cout << std::string("line ") + STR(__LINE__) + ": " + STR(v) + " ASSERT_EQUALS failed: ";\
    std::cout << "Expected " << valtostr(e) << " but got " << valtostr(v) << ". " << std::endl;\
    fail();\
  }\
}
#define ASSERT_NOT_EQUALS(e, v) {\
  if((e) == (v)) {\
    std::cout << std::string("line ") + STR(__LINE__) + ": " + STR(v) + " ASSERT_NOT_EQUALS failed: ";\
    std::cout << "Expected not " << valtostr(e) << " but got " << valtostr(v) << ". " << std::endl;\
    fail();\
  }\
}

template<typename T, typename U, typename V>
bool isNear(T e, U v, V maxdist) {
  T dist = e > (T)v ? e - (T)v : (T)v - e;
  return dist <= (T)maxdist;
}

template<typename T, typename U>
T diff(T e, U v) {
  return v > e ? v - e : e - v;
}

#define ASSERT_NEAR(e, v, maxdist) {\
  if(!isNear(e, v, maxdist)) {\
    std::cout << std::string("line ") + STR(__LINE__) + ": " + STR(v) + " ASSERT_NEAR failed: ";\
    std::cout << "dist too great! Expected near " << valtostr(e) << " but got " << valtostr(v) << ", with max dist " << valtostr(maxdist)\
              << " but got dist " << valtostr(diff(e, v)) << ". " << std::endl;\
    fail();\
  }\
}

#define ASSERT_STRING_EQUALS(e, v) ASSERT_EQUALS(std::string(e), std::string(v))
#define ASSERT_NO_PNG_ERROR_MSG(error, message) assertNoPNGError(error, std::string("line ") + STR(__LINE__) + (std::string(message).empty() ? std::string("") : (": " + std::string(message))))
#define ASSERT_NO_PNG_ERROR(error) ASSERT_NO_PNG_ERROR_MSG(error, std::string(""))

static const std::string BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";



//T and U can be std::string or std::vector<unsigned char>
template<typename T, typename U>
void toBase64(T& out, const U& in) {
  for(size_t i = 0; i < in.size(); i += 3) {
    int v = 65536 * in[i];
    if(i + 1 < in.size()) v += 256 * in[i + 1];
    if(i + 2 < in.size()) v += in[i + 2];
    out.push_back(BASE64[(v >> 18) & 0x3f]);
    out.push_back(BASE64[(v >> 12) & 0x3f]);
    if(i + 1 < in.size()) out.push_back(BASE64[(v >> 6) & 0x3f]);
    else out.push_back('=');
    if(i + 2 < in.size()) out.push_back(BASE64[(v >> 0) & 0x3f]);
    else out.push_back('=');
  }
}

int fromBase64(int v) {
  if(v >= 'A' && v <= 'Z') return (v - 'A');
  if(v >= 'a' && v <= 'z') return (v - 'a' + 26);
  if(v >= '0' && v <= '9') return (v - '0' + 52);
  if(v == '+') return 62;
  if(v == '/') return 63;
  return 0; //v == '='
}

//T and U can be std::string or std::vector<unsigned char>
template<typename T, typename U>
void fromBase64(T& out, const U& in) {
  for(size_t i = 0; i + 3 < in.size(); i += 4) {
    int v = 262144 * fromBase64(in[i]) + 4096 * fromBase64(in[i + 1]) + 64 * fromBase64(in[i + 2]) + fromBase64(in[i + 3]);
    out.push_back((v >> 16) & 0xff);
    if(in[i + 2] != '=') out.push_back((v >> 8) & 0xff);
    if(in[i + 3] != '=') out.push_back((v >> 0) & 0xff);
  }
}

unsigned getRandom() {
  static unsigned s = 1000000000;
  // xorshift32, good enough for testing
  s ^= (s << 13);
  s ^= (s >> 17);
  s ^= (s << 5);
  return s;
}

////////////////////////////////////////////////////////////////////////////////


unsigned leftrotate(unsigned x, unsigned c) {
  return (x << c) | (x >> (32u - c));
}

// the 128-bit result is output in 4 32-bit integers a0..d0 (to make 16-byte digest: append a0|b0|c0|d0 in little endian)
void md5sum(const unsigned char* in, size_t size, unsigned* a0, unsigned* b0, unsigned* c0, unsigned* d0) {
  ASSERT_EQUALS(4, sizeof(unsigned));
  // per-round shift amounts
  static const unsigned s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
  };
  // precomputed table from sines
  static const unsigned k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
  };

  *a0 = 0x67452301;
  *b0 = 0xefcdab89;
  *c0 = 0x98badcfe;
  *d0 = 0x10325476;

  // append bit, padding and size to input
  std::vector<unsigned char> data(in, in + size);
  data.resize(((size + 1 + 8 + 63) / 64) * 64, 0);
  data[size] = 128; // append 1 bit (msb)
  size_t bitsize = size * 8; // append the size (shifts > 31 are avoided)
  data[data.size() - 1] = ((bitsize >> 28u) >> 28u) & 255u;
  data[data.size() - 2] = ((bitsize >> 24u) >> 24u) & 255u;
  data[data.size() - 3] = ((bitsize >> 20u) >> 20u) & 255u;
  data[data.size() - 4] = ((bitsize >> 16u) >> 16u) & 255u;
  data[data.size() - 5] = (bitsize >> 24u) & 255u;
  data[data.size() - 6] = (bitsize >> 16u) & 255u;
  data[data.size() - 7] = (bitsize >> 8u) & 255u;
  data[data.size() - 8] = bitsize & 255u;

  // per chunk
  for(size_t i = 0; i < data.size(); i += 64) {
    unsigned a = *a0;
    unsigned b = *b0;
    unsigned c = *c0;
    unsigned d = *d0;

    for(size_t j = 0; j < 64; j++) {
      unsigned f, g;
      if(j <= 15u) {
        f = (b & c) | (~b & d);
        g = j;
      } else if(j <= 31u) {
        f = (d & b) | (~d & c);
        g = (5u * j + 1u) & 15u;
      } else if(j <= 47u) {
        f = b ^ c ^ d;
        g = (3u * j + 5u) & 15u;
      } else {
        f = c ^ (b | ~d);
        g = (7u * j) & 15u;
      }
      unsigned m = (unsigned)(data[i + g * 4 + 3] << 24u) | (unsigned)(data[i + g * 4 + 2] << 16u)
                 | (unsigned)(data[i + g * 4 + 1] << 8u) | (unsigned)data[i + g * 4];
      f += a + k[j] + m;
      a = d;
      d = c;
      c = b;
      b += leftrotate(f, s[j]);
    }
    *a0 += a;
    *b0 += b;
    *c0 += c;
    *d0 += d;
  }
}

std::string md5sum(const std::vector<unsigned char>& in) {
  unsigned a0, b0, c0, d0;
  md5sum(in.data(), in.size(), &a0, &b0, &c0, &d0);
  char result[33];
  //sprintf(result, "%8.8x%8.8x%8.8x%8.8x", a0, b0, c0, d0);
  sprintf(result, "%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x%2.2x",
          a0 & 255, (a0 >> 8) & 255, (a0 >> 16) & 255, (a0 >> 24) & 255,
          b0 & 255, (b0 >> 8) & 255, (b0 >> 16) & 255, (b0 >> 24) & 255,
          c0 & 255, (c0 >> 8) & 255, (c0 >> 16) & 255, (c0 >> 24) & 255,
          d0 & 255, (d0 >> 8) & 255, (d0 >> 16) & 255, (d0 >> 24) & 255);
  return std::string(result);
}

////////////////////////////////////////////////////////////////////////////////

//Test image data
struct Image {
  std::vector<unsigned char> data;
  unsigned width;
  unsigned height;
  LodePNGColorType colorType;
  unsigned bitDepth;
};

//Get number of color channels for a given PNG color type
unsigned getNumColorChannels(unsigned colorType) {
  switch(colorType) {
    case 0: return 1; /*gray*/
    case 2: return 3; /*RGB*/
    case 3: return 1; /*palette*/
    case 4: return 2; /*gray + alpha*/
    case 6: return 4; /*RGBA*/
  }
  return 0; /*unexisting color type*/
}

//Generate a test image with some data in it, the contents of the data is unspecified,
//except the content is not just one plain color, and not true random either to be compressible.
void generateTestImage(Image& image, unsigned width, unsigned height, LodePNGColorType colorType = LCT_RGBA, unsigned bitDepth = 8) {
  image.width = width;
  image.height = height;
  image.colorType = colorType;
  image.bitDepth = bitDepth;

  size_t bits = bitDepth * getNumColorChannels(colorType); //bits per pixel
  size_t size = (width * height * bits + 7) / 8; //total image size in bytes
  image.data.resize(size);
  unsigned char value = 128;
  for(size_t i = 0; i < size; i++) {
    image.data[i] = value++;
  }
}

//Generate a 16-bit test image with minimal size that requires at minimum the given color type (bit depth, grayscaleness, ...)
//If key is true, makes it such that exactly one color is transparent, so it can use a key. If false, adds a translucent color depending on
//whether it's an alpha color type or not.
void generateTestImageRequiringColorType16(Image& image, LodePNGColorType colorType, unsigned bitDepth, bool key) {
  image.colorType = colorType;
  image.bitDepth = bitDepth;
  unsigned w = 1;
  unsigned h = 1;

  bool gray = colorType == LCT_GREY || colorType == LCT_GREY_ALPHA;
  bool alpha = colorType == LCT_RGBA || colorType == LCT_GREY_ALPHA;

  if(colorType == LCT_PALETTE) {
    w = 1u << bitDepth;
    h = 256; // ensure it'll really choose palette, not omit it due to small image size
    image.data.resize(w * h * 8);
    for(size_t y = 0; y < h; y++) {
      for(size_t x = 0; x < w; x++) {
        size_t i = y * w * 8 + x * 8;
        image.data[i + 0] = image.data[i + 1] = y;
        image.data[i + 2] = image.data[i + 3] = 255;
        image.data[i + 4] = image.data[i + 5] = 0;
        image.data[i + 6] = image.data[i + 7] = (key && y == 0) ? 0 : 255;
      }
    }
  } else if(bitDepth == 16) {
    // one color suffices for this model. But add one more to support key.
    w = 2;
    image.data.resize(w * h * 8);
    image.data[0] = 10; image.data[1] = 20;
    image.data[2] = 10; image.data[3] = 20;
    image.data[4] = gray ? 10 : 110; image.data[5] = gray ? 20 : 120;
    image.data[6] = alpha ? 128 : 255; image.data[7] = alpha ? 20 : 255;

    image.data[8] = 40; image.data[9] = 50;
    image.data[10] = 40; image.data[11] = 50;
    image.data[12] = gray ? 40 : 140; image.data[13] = gray ? 50 : 150;
    image.data[14] = key ? 0 : 255; image.data[15] = key ? 0 : 255;
  } else if(gray) {
    w = 2;
    unsigned v = 255u / ((1u << bitDepth) - 1u); // value that forces at least this bitdepth
    image.data.resize(w * h * 8);
    image.data[0] = v; image.data[1] = v;
    image.data[2] = v; image.data[3] = v;
    image.data[4] = v; image.data[5] = v;
    image.data[6] = alpha ? v : 255; image.data[7] = alpha ? v : 255;

    image.data[8] = image.data[9] = 0;
    image.data[10] = image.data[11] = 0;
    image.data[12] = image.data[13] = 0;
    image.data[14] = image.data[15] = key ? 0 : 255;
  } else {
    // now it's RGB or RGBA with bitdepth 8
    w = 257; // must have at least more than 256 colors so it won't use palette
    image.data.resize(w * h * 8);
    for(size_t y = 0; y < h; y++) {
      for(size_t x = 0; x < w; x++) {
        size_t i = y * w * 8 + x * 8;
        image.data[i + 0] = image.data[i + 1] = i / 2;
        image.data[i + 2] = image.data[i + 3] = i / 3;
        image.data[i + 4] = image.data[i + 5] = i / 5;
        image.data[i + 6] = image.data[i + 7] = (key && y == 0) ? 0 : (alpha ? i : 255);
      }
    }
  }

  image.width = w;
  image.height = h;
}

//Generate a 8-bit test image with minimal size that requires at minimum the given color type (bit depth, grayscaleness, ...). bitDepth max 8 here.
//If key is true, makes it such that exactly one color is transparent, so it can use a key. If false, adds a translucent color depending on
//whether it's an alpha color type or not.
void generateTestImageRequiringColorType8(Image& image, LodePNGColorType colorType, unsigned bitDepth, bool key) {
  image.colorType = colorType;
  image.bitDepth = bitDepth;
  unsigned w = 1;
  unsigned h = 1;

  bool gray = colorType == LCT_GREY || colorType == LCT_GREY_ALPHA;
  bool alpha = colorType == LCT_RGBA || colorType == LCT_GREY_ALPHA;

  if(colorType == LCT_PALETTE) {
    w = 1u << bitDepth;
    h = 256; // ensure it'll really choose palette, not omit it due to small image size
    image.data.resize(w * h * 4);
    for(size_t y = 0; y < h; y++) {
      for(size_t x = 0; x < w; x++) {
        size_t i = y * w * 4 + x * 4;
        image.data[i + 0] = x;
        image.data[i + 1] = 255;
        image.data[i + 2] = 0;
        image.data[i + 3] = (key && x == 0) ? 0 : 255;
      }
    }
  } else if(gray) {
    w = 2;
    unsigned v = 255u / ((1u << bitDepth) - 1u); // value that forces at least this bitdepth
    image.data.resize(w * h * 4);
    image.data[0] = v;
    image.data[1] = v;
    image.data[2] = v;
    image.data[3] = alpha ? v : 255;

    image.data[4] = 0;
    image.data[5] = 0;
    image.data[6] = 0;
    image.data[7] = key ? 0 : 255;
  } else {
    // now it's RGB or RGBA with bitdepth 8
    w = 257; // must have at least more than 256 colors so it won't use palette
    image.data.resize(w * h * 4);
    for(size_t y = 0; y < h; y++) {
      for(size_t x = 0; x < w; x++) {
        size_t i = y * w * 4 + x * 4;
        image.data[i + 0] = i / 2;
        image.data[i + 1] = i / 3;
        image.data[i + 2] = i / 5;
        image.data[i + 3] = (key && x == 0) ? 0 : (alpha ? i : 255);
      }
    }
  }

  image.width = w;
  image.height = h;
}

//Check that the decoded PNG pixels are the same as the pixels in the image
void assertPixels(Image& image, const unsigned char* decoded, const std::string& message) {
  for(size_t i = 0; i < image.data.size(); i++) {
    int byte_expected = image.data[i];
    int byte_actual = decoded[i];

    //last byte is special due to possible random padding bits which need not to be equal
    if(i == image.data.size() - 1) {
      size_t numbits = getNumColorChannels(image.colorType) * image.bitDepth * image.width * image.height;
      size_t padding = 8u - (numbits - 8u * (numbits / 8u));
      if(padding != 8u) {
        //set all padding bits of both to 0
        for(size_t j = 0; j < padding; j++) {
          byte_expected = (byte_expected & (~(1 << j))) % 256;
          byte_actual = (byte_actual & (~(1 << j))) % 256;
        }
      }
    }

    assertEquals(byte_expected, byte_actual, message + " " + valtostr(i));
  }
}

//Test LodePNG encoding and decoding the encoded result, using the C interface
void doCodecTestC(Image& image) {
  unsigned char* encoded = 0;
  size_t encoded_size = 0;
  unsigned char* decoded = 0;
  unsigned decoded_w;
  unsigned decoded_h;

  struct OnExitScope {
    unsigned char** a;
    unsigned char** b;
    OnExitScope(unsigned char** ca, unsigned char** cb) : a(ca), b(cb) {}
    ~OnExitScope() { free(*a); free(*b); }
  } onExitScope(&encoded, &decoded);

  unsigned error_enc = lodepng_encode_memory(&encoded, &encoded_size, &image.data[0],
                                             image.width, image.height, image.colorType, image.bitDepth);

  if(error_enc != 0) std::cout << "Error: " << lodepng_error_text(error_enc) << std::endl;
  ASSERT_NO_PNG_ERROR_MSG(error_enc, "encoder error C");

  //if the image is large enough, compressing it should result in smaller size
  if(image.data.size() > 512) assertTrue(encoded_size < image.data.size(), "compressed size");

  unsigned error_dec = lodepng_decode_memory(&decoded, &decoded_w, &decoded_h,
                                             encoded, encoded_size, image.colorType, image.bitDepth);

  if(error_dec != 0) std::cout << "Error: " << lodepng_error_text(error_dec) << std::endl;
  ASSERT_NO_PNG_ERROR_MSG(error_dec, "decoder error C");

  ASSERT_EQUALS(image.width, decoded_w);
  ASSERT_EQUALS(image.height, decoded_h);
  assertPixels(image, decoded, "Pixels C");
}

//Test LodePNG encoding and decoding the encoded result, using the C++ interface
void doCodecTestCPP(Image& image) {
  std::vector<unsigned char> encoded;
  std::vector<unsigned char> decoded;
  unsigned decoded_w;
  unsigned decoded_h;

  unsigned error_enc = lodepng::encode(encoded, image.data, image.width, image.height,
                                       image.colorType, image.bitDepth);

  ASSERT_NO_PNG_ERROR_MSG(error_enc, "encoder error C++");

  //if the image is large enough, compressing it should result in smaller size
  if(image.data.size() > 512) assertTrue(encoded.size() < image.data.size(), "compressed size");

  unsigned error_dec = lodepng::decode(decoded, decoded_w, decoded_h, encoded, image.colorType, image.bitDepth);

  ASSERT_NO_PNG_ERROR_MSG(error_dec, "decoder error C++");

  ASSERT_EQUALS(image.width, decoded_w);
  ASSERT_EQUALS(image.height, decoded_h);
  ASSERT_EQUALS(image.data.size(), decoded.size());
  assertPixels(image, &decoded[0], "Pixels C++");
}


void doCodecTestWithEncState(Image& image, lodepng::State& state) {
  std::vector<unsigned char> encoded;
  std::vector<unsigned char> decoded;
  unsigned decoded_w;
  unsigned decoded_h;
  state.info_raw.colortype = image.colorType;
  state.info_raw.bitdepth = image.bitDepth;


  unsigned error_enc = lodepng::encode(encoded, image.data, image.width, image.height, state);
  ASSERT_NO_PNG_ERROR_MSG(error_enc, "encoder error uncompressed");

  unsigned error_dec = lodepng::decode(decoded, decoded_w, decoded_h, encoded, image.colorType, image.bitDepth);

  ASSERT_NO_PNG_ERROR_MSG(error_dec, "decoder error uncompressed");

  ASSERT_EQUALS(image.width, decoded_w);
  ASSERT_EQUALS(image.height, decoded_h);
  ASSERT_EQUALS(image.data.size(), decoded.size());
  assertPixels(image, &decoded[0], "Pixels uncompressed");
}


//Test LodePNG encoding and decoding the encoded result, using the C++ interface
void doCodecTestUncompressed(Image& image) {
  lodepng::State state;
  state.encoder.zlibsettings.btype = 0;
  doCodecTestWithEncState(image, state);
}

void doCodecTestNoLZ77(Image& image) {
  lodepng::State state;
  state.encoder.zlibsettings.use_lz77 = 0;
  doCodecTestWithEncState(image, state);
}

//Test LodePNG encoding and decoding the encoded result, using the C++ interface, with interlace
void doCodecTestInterlaced(Image& image) {
  std::vector<unsigned char> encoded;
  std::vector<unsigned char> decoded;
  unsigned decoded_w;
  unsigned decoded_h;

  lodepng::State state;
  state.info_png.interlace_method = 1;
  state.info_raw.colortype = image.colorType;
  state.info_raw.bitdepth = image.bitDepth;

  unsigned error_enc = lodepng::encode(encoded, image.data, image.width, image.height, state);

  ASSERT_NO_PNG_ERROR_MSG(error_enc, "encoder error interlaced");

  //if the image is large enough, compressing it should result in smaller size
  if(image.data.size() > 512) assertTrue(encoded.size() < image.data.size(), "compressed size");

  state.info_raw.colortype = image.colorType;
  state.info_raw.bitdepth = image.bitDepth;
  unsigned error_dec = lodepng::decode(decoded, decoded_w, decoded_h, state, encoded);

  ASSERT_NO_PNG_ERROR_MSG(error_dec, "decoder error interlaced");

  ASSERT_EQUALS(image.width, decoded_w);
  ASSERT_EQUALS(image.height, decoded_h);
  ASSERT_EQUALS(image.data.size(), decoded.size());
  assertPixels(image, &decoded[0], "Pixels interlaced");
}

//Test LodePNG encoding and decoding the encoded result
void doCodecTest(Image& image) {
  doCodecTestC(image);
  doCodecTestCPP(image);
  doCodecTestInterlaced(image);
  doCodecTestUncompressed(image);
  doCodecTestNoLZ77(image);
}


//Test LodePNG encoding and decoding using some image generated with the given parameters
void codecTest(unsigned width, unsigned height, LodePNGColorType colorType = LCT_RGBA, unsigned bitDepth = 8) {
  std::cout << "codec test " << width << " " << height << std::endl;
  Image image;
  generateTestImage(image, width, height, colorType, bitDepth);
  doCodecTest(image);
}

std::string removeSpaces(const std::string& s) {
  std::string result;
  for(size_t i = 0; i < s.size(); i++) if(s[i] != ' ') result += s[i];
  return result;
}

void bitStringToBytes(std::vector<unsigned char>& bytes, const std::string& bits_) {
  std::string bits = removeSpaces(bits_);
  bytes.resize((bits.size()) + 7 / 8);
  for(size_t i = 0; i < bits.size(); i++) {
    size_t j = i / 8;
    size_t k = i % 8;
    char c = bits[i];
    if(k == 0) bytes[j] = 0;
    if(c == '1') bytes[j] |= (1 << (7 - k));
  }
}

/*
test color convert on a single pixel. Testing palette and testing color keys is
not supported by this function. Pixel values given using bits in an std::string
of 0's and 1's.
*/
void colorConvertTest(const std::string& bits_in, LodePNGColorType colorType_in, unsigned bitDepth_in,
                      const std::string& bits_out, LodePNGColorType colorType_out, unsigned bitDepth_out) {
  std::cout << "color convert test " << bits_in << " - " << bits_out << std::endl;

  std::vector<unsigned char> expected, actual, image;
  bitStringToBytes(expected, bits_out);
  actual.resize(expected.size());
  bitStringToBytes(image, bits_in);
  LodePNGColorMode mode_in, mode_out;
  lodepng_color_mode_init(&mode_in);
  lodepng_color_mode_init(&mode_out);
  mode_in.colortype = colorType_in;
  mode_in.bitdepth = bitDepth_in;
  mode_out.colortype = colorType_out;
  mode_out.bitdepth = bitDepth_out;
  unsigned error = lodepng_convert(&actual[0], &image[0], &mode_out, &mode_in, 1, 1);

  ASSERT_NO_PNG_ERROR_MSG(error, "convert error");

  for(size_t i = 0; i < expected.size(); i++) {
    assertEquals((int)expected[i], (int)actual[i], "byte " + valtostr(i));
  }

  lodepng_color_mode_cleanup(&mode_in);
  lodepng_color_mode_cleanup(&mode_out);
}

void testOtherPattern1() {
  std::cout << "codec other pattern 1" << std::endl;

  Image image1;
  size_t w = 192;
  size_t h = 192;
  image1.width = w;
  image1.height = h;
  image1.colorType = LCT_RGBA;
  image1.bitDepth = 8;
  image1.data.resize(w * h * 4u);
  for(size_t y = 0; y < h; y++)
  for(size_t x = 0; x < w; x++) {
    //pattern 1
    image1.data[4u * w * y + 4u * x + 0u] = (unsigned char)(127 * (1 + std::sin((                    x * x +                     y * y) / (w * h / 8.0))));
    image1.data[4u * w * y + 4u * x + 1u] = (unsigned char)(127 * (1 + std::sin(((w - x - 1) * (w - x - 1) +                     y * y) / (w * h / 8.0))));
    image1.data[4u * w * y + 4u * x + 2u] = (unsigned char)(127 * (1 + std::sin((                    x * x + (h - y - 1) * (h - y - 1)) / (w * h / 8.0))));
    image1.data[4u * w * y + 4u * x + 3u] = (unsigned char)(127 * (1 + std::sin(((w - x - 1) * (w - x - 1) + (h - y - 1) * (h - y - 1)) / (w * h / 8.0))));
  }

  doCodecTest(image1);
}

void testOtherPattern2() {
  std::cout << "codec other pattern 2" << std::endl;

  Image image1;
  size_t w = 192;
  size_t h = 192;
  image1.width = w;
  image1.height = h;
  image1.colorType = LCT_RGBA;
  image1.bitDepth = 8;
  image1.data.resize(w * h * 4u);
  for(size_t y = 0; y < h; y++)
  for(size_t x = 0; x < w; x++) {
    image1.data[4u * w * y + 4u * x + 0u] = 255 * !(x & y);
    image1.data[4u * w * y + 4u * x + 1u] = x ^ y;
    image1.data[4u * w * y + 4u * x + 2u] = x | y;
    image1.data[4u * w * y + 4u * x + 3u] = 255;
  }

  doCodecTest(image1);
}

void testSinglePixel(int r, int g, int b, int a) {
  std::cout << "codec single pixel " << r << " " << g << " " << b << " " << a << std::endl;
  Image pixel;
  pixel.width = 1;
  pixel.height = 1;
  pixel.colorType = LCT_RGBA;
  pixel.bitDepth = 8;
  pixel.data.resize(4);
  pixel.data[0] = r;
  pixel.data[1] = g;
  pixel.data[2] = b;
  pixel.data[3] = a;

  doCodecTest(pixel);
}

void testColor(int r, int g, int b, int a) {
  std::cout << "codec test color " << r << " " << g << " " << b << " " << a << std::endl;
  Image image;
  image.width = 20;
  image.height = 20;
  image.colorType = LCT_RGBA;
  image.bitDepth = 8;
  image.data.resize(20 * 20 * 4);
  for(size_t y = 0; y < 20; y++)
  for(size_t x = 0; x < 20; x++) {
    image.data[20 * 4 * y + 4 * x + 0] = r;
    image.data[20 * 4 * y + 4 * x + 0] = g;
    image.data[20 * 4 * y + 4 * x + 0] = b;
    image.data[20 * 4 * y + 4 * x + 0] = a;
  }

  doCodecTest(image);

  Image image2 = image;
  image2.data[3] = 0; //one fully transparent pixel
  doCodecTest(image2);
  image2.data[3] = 128; //one semi transparent pixel
  doCodecTest(image2);

  Image image3 = image;
  // add 255 different colors
  for(size_t i = 0; i < 255; i++) {
    image.data[i * 4 + 0] = i;
    image.data[i * 4 + 1] = i;
    image.data[i * 4 + 2] = i;
    image.data[i * 4 + 3] = 255;
  }
  doCodecTest(image3);
  // a 256th color
  image.data[255 * 4 + 0] = 255;
  image.data[255 * 4 + 1] = 255;
  image.data[255 * 4 + 2] = 255;
  image.data[255 * 4 + 3] = 255;
  doCodecTest(image3);

  testSinglePixel(r, g, b, a);
}

// Tests combinations of various colors in different orders
void testFewColors() {
  std::cout << "codec test few colors " << std::endl;
  Image image;
  image.width = 4;
  image.height = 4;
  image.colorType = LCT_RGBA;
  image.bitDepth = 8;
  image.data.resize(image.width * image.height * 4);
  std::vector<unsigned char> colors;
  colors.push_back(0); colors.push_back(0); colors.push_back(0); colors.push_back(255); // black
  colors.push_back(255); colors.push_back(255); colors.push_back(255); colors.push_back(255); // white
  colors.push_back(128); colors.push_back(128); colors.push_back(128); colors.push_back(255); // gray
  colors.push_back(0); colors.push_back(0); colors.push_back(255); colors.push_back(255); // blue
  colors.push_back(255); colors.push_back(255); colors.push_back(255); colors.push_back(0); // transparent white
  colors.push_back(255); colors.push_back(255); colors.push_back(255); colors.push_back(1); // translucent white
  for(size_t i = 0; i < colors.size(); i += 4)
  for(size_t j = 0; j < colors.size(); j += 4)
  for(size_t k = 0; k < colors.size(); k += 4)
  for(size_t l = 0; l < colors.size(); l += 4) {
    for(unsigned y = 0; y < image.height; y++)
    for(unsigned x = 0; x < image.width; x++) {
      size_t a = (y * image.width + x) & 3;
      size_t b = (a == 0) ? i : ((a == 1) ? j : ((a == 2) ? k : l));
      for(size_t c = 0; c < 4; c++) {
        image.data[y * image.width * 4 + x * 4 + c] = colors[b + c];
      }
    }
    doCodecTest(image);
  }
  image.width = 20;
  image.height = 20;
  image.data.resize(image.width * image.height * 4);
  for(size_t i = 0; i < colors.size(); i += 4)
  for(size_t j = 0; j < colors.size(); j += 4)
  for(size_t k = 0; k < colors.size(); k += 4) {
    for(unsigned y = 0; y < image.height; y++)
    for(unsigned x = 0; x < image.width; x++) {
      size_t a = (y * image.width + x) % 3;
      size_t b = (a == 0) ? i : ((a == 1) ? j : k);
      for(size_t c = 0; c < 4; c++) {
        image.data[y * image.width * 4 + x * 4 + c] = colors[b + c];
      }
    }
    doCodecTest(image);
  }
}

void testSize(unsigned w, unsigned h) {
  std::cout << "codec test size " << w << " " << h << std::endl;
  Image image;
  image.width = w;
  image.height = h;
  image.colorType = LCT_RGBA;
  image.bitDepth = 8;
  image.data.resize(w * h * 4);
  for(size_t y = 0; y < h; y++)
  for(size_t x = 0; x < w; x++) {
    image.data[w * 4 * y + 4 * x + 0] = x % 256;
    image.data[w * 4 * y + 4 * x + 0] = y % 256;
    image.data[w * 4 * y + 4 * x + 0] = 255;
    image.data[w * 4 * y + 4 * x + 0] = 255;
  }

  doCodecTest(image);
}

void testPNGCodec() {
  codecTest(1, 1);
  codecTest(2, 2);
  codecTest(1, 1, LCT_GREY, 1);
  codecTest(7, 7, LCT_GREY, 1);
#ifndef DISABLE_SLOW
  codecTest(127, 127);
  codecTest(127, 127, LCT_GREY, 1);
  codecTest(320, 320);
  codecTest(1, 10000);
  codecTest(10000, 1);

  testOtherPattern1();
  testOtherPattern2();
#endif // DISABLE_SLOW

  testColor(255, 255, 255, 255);
  testColor(0, 0, 0, 255);
  testColor(1, 2, 3, 255);
  testColor(255, 0, 0, 255);
  testColor(0, 255, 0, 255);
  testColor(0, 0, 255, 255);
  testColor(0, 0, 0, 255);
  testColor(1, 1, 1, 255);
  testColor(1, 1, 1, 1);
  testColor(0, 0, 0, 128);
  testColor(255, 0, 0, 128);
  testColor(127, 127, 127, 255);
  testColor(128, 128, 128, 255);
  testColor(127, 127, 127, 128);
  testColor(128, 128, 128, 128);
  //transparent single pixels
  testColor(0, 0, 0, 0);
  testColor(255, 0, 0, 0);
  testColor(1, 2, 3, 0);
  testColor(255, 255, 255, 0);
  testColor(254, 254, 254, 0);

  // This is mainly to test the Adam7 interlacing
  for(unsigned h = 1; h < 12; h++)
  for(unsigned w = 1; w < 12; w++) {
    testSize(w, h);
  }
}
