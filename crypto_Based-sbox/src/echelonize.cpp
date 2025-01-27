#include <iostream>
#include <fstream>
#include <string>

#include <NTL/GF2E.h>
#include <NTL/GF2X.h>
#include <NTL/mat_GF2E.h>

#define ull unsigned long long
#define uchar unsigned char

using namespace std;
using namespace NTL;


void init_GF2E() {
    GF2X f;
    SetCoeff(f, 64);
    for (ull i = 0, m = 0x1b; i < 64 && m; i++, m >>= 1) {
        SetCoeff(f, i, m & 1);
    }
    GF2E::init(f);  // x^64 + x^4 + x^3 + x + 1
}

GF2E GF2EFromBytes(uchar c[8]) {
    GF2X tmp = GF2XFromBytes(c, 8);
    return conv<GF2E>(tmp);
}

void BytesFromGF2E(uchar c[8], const GF2E& e) {
    GF2X tmp = rep(e);
    BytesFromGF2X(c, tmp, 8);
}

mat_GF2E read_matrix(const string& filename) {
    mat_GF2E M;

    ifstream f(filename, ios::binary);
    if (f.is_open()) {
        ull rows, cols;
        f.read(reinterpret_cast<char*>(&rows), sizeof(rows));
        f.read(reinterpret_cast<char*>(&cols), sizeof(cols));

        M.SetDims(rows, cols);

        for (ull i = 0; i < rows; i++) {
            for (ull j = 0; j < cols; j++) {
                uchar c[8];
                f.read(reinterpret_cast<char*>(c), 8);
                M[i][j] = GF2EFromBytes(c);
            }
        }
        f.close();
    } else {
        cerr << "Failed to open '" << filename << "'.\n";
        exit(1);
    }

    return M;
}

void write_matrix(const mat_GF2E& M, const string& filename) {
    ofstream f(filename, ios::binary);
    if (f.is_open()) {
        ull rows = M.NumRows();
        ull cols = M.NumCols();
        f.write(reinterpret_cast<const char*>(&rows), sizeof(rows));
        f.write(reinterpret_cast<const char*>(&cols), sizeof(cols));

        for (ull i = 0; i < rows; i++) {
            for (ull j = 0; j < cols; j++) {
                uchar c[8];
                BytesFromGF2E(c, M[i][j]);
                f.write(reinterpret_cast<const char*>(c), 8);
            }
        }
        f.close();
    } else {
        cerr << "Failed to open '" << filename << "'.\n";
        exit(1);
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <filename>\n";
        return 1;
    }

    string filename = argv[1];
    init_GF2E();  // Initialize the finite field

    // Read the matrix from the file
    mat_GF2E M = read_matrix(filename);

    // clock_t start = clock();
    gauss(M);  // Echelonize the matrix
    // cout << "Elapsed time: " << (double)(clock() - start) / CLOCKS_PER_SEC << "s\n";

    // Write the echelonized matrix to the file
    write_matrix(M, filename);

    return 0;
}
