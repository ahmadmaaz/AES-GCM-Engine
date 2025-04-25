
# Parallelizing AES-256 GCM 

How to compile

```
 g++ -fopenmp -std=c++14 -Ofast -funroll-loops -flto -march=native  -maes -mpclmul -msse4.1 -msse2 AES.cpp Ghash.cpp Utils.cpp GCM.cpp -o AES_Parallelized
```