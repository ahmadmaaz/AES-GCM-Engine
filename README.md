
# Parallelizing AES-256 GCM 

How to compile

```
   g++ -fopenmp -std=c++14 -O0 -maes -msse4.1 -mpclmul -msse2 AES.cpp Ghash.cpp Utils.cpp GCM.cpp -o AES_Paralelized
```