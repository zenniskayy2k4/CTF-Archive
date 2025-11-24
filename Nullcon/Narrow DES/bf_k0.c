#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#ifdef _OPENMP
#include <omp.h>
#endif

#define LB24 ((1u<<24)-1)

static const unsigned char Ptbl[24] = {
  8,18,3,2,15,24,10,14,20,7,5,13,1,6,21,9,4,11,23,22,12,19,16,17
};
static const unsigned char Sbox[8][16] = {{
  5,3,0,2,7,1,4,6,1,6,4,7,5,0,3,2},{
  4,1,0,5,3,7,6,2,1,4,0,5,2,6,3,7},{
  3,4,2,0,7,6,1,5,3,7,6,0,4,2,1,5},{
  5,6,4,2,7,0,3,1,6,5,7,2,1,3,4,0},{
  5,6,7,3,1,0,4,2,3,6,2,1,7,4,0,5},{
  0,3,1,4,6,5,2,7,0,3,5,4,7,6,1,2},{
  6,0,4,2,3,5,1,7,0,6,7,3,2,1,4,5},{
  0,5,6,2,3,7,4,1,2,4,0,7,3,1,5,6}
};

static inline uint32_t F(uint32_t r24, uint32_t k32){
    uint32_t expanded=0, s_output=0, p_output=0;
    for(int j=0;j<7;j++){
        expanded |= ((r24 >> (20 - 3*j)) & 0xF) << (28 - 4*j);
    }
    expanded |= (r24 & 7) << 1 | (r24 >> 23);
    expanded ^= k32;
    for(int j=0;j<8;j++){
        uint32_t t = (expanded >> (4*j)) & 0xF;
        s_output = (s_output << 3) | Sbox[j][t];
    }
    for(int j=0;j<24;j++){
        p_output = (p_output << 1) | ((s_output >> (24 - Ptbl[j])) & 1);
    }
    return p_output;
}

static inline uint64_t enc48(uint64_t msg48, uint32_t k0, uint32_t k1){
    uint32_t L = (msg48 >> 24) & LB24;
    uint32_t R = msg48 & LB24;
    for(int i=0;i<32;i++){
        uint32_t sub = (i%2==0)? k0 : k1;
        uint32_t fout = F(R, sub);
        uint32_t t = R;
        R = L ^ fout;
        L = t;
    }
    return (((uint64_t)L)<<24) | R;
}

int main(int argc, char** argv){
    if(argc<2){ fprintf(stderr,"Usage: %s k1_and_pairs.txt\n", argv[0]); return 1; }
    // Read k1 and up to 4 pairs
    FILE* f = fopen(argv[1],"r"); if(!f){perror("open"); return 1;}
    uint32_t k1=0; uint64_t P[4]={0}, C[4]={0}; int n=0;
    char line[256];
    while(fgets(line,sizeof(line),f)){
        if(sscanf(line,"k1=0x%x",&k1)==1) continue;
        unsigned long long p,c;
        if(sscanf(line,"P=%llx C=%llx",&p,&c)==2){
            P[n]=p; C[n]=c; n++;
            if(n==4) break;
        }
    }
    fclose(f);
    if(k1==0 || n==0){ fprintf(stderr,"Need k1 and at least one pair.\n"); return 1; }
    printf("[+] k1 = 0x%08x, testing %d pairs\n", k1, n);

    volatile int found = 0;
    uint32_t found_k0 = 0;

    #pragma omp parallel for schedule(dynamic) ifndef(_OPENMP)
    for (uint64_t k0 = 0; k0 < (1ULL<<32); k0++){
        if(found) continue;
        uint32_t k0_32 = (uint32_t)k0;
        // quick reject using first pair
        if(enc48(P[0], k0_32, k1) != C[0]) continue;
        int ok = 1;
        for(int i=1;i<n;i++){
            if(enc48(P[i], k0_32, k1) != C[i]) { ok = 0; break; }
        }
        if(ok){
            found_k0 = k0_32;
            found = 1;
            #ifdef _OPENMP
            #pragma omp flush(found)
            #endif
        }
        if(found) continue;
    }

    if(!found){
        printf("[-] k0 not found. Try more (P,C) pairs.\n");
        return 1;
    }
    printf("[+] k0 = 0x%08x\n", found_k0);

    // In ra flag
    unsigned long long fullkey = (((unsigned long long)found_k0)<<32) | k1;
    printf("FLAG: ENO{%016llx}\n", fullkey);
    return 0;
}
