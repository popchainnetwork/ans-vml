#include <stdio.h>
#include <string.h>
#include "params.h"
#include "xmss_core.h"
#include "xmss.h"
static void hexout(const char*name,const unsigned char*b,unsigned long long n){printf("%s ",name);for(unsigned long long i=0;i<n;i++)printf("%02x",b[i]);printf("\n");}
int main(){
  xmss_params p; uint32_t oid; xmssmt_str_to_oid(&oid,"XMSSMT-SHA2_20/2_256"); xmssmt_parse_oid(&p,oid);
  unsigned char seed[96]; for(int i=0;i<96;i++)seed[i]=i;
  unsigned char pk[64+4], sk[4+2000]; unsigned char m[1]={0x25};
  xmssmt_core_seed_keypair(&p,pk,sk,seed);
  hexout("pk",pk,p.pk_bytes);
  unsigned long long idxs[3]={0,1029,1048574};
  for(int k=0;k<3;k++){
    unsigned long long ix=idxs[k];
    for(unsigned j=0;j<p.index_bytes;j++) sk[j]=(ix>>(8*(p.index_bytes-1-j)))&0xff;
    unsigned char sm[10000]; unsigned long long smlen;
    xmssmt_core_sign(&p,sk,sm,&smlen,m,1);
    char nm[32]; sprintf(nm,"sig_%llu",ix); hexout(nm,sm,smlen-1);
    unsigned char mo[10000]; unsigned long long mlen;
    if(xmssmt_core_sign_open(&p,mo,&mlen,sm,smlen,pk)) {printf("VERIFY FAIL\n");return 1;}
  }
  printf("sig_bytes %u index_bytes %u\n",p.sig_bytes,p.index_bytes);
  return 0;
}
