#include <stdio.h>
#include <string.h>
int main(int c,char**v){
 if(c<2){puts("NorthPier Diagnostic Utility");puts("usage: quietdiag <mode>");return 0;}
 if(!strcmp(v[1],"--status")){puts("status: nominal");return 0;}
 if(!strcmp(v[1],"--recover")){
  if(c<3)return 2;
  for(int i=0;v[2][i]&&v[2][i+1];i+=2){unsigned x=0;sscanf(v[2]+i,"%2x",&x);putchar((char)(x^0x2a));}
  putchar('\n');return 0;
 }
 puts("unknown mode");return 1;
}