#include<stdio.h>
int function(int a, int b)
{
    return a + b;
}
int function2(int a, int b){
    return a + function(a, b);
}