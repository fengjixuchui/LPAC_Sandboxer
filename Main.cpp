#include <windows.h>
#include <stdio.h>
#include "Sandboxer.h"

int main(int argc, char *argv[])
{
	printf("Sandboxer with Windows LPAC\n");
	printf("Usage: lpac.exe <path to your file>\n");

	if(argc == 2)
    		Sandboxed(argv[1]);

	system("pause");

  return 0;
}
