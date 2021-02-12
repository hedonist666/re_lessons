#include "pe.h"
#include <iostream>
#include <stdio.h>
#include <sys/mman.h>
#include <fstream>
#include <sys/stat.h>
#include <cstring>

using namespace std;

void volatile shellcode(){

#define _BUFFER_SIZE 57
const uint8_t buffer[_BUFFER_SIZE] = {
0x66, 0x60, 0xe8, 0x00, 0x00, 0x66, 0x5d, 0x66, 0x83, 0xed,
0x05, 0x6a, 0x10, 0x67, 0x66, 0x8d, 0x45, 0x30, 0x66, 0x50,
0x67, 0x66, 0x8d, 0x45, 0x26, 0x66, 0x50, 0x6a, 0x00, 0x66,
0x61, 0x66, 0xb8, 0xaa, 0xaa, 0xaa, 0xaa, 0xc3, 0x53, 0x6f,
0x73, 0x69, 0x74, 0x65, 0x68, 0x75, 0x69, 0x00, 0x70, 0x69,
0x64, 0x61, 0x72, 0x61, 0x7a, 0x79, 0x00
};

    ((void (*)(void))buffer)();
};

struct MappedFile{
    FILE* f;
    int fd;
    struct stat st;
    char* mem;
    MappedFile(const char* fn) {
            f = fopen(fn, "r");
            fd = fileno(f);
            fstat(fd, &st);
            mem = (char*)mmap(NULL, st.st_size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE, fd, 0);
    }
    // vera v distructor
    ~MappedFile() {
        munmap(mem, st.st_size);
        fclose(f);
    }
};

struct PEParser{
	char* mem;
	IMAGE_DOS_HEADER* idh;
	IMAGE_NT_HEADERS32* nt;
	IMAGE_FILE_HEADER* fh;
	IMAGE_OPTIONAL_HEADER* oh;
	PEParser(char* mem) : mem(mem){
		idh = (decltype(idh)) mem;
		nt = (decltype(nt)) (mem + idh->e_lfanew);
		fh = (decltype(fh)) (&nt->FileHeader);
		oh = (decltype(oh)) (&nt->OptionalHeader);
    	}	
	void mzk(){
	if ( idh->e_magic == 0x5a4d)
		cout << " ts'enitel nahui idi" << endl;
	if ( nt->Signature == 0x4550 )
		cout << " ebat ti executable" << endl;
	}
	

};

void step one indetify the target(){
	cout<<" and its flos, they'r always flos" << endl;
}
void step two build malware(){
	cout << "and start attack" << endl;
void step three build malware(){
	cout << "and start attack" << endl;
}
int main() {
	MappedFile mz("firhex.exe");
 	PEParser pe(mz.mem);
	pe.mzk();	
}
