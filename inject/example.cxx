#include "pe.h"
#include <iostream>
#include <fstream>

using namespace std;


int main() {
    ifstream ifn("ch17.exe");
    IMAGE_DOS_HEADER idh;
    IMAGE_NT_HEADERS32 nt   cout << "SIZES (dos header, nt headers): " 
         << sizeof(idh) << ", " << sizeof(nt) << endl;
    char data[sizeof(nt)];
    ifn.read(data, sizeof(idh));
    idh = *(IMAGE_DOS_HEADER*)data;
    cout << "MAGIC: " << (char*)&idh.e_magic << ' ' << idh.e_lfanew << endl;
    ifn.seekg(idh.e_lfanew, ios_base::beg);
    ifn.read(data, sizeof(nt));
    nt = *(IMAGE_NT_HEADERS32*)data;
    cout << "MAGIC: " << (char*)&nt.Signature << endl;
    cout << "Number of Sections: " << nt.FileHeader.NumberOfSections << endl;
    cout << hex;
    auto& dirs = nt.OptionalHeader.DataDirectory;
    for (int i = 0; i < 14; ++i) {
        cout << i << ": " << dirs[i].VirtualAddress << ' ' << dirs[i].Size << endl;
    }
    auto& exdir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    cout << "Exception handler? "
         << hex << exdir.VirtualAddress << ' ' << exdir.Size;
}
