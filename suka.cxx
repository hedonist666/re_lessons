#include <fstream>
#include <iostream>

using namespace std;

int main(int argc, char ** argv){	
	
	if( argc < 2) {
		cerr << " dai file suka";
		return 0;
	}
	fstream f;
	f.open( argv[1] );
	if (!f.is_open())
	{
		cerr << "otsosi";
		f.close();
		return 0;
	}
	f.seekg(0, ios_base::end);
	int size = f.tellg();
	if (size == -1)
	{
		cerr << " sosi";
		f.close();
		return 0;

	}
	char * new_char_size = new char[size];
	f.seekg(0, ios_base::beg);
	f.read(new_char_size, size);
	f.close();
	cout.write(new_char_size, size);
	
}
