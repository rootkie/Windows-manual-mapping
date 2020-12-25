#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "manualMap.h"

UINT64 getFileSize(const char* path) {
	FILE* fp;
	fopen_s(&fp, path, "rb");
	if (!fp) {
		puts("File opening failed");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	UINT64 fSize = ftell(fp);

	fclose(fp);
	return fSize;
}

UINT64 loadFile(const char* path, BYTE* buf) {
	FILE* fp;
	fopen_s(&fp, path, "rb");
	if (!fp) {
		puts("File opening failed");
		return 0;
	}

	fseek(fp, 0, SEEK_END);
	UINT64 fSize = ftell(fp);
	rewind(fp);

	UINT64 result = fread(buf, 1, fSize, fp);

	if (result != fSize) {
		puts("Reading error");
		return 0;
	}

	fclose(fp);
	return result;
}

int main(int argc, const char** argv) {
	puts("hello world");


	auto fileSize = getFileSize(argv[1]);
	BYTE* DllFile = static_cast<BYTE*>(malloc(fileSize));
	if (!loadFile(argv[1], DllFile)) {
		puts("failed to read file");
		free(DllFile);
		return 1;
	}
	ManualMap(DllFile, fileSize);
	free(DllFile);
	return 0;
}