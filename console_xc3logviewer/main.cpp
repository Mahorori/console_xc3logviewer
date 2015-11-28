#include "stdafx.h"

#include "xc3.h"
#include <time.h>
#include <Windows.h>

#include "rijndael.h"

bool decrypt(int bufsize, char *buf, const unsigned char *key)
{
	int keysize = 16;
	rijndael_key rijndael;
	unsigned char *buf_temp = (unsigned char*)buf;

	if (rijndael_keysize(&keysize))
		return false;

	if (rijndael_setup(key, keysize, 0, &rijndael))
		return false;

	int a = bufsize / 16;

	if (a > 0)
	{
		for (int i = 0; i < a; i++)
		{
			if (rijndael_ecb_decrypt(buf_temp, buf_temp, &rijndael))
				return false;

			buf_temp += keysize;
		}
	}

	return true;
}

bool decrypt_and_output(HANDLE hFile, HANDLE hFileOut)
{
	XC3_LOG_BUFFER	buffer;
	XC3_LOG_TAILS	tails;
	XC3_LOG_CTX		ctx;

	DWORD		dwNumberOfBytesRead;
	char		sign_dst[5];
	struct tm	tm;
	char		buf_temp[80];
	int			index_end = -1;

	SetFilePointer(hFile, -int(sizeof XC3_LOG_TAILS), 0, FILE_END);

	if (!ReadFile(hFile, &tails, sizeof(XC3_LOG_TAILS), &dwNumberOfBytesRead, NULL))
	{
		_tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
		return false;
	}
	if (dwNumberOfBytesRead < sizeof(XC3_LOG_TAILS))
	{
		_tprintf(TEXT("EOF\n"));
		return true;
	}

	if (tails.signature != XC3_LOG_SIGNATURE1)
	{
		// copy signature
		memcpy(sign_dst, &tails.signature, 4);
		sign_dst[4] = 0;

		printf("signature doesn't match : %s 0x%08X\n", sign_dst, tails.signature);
		return false;
	}
	if (tails.index < 3000)
	{
		// beginning of the file
		SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	}
	else if (tails.index == 3000)
	{
		if (tails.position != 0)
		{
			SetFilePointer(hFile, tails.position - 4, 0, FILE_BEGIN);

			if (!ReadFile(hFile, &index_end, 4, &dwNumberOfBytesRead, NULL))
			{
				_tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
				return false;
			}
		}

		SetFilePointer(hFile, tails.position, 0, FILE_BEGIN);
	}
	else
	{
		_tprintf(TEXT("log file is broken. index : %d\n"), tails.index);
		return false;
	}

	do
	{
		// load buffer
		if (!ReadFile(hFile, &buffer, sizeof(XC3_LOG_BUFFER), &dwNumberOfBytesRead, NULL))
		{
			_tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
			return false;
		}
		if (dwNumberOfBytesRead == 0)
		{
			if (tails.position == 0)
			{
				// success
				return true;
			}
			else
			{
				// beginning of the file
				SetFilePointer(hFile, 0, 0, FILE_BEGIN);
				continue;
			}
		}
		if (buffer.signature != XC3_LOG_SIGNATURE2)
		{
			// copy signature
			memcpy(sign_dst, &buffer.signature, 4);
			sign_dst[4] = 0;

			printf("signature doesn't match : %s 0x%08X\n", sign_dst, buffer.signature);
			return false;
		}
		if (buffer.size > sizeof(XC3_LOG_BUFFER))
		{
			_tprintf(TEXT("log file is broken  buffer.size : %d\n"), buffer.size);
			return false;
		}

		switch (buffer.type)
		{
		case 9039:
		{
			// B8 4F 23 00 00 C7 06 6D 4C 78 7A
			sprintf_s(buffer.buffer, "client closed(?) with error code : 0x%08X", buffer.errorcode);
			printf(buffer.buffer);
			printf("\n");
			break;
		}
		case 9040:
		{
			// ZeroMemory(&ctx, sizeof(ctx));
			ctx.init(XC3_LOG_S1, strlen(XC3_LOG_S1));

			for (int i = 0; i < sizeof(buffer.buffer); i++)
				buffer.buffer[i] ^= ctx.calc();

			break;
		}
		case 9041:
		{
			if (!decrypt(sizeof(buffer.buffer), buffer.buffer, buffer.key))
			{
				_tprintf(TEXT("couldn't decrypt.\n"));
				return false;
			}

			break;
		}
		default:
		{
			// copy type
			memcpy(sign_dst, &buffer.type, 2);
			sign_dst[2] = 0;

			_tprintf(TEXT("unknown type : %s %04X\n"), sign_dst, buffer.type);
			break;
		}
		}

		_localtime32_s(&tm, &buffer.unix_time);
		strftime(buf_temp, sizeof(buf_temp), "[%Y-%m-%d %H:%M:%S] ", &tm);

		WriteFile(hFileOut, buf_temp, strlen(buf_temp), NULL, NULL);
		if (buffer.name[0] != '\0')
		{
			WriteFile(hFileOut, "[", 1, NULL, NULL);
			WriteFile(hFileOut, buffer.name, strlen(buffer.name), NULL, NULL);
			WriteFile(hFileOut, "] ", 2, NULL, NULL);
		}
		WriteFile(hFileOut, buffer.buffer, strlen(buffer.buffer), NULL, NULL);
		WriteFile(hFileOut, "\r\n", 2, NULL, NULL);

		// load tails
		if (!ReadFile(hFile, &tails, sizeof(XC3_LOG_TAILS), &dwNumberOfBytesRead, NULL))
		{
			_tprintf(TEXT("couldn't read log file GLE : 0x%08X\n"), GetLastError());
			return false;
		}
	} while (tails.index != index_end);

	return true;
}

int _tmain(int argc, _TCHAR* argv[])
{
	TCHAR *tszFileNameIn = TEXT("C:\\Nexon\\MapleStory\\XignCode\\xigncode.log");
	TCHAR *tszFileNameOut = TEXT("C:\\Nexon\\MapleStory\\XignCode\\xigncode.txt");

	HANDLE hFileIn, hFileOut;

	if (argc > 1)
		tszFileNameIn = argv[1];

	if (argc > 2)
		tszFileNameOut = argv[2];

	SetFileAttributes(tszFileNameIn, FILE_ATTRIBUTE_NORMAL);

	hFileIn = CreateFile(tszFileNameIn, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFileIn == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("couldn't open log file : %s\n"), tszFileNameIn);
		return 0;
	}

	hFileOut = CreateFile(tszFileNameOut, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
		CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);


	if (hFileOut == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("couldn't open output file : %s\n"), tszFileNameOut);

		CloseHandle(hFileIn);
		return 0;
	}

	if (decrypt_and_output(hFileIn, hFileOut))
		_tprintf(TEXT("success!!\n"));

	if (hFileIn != INVALID_HANDLE_VALUE)
		CloseHandle(hFileIn);

	if (hFileOut != INVALID_HANDLE_VALUE)
		CloseHandle(hFileOut);

	getchar();

	return 0;
}