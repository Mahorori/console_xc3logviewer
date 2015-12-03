#pragma once

#include <Windows.h>

#define XC3_ERROR 0x80000000
#define XC3_IO_ERROR 0xE0010001

#define XC3_LOG_SIGNATURE1 0x6368784C // Lxhc
#define XC3_LOG_SIGNATURE2 0x7A784C6D // mLxz

#define XC3_LOG_S1 "@#we$ppAz~?xqt"
#define XC3_LOG_S2 "                THE             WORLD'S BEST    ANTI-CHEAT      XIGNCODE3       HEROES                          2006            apuro           knwook          jeeyou          codewiz                         2007            zextor                          2008            maengee1234     neohan21                        2009            sungmirr        well_sj         k4ir05          zippolook                       2010            nasery00        kjjhihi         airking         maeng3028                       2011            choihj          anxiangzhe                      2012            hirowith        jhahn           qkrsky          lifting         withyou8008                     2013            bandasi         chae                            Copyright       (c) 2006-2013   Wellbia.com     Co., Ltd.                       Speed is        irrelevant      if you are      going in the    wrong direction.- Mahatma Gandhi                                "

typedef struct _XC3_LOG_CTX
{
	unsigned char _byte[0x100];
	unsigned long _100;
	unsigned long _104;

	void init(const char *key, int size)
	{
		unsigned char a;

		for (int i = 0; i < sizeof(_byte); i++)
			_byte[i] = i;

		for (int i = 0, j = 0; i < sizeof(_byte); i++)
		{
			a = _byte[i];
			j = key[i % size] + _byte[i] + j & 0xFF;
			_byte[i] = _byte[j];
			_byte[j] = a;
		}

		_100 = 0;
		_104 = 0;
	}

	unsigned char calc()
	{
		unsigned char a, b;

		_100 = _100 + 1 & 0xFF;

		a = _byte[_100] + _104 & 0xFF;
		_104 = a;
		b = _byte[a];

		_byte[a] = _byte[_100];
		_byte[_100] = b;

		return _byte[(_byte[_104] + b) & 0xFF];
	}
} XC3_LOG_CTX, *PXC3_LOG_CTX, *LPXC3_LOG_CTX;

struct XC3_LOG_TAILS
{
	unsigned long signature;
	unsigned long position;
	unsigned long index;
};

struct XC3_LOG_BUFFER
{
	unsigned long signature;
	unsigned short size;
	unsigned short type;
	// 8
	unsigned char key[16];
	char name[16];
	__time32_t unix_time;
	unsigned long _2C;
	unsigned long _30;
	unsigned long _34;
	unsigned long errorcode;	// errorcode?
	unsigned long _3C;
	unsigned long _40;
	char buffer[0xF0];

	// 308bytes.
};