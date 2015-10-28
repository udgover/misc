/* Copyright (c) 2015 udgover */

/* Permission is hereby granted, free of charge, to any person obtaining a copy */
/* of this software and associated documentation files (the "Software"), to deal */
/* in the Software without restriction, including without limitation the rights */
/* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell */
/* copies of the Software, and to permit persons to whom the Software is */
/* furnished to do so, subject to the following conditions: */

/* The above copyright notice and this permission notice shall be included in */
/* all copies or substantial portions of the Software. */

/* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR */
/* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, */
/* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE */
/* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER */
/* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, */
/* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN */
/* THE SOFTWARE. */

/* Benchmark for libmagic */
/* gcc -O2 magicbench.c -lmagic -o magicbench */
/* ./magicbench -f file -b 4096 -i 10000 */

#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <magic.h>


/* Douglas B. Staple code at http://stackoverflow.com/a/21665642 */
double get_elapsed_time(struct timespec *before, struct timespec *after)
{
  double deltat_s  = after->tv_sec - before->tv_sec;
  double deltat_ns = after->tv_nsec - before->tv_nsec;
  return deltat_s + deltat_ns*1e-9;
}


char*	get_magic(void* buffer, size_t size)
{
  magic_t	ms;
  const char*	tmp;
  char*		result;

  ms = NULL;
  tmp = NULL;
  result = NULL;
  if ((ms = magic_open(MAGIC_NONE)) != NULL)
    {
      if (magic_load(ms, "/usr/share/misc/magic.mgc") != -1)
	{
	  if ((tmp = magic_buffer(ms, buffer, size)) != NULL)
	    {
	      if ((result = malloc(strlen(tmp) * sizeof(char))) != NULL)
		memcpy(result, tmp, strlen(tmp));
	    }
	}
      magic_close(ms);
    }
  return result;
}


void		magic_benchmarked(void* buffer, size_t size)
{
  struct timespec	before;
  struct timespec	after;
  magic_t		ms;
  const char*		result;
  int			load;

  ms = NULL;
  result = NULL;
  clock_gettime(CLOCK_MONOTONIC, &before);
  ms = magic_open(MAGIC_NONE);
  clock_gettime(CLOCK_MONOTONIC, &after);
  printf("magic_open = %e s\n", get_elapsed_time(&before, &after));
  if (ms != NULL)
    {
      clock_gettime(CLOCK_MONOTONIC, &before);
      load = magic_load(ms, "/usr/share/misc/magic.mgc");
      clock_gettime(CLOCK_MONOTONIC, &after);
      printf("magic_load = %e s\n", get_elapsed_time(&before, &after));
      if (load != -1)
	{
	  clock_gettime(CLOCK_MONOTONIC, &before);
	  result = magic_buffer(ms, buffer, size);
	  clock_gettime(CLOCK_MONOTONIC, &after);
	  printf("magic_buffer = %e s\n", get_elapsed_time(&before, &after));
	  if (result != NULL)
	    printf("%s\n", result);
	}
      clock_gettime(CLOCK_MONOTONIC, &before);
      magic_close(ms);
      clock_gettime(CLOCK_MONOTONIC, &after);
      printf("magic_close = %e s\n", get_elapsed_time(&before, &after));	  
    }
  return;
}


void	magic_iter(void* buffer, int size, int iter)
{
  struct timespec	before;
  struct timespec	after;
  const char*		tmp;
  int			i;

  clock_gettime(CLOCK_MONOTONIC, &before);
  for (i = 0; i != iter; ++i)
    {
      if ((tmp = get_magic(buffer, size)) != NULL)
	free((void*)tmp);
    }
  clock_gettime(CLOCK_MONOTONIC, &after);
  printf("%d iter = %e s\n", iter, get_elapsed_time(&before, &after));
}


int	allocAndRead(char* path, void** buffer, int size)
{
  int	fd;
  int	rbytes;

  rbytes = -1;
  if ((fd = open(path, O_RDONLY)) != -1)
    {
      if ((*buffer = malloc(size)) != NULL)
	rbytes = read(fd, *buffer, size);
      close(fd);
    }
  return rbytes;
}


int	main(int argc, char* argv[])
{
  void*			buffer;
  char*			filename;
  int			rbytes;
  int			opt;
  int			buffsize;
  int			iter;

  filename = NULL;
  buffsize = 0;
  iter = 0;
  if (argc != 7)
    {
      printf("Usage: %s -f filename -b buffer-size -i iteration\n", argv[0]);
      exit(EXIT_FAILURE);
    }
  while ((opt = getopt(argc, argv, "f:b:i:")) != -1)
    {
      switch (opt)
	{
	case 'f':
	  filename = optarg;
	  break;
	case 'b':
	  buffsize = atoi(optarg);
	  break;
	case 'i':
	  iter = atoi(optarg);
	  break;
	default:
	  printf("Usage: %s -f filename -b buffer-size -i iteration\n", argv[0]);
	  exit(EXIT_FAILURE);
	}
    }
  if (buffsize > 100*1024*1024)
    {
      printf("buffer-size is greater than %d\n", 100*1024*1024);
      exit(EXIT_FAILURE);
    }
  if (iter < 1)
    {
      printf("iter is lesser than 1\n");
      exit(EXIT_FAILURE);
    }
  if ((rbytes = allocAndRead(filename, &buffer, buffsize)) > 0)
    {
      printf("Buffer size: %d bytes\n", rbytes);
      magic_benchmarked(buffer, rbytes);
      magic_iter(buffer, rbytes, iter);
      free(buffer);
    }
}


