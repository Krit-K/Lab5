#include "zc_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

// The zc_file struct is analogous to the FILE struct that you get from fopen.
struct zc_file
{
    off_t fileSize;
    void *dataPtr;
    int fd;
    int offset;
};

/**************
 * Exercise 1 *
 **************/

zc_file *zc_open(const char *path)
{
    // To implement
    int fd;
    zc_file file;
    zc_file *filePtr;
    void *dataPtr;

    struct stat buf;

    if ((fd = open(path, O_RDWR | O_CREAT) == -1))
    {
        return NULL;
    }
    file.fd = fd;

    fstat(fd, &buf);
    off_t size = buf.st_size;
    file.fileSize = size;

    if (size == 0)
    {
        if ((dataPtr = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of newly created file");
            exit(1);
        };
    }
    else
    {
        if ((dataPtr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of a file");
            exit(1);
        };
    }

    file.dataPtr = dataPtr;
    filePtr = &file;

    return filePtr;
}

int zc_close(zc_file *file)
{
    // To implement

    off_t size;
    int fd;

    fd = file->fd;
    size = file->fileSize;

    if (munmap(file, size) == -1)
    {
        return -1;
    }
    else
    {
        free(file->dataPtr);
        if (close(fd) == -1)
        {
            return -1;
        }
        return 0;
    }
}

const char *zc_read_start(zc_file *file, size_t *size)
{
    // To implement
    size_t neededSize;
    size_t newSize;
    size_t offset = 0;

    neededSize = *size;
    offset += *size;

    char *tempPtr = (char *)(file->dataPtr);
    char *bytePtr;

    if ((file->fileSize - file->offset) < neededSize)
    {
        newSize = file->fileSize - file->offset;
        neededSize = newSize;
    }

    bytePtr = tempPtr + file->offset;
    file->offset += neededSize;

    return NULL;
}

void zc_read_end(zc_file *file)
{
    // To implement
}

/**************
 * Exercise 2 *
 **************/

char *zc_write_start(zc_file *file, size_t size)
{
    // To implement
    return NULL;
}

void zc_write_end(zc_file *file)
{
    // To implement
}

/**************
 * Exercise 3 *
 **************/

off_t zc_lseek(zc_file *file, long offset, int whence)
{
    // To implement
    return -1;
}

/**************
 * Exercise 5 *
 **************/

int zc_copyfile(const char *source, const char *dest)
{
    // To implement
    return -1;
}
