#define _GNU_SOURCE
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
    char *path;
    pthread_mutex_t mutex;
    pthread_mutex_t wrt;
};

/**************
 * Exercise 1 *
 **************/

zc_file *zc_open(const char *path)
{
    // To implement
    int fd;
    zc_file *filePtr = malloc(sizeof(zc_file));
    void *dataPtr;

    struct stat buf;

    if ((filePtr->fd = open(path, O_RDWR | O_CREAT)) == -1)
    {
        return NULL;
    }
    // filePtr->fdPtr = &fd;

    fstat(filePtr->fd, &buf);
    off_t size = buf.st_size;
    filePtr->fileSize = size;

    if (size == 0)
    {
        if ((filePtr->dataPtr = mmap(NULL, 1, PROT_WRITE | PROT_EXEC, MAP_SHARED, filePtr->fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of newly created file");
            exit(1);
        }
        filePtr->fileSize = 1;
    }
    else
    {
        if ((dataPtr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, filtePtr->fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of a file");
            exit(1);
        };
    }

    filePtr->dataPtr = dataPtr;
    filePtr->offset = 0;

    return filePtr;
}

int zc_close(zc_file *file)
{
    // To implement

    off_t size;
    int fd;

    fd = file->fd;
    size = file->fileSize;

    if ((munmap(file, size)) == -1)
    {
        return -1;
    }
    else
    {
        free(file);
        if (close(file->fd) == -1)
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

    // offset += *size;

    char *tempPtr = (char *)(file->dataPtr);
    char *bytePtr;

    neededSize = *size;

    int currentSpace = file->fileSize - file->offset;
    if (currentSpace < neededSize)
    {
        //neededSize = *size;
        *size = file->fileSize - file->offset;
        neededSize = *size;
    }

    bytePtr = tempPtr + file->offset;
    file->offset += neededSize;

    // return NULL;
    return bytePtr;
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
    pthread_mutex_lock(&(file->wrt));
    size_t left = file->fileSize - file->offset;
    if (left < size)
    {
        file->dataPtr = mremap(file->dataPtr, file->fileSize, size + file->offset, MREMAP_MAYMOVE);
        file->fileSize = size + file->offset;
        ftruncate(file->fd, size + file->offset);
    }

    size_t temp = file->offset;
    file->offset += size;
    char *newPath;
    newPath = file->path + temp;

    return newPath;
}

void zc_write_end(zc_file *file)
{
    pthread_mutex_unlock(&(file->wrt));
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
