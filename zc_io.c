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
    char *dataPtr;
    int fd;
    off_t offset;
    char *path;
    pthread_mutex_t mutex;
    pthread_mutex_t wrt;
};

/**************
 * Exercise 1 *
 **************/

zc_file *zc_open(const char *path)
{
    // // To implement
    // int fd;
    int info;
    // char *dataPtr;

    zc_file *filePtr = malloc(sizeof(zc_file));
    struct stat buf;

    if ((filePtr->fd = open(path, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO)) == -1)
    {
        return NULL;
    }
    // filePtr->fdPtr = &fd;

    if ((info = fstat(filePtr->fd, &buf)) == -1)
    {
        perror("Error in fstat");
        exit(1);
    };
    off_t size = buf.st_size;
    // filePtr->fileSize = size;

    if (size == 0)
    {
        if ((filePtr->dataPtr = mmap(NULL, 1, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, filePtr->fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of newly created file");
            exit(1);
        }
        filePtr->fileSize = 1;
    }
    else
    {
        if ((filePtr->dataPtr = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, filePtr->fd, 0)) == MAP_FAILED)
        {
            perror("Error in mmap of a file");
            exit(1);
        };
        filePtr->fileSize = size;
    }

    // filePtr->dataPtr = dataPtr;
    filePtr->offset = 0;

    return filePtr;
}

int zc_close(zc_file *file)
{
    // To implement

    off_t size;
    int fd;
    char *data;

    fd = file->fd;
    data = file->dataPtr;
    size = file->fileSize;

    if ((munmap(data, size)) == -1)
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
    off_t neededSize;
    size_t newSize;
    // size_t offset = 0;

    // offset += *size;

    // char *tempPtr = (char *)(file->dataPtr);

    char *bytePtr;

    neededSize = *size;

    off_t currentSpace = file->fileSize - file->offset;
    if (currentSpace < neededSize)
    {
        //neededSize = *size;
        *size = file->fileSize - file->offset;
        neededSize = *size;
    }

    char *tempPtr = file->dataPtr;
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
    // pthread_mutex_lock(&(file->wrt));
    off_t leftSpace = file->fileSize - file->offset;
    if (leftSpace < size)
    {
        file->dataPtr = mremap(file->dataPtr, file->fileSize, size + file->offset, MREMAP_MAYMOVE);
        file->fileSize = size + file->offset;
        ftruncate(file->fd, size + file->offset);
    }

    off_t temp = file->offset;
    char *newPath;
    newPath = file->dataPtr + temp;
    file->offset += size;

    return newPath;
}

void zc_write_end(zc_file *file)
{
    // pthread_mutex_unlock(&(file->wrt));
    msync(file->dataPtr, file->fileSize, MS_SYNC);
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
