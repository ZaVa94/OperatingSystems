
#define FUSE_USE_VERSION 28
#define HAVE_SETXATTR

#define ENC_DATA ((struct enc_state *) fuse_get_context()->private_data)

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
#define _XOPEN_SOURCE 700
#define _POSIX_C_SOURCE 200809L
#endif

#include "aes-crypt.h"
#include <linux/limits.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#define USAGE "Usage:\n\t./pa5-encfs KEY ENCYPTION_DIRECTORY MOUNT_POINT\n"

#define ENCRYPT 1
#define DECRYPT 0
#define PASS -1

#define ENC_ATTR "user.pa5-encfs.encrypted"
#define ENCRYPTED "true"
#define UNENCRYPTED "false"

struct enc_state {
	char *rootdir;
	char *key;
};

static void xmp_fullpath(char fpath[PATH_MAX], const char *path)
{
    strcpy(fpath, ENC_DATA->rootdir);
    strncat(fpath, path, PATH_MAX);
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = lstat(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_access(const char *path, int mask)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = access(fpath, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = readlink(fpath, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	dp = opendir(fpath);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	
	if (S_ISREG(mode)) {
		res = open(fpath, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(fpath, mode);
	else
		res = mknod(fpath, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = mkdir(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = unlink(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = rmdir(fpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	char flink[PATH_MAX];
	xmp_fullpath(flink, to);
	res = symlink(from, flink);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	char fpath[PATH_MAX];
	char fnewpath[PATH_MAX];
	xmp_fullpath(fpath, from);
	xmp_fullpath(fnewpath, to);
	res = rename(fpath, fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;
	char fpath[PATH_MAX];
	char fnewpath[PATH_MAX];
	xmp_fullpath(fpath, from);
	xmp_fullpath(fnewpath, to);
	res = link(fpath, fnewpath);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = chmod(fpath, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = lchown(fpath, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = truncate(fpath, size);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	struct timeval tv[2];

	tv[0].tv_sec = ts[0].tv_sec;
	tv[0].tv_usec = ts[0].tv_nsec / 1000;
	tv[1].tv_sec = ts[1].tv_sec;
	tv[1].tv_usec = ts[1].tv_nsec / 1000;

	res = utimes(fpath, tv);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = open(fpath, fi->flags);
	if (res == -1)
		return -errno;
		
	close(res);
	
	fi->fh = res;
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	FILE *file;
	FILE *tempfile;
	char *tempdata;
	size_t tempsize;
	
	char xattrval[8];
	ssize_t xattrlen;
	
	int action = PASS;
	
	int res;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	
	file = fopen(fpath, "r");
	if (file == NULL)
		return -errno;
		
	tempfile = open_memstream(&tempdata, &tempsize);
	if (tempfile == NULL)
		return -errno;

	xattrlen = getxattr(fpath, ENC_ATTR, xattrval, 8);
	if(xattrlen != -1 && strcmp(xattrval, ENCRYPTED) == 0) {
		action = DECRYPT;
	}
	
	do_crypt(file, tempfile, action, ENC_DATA->key);
	fclose(file);

	fflush(tempfile);
	fseek(tempfile, offset, SEEK_SET);
	
	res = fread(buf, 1, size, tempfile);
	if (res == -1)
		res = -errno;
	
	fclose(tempfile);

	return res;

}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;
	FILE *file; 
	FILE *tempfile;
	char *tempdata;
	size_t tempsize;

	char xattr_value[6];
	ssize_t xattr_length;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	int action = PASS;

	(void) fi;

	file = fopen(fpath, "r");
	if (file == NULL){
		return -errno;
	}

	tempfile = open_memstream(&tempdata, &tempsize);
	if (tempfile == NULL) {
		return -errno;
	}
	
	xattr_length = getxattr(fpath, ENC_ATTR, xattr_value, 6);
	if(xattr_length != -1 && strcmp(xattr_value, ENCRYPTED) == 0) {
		action = DECRYPT;
	}

	do_crypt(file, tempfile, action, ENC_DATA->key);
	fclose(file);

	fseek(tempfile, offset, SEEK_SET);
	res = fwrite(buf, 1, size, tempfile);
	if (res == -1)
		res = -errno;
	fflush(tempfile);

	file = fopen(fpath, "w");
	fseek(tempfile, 0, SEEK_SET);
	do_crypt(tempfile, file, ENCRYPT, ENC_DATA->key);

	fclose(tempfile);
	fclose(file);

	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);
	res = statvfs(fpath, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_create(const char* path, mode_t mode, struct fuse_file_info* fi) {
	FILE *file;
	FILE *tempfile;
    char *tempdata;
	size_t tempsize;
	
	char fpath[PATH_MAX];
	xmp_fullpath(fpath, path);

	(void) fi;
	(void) mode;

	file = fopen(fpath, "w");
	if(file == NULL){
		return -errno;
	}
	tempfile = open_memstream(&tempdata, &tempsize);
	if(tempfile == NULL){
		return -errno;
	}
	if(setxattr(fpath, ENC_ATTR, ENCRYPTED, sizeof(ENCRYPTED), 0) == -1){
		return -errno;
	}
	do_crypt(tempfile, file, ENCRYPT, ENC_DATA->key);
	fclose(tempfile);
	fclose(file);

    return 0;

}


static int xmp_release(const char *path, struct fuse_file_info *fi)
{

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_SETXATTR
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	char fpath[PATH_MAX];
    xmp_fullpath(fpath, path);
	int res = lsetxattr(fpath, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	char fpath[PATH_MAX];
    xmp_fullpath(fpath, path);
	int res = lgetxattr(fpath, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	char fpath[PATH_MAX];
    xmp_fullpath(fpath, path);
	int res = llistxattr(fpath, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	char fpath[PATH_MAX];
    xmp_fullpath(fpath, path);
	int res = lremovexattr(fpath, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
	.utimens	= xmp_utimens,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.create         = xmp_create,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	struct enc_state * enc_data;
	if ((getuid() == 0) || (geteuid() == 0)) {
		fprintf(stderr, "Running ENCFS as root opens unnacceptable security holes\n");
		return 1;
    }
	if ((argc < 4) || (argv[argc-2][0] == '-') || (argv[argc-1][0] == '-')) {
		fprintf(stderr, USAGE);
	}
	
	enc_data = malloc(sizeof(struct enc_state));
	if (enc_data == NULL){
		perror("Error");
		exit(1);
	}
	enc_data->rootdir = realpath(argv[argc-2], NULL);
	
	enc_data->key = argv[argc-3];
	argv[argc-3] = argv[argc-1];
    argv[argc-2] = NULL;
    argv[argc-1] = NULL;
    argc -= 2;
    
    umask(0);
	fprintf(stderr, "about to call fuse_main\n");
    return fuse_main(argc, argv, &xmp_oper, enc_data);
    fprintf(stderr, "Fused finished\n");
}
