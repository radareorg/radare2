/*
 * Create a squashfs filesystem.  This is a highly compressed read only
 * filesystem.
 *
 * Copyright (c) 2009
 * Phillip Lougher <phillip@lougher.demon.co.uk>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2,
 * or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * pseudo.h
 */
struct pseudo_dev {
	char		type;
	unsigned int	mode;
	unsigned int	uid;
	unsigned int	gid;
	unsigned int	major;
	unsigned int	minor;
	int		pseudo_id;
	int		fd;
	int		child;
#ifdef USE_TMP_FILE
	char		*filename;
#endif
};

struct pseudo_entry {
	char			*name;
	char			*pathname;
	struct pseudo		*pseudo;
	struct pseudo_dev	*dev;
};
	
struct pseudo {
	int			names;
	int			count;
	struct pseudo_entry	*name;
};

extern int read_pseudo_def(struct pseudo **, char *);
extern int read_pseudo_file(struct pseudo **, char *);
extern struct pseudo *pseudo_subdir(char *, struct pseudo *);
extern struct pseudo_entry *pseudo_readdir(struct pseudo *);
extern struct pseudo_dev *get_pseudo_file(int);
extern void delete_pseudo_files();
