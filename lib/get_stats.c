/* get_stats.h -- API to get per-backend stats from the IO manager
 *
 * Copyright (C) 2013 UT-Battelle.
 *
 * This file may be redistributed under the terms of the GNU Library General
 * Public License version 2; see COPYING for details.
 */
#include <ext2fs/ext2fs.h>
#include "ext2fs-extra.h"

errcode_t io_channel_get_stats(io_channel channel, io_stats *stats)
{
        EXT2_CHECK_MAGIC(channel, EXT2_ET_MAGIC_IO_CHANNEL);

	if (!channel->manager->get_stats)
		return EXT2_ET_UNIMPLEMENTED;

	return channel->manager->get_stats(channel, stats);
}
